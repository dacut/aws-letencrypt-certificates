use std::{str::from_utf8, sync::Arc};
use crate::{
    auth::CertificateAuthorization,
    errors::CertificateRequestError,
    events::{CertificateResponse, CertificateResponseStatus, Response, ValidationState},
    storage::{CertificateStorage, CertificateStorageResult},
    utils::{CertificateComponents, ssm_acme_parameter_path},
};
use acme2::{Account, AccountBuilder, Csr, DirectoryBuilder, Directory, Order, OrderBuilder, OrderStatus};
use futures::stream::{FuturesOrdered, StreamExt};
use lamedh_runtime::{self, Error as LambdaError};
use log::{debug, error, info};
use openssl::{
    pkey::{PKey, Private},
    rsa::Rsa,
};
use rusoto_core::{Region, RusotoError};
use rusoto_ssm::{GetParameterError, GetParameterRequest, PutParameterRequest, Ssm, SsmClient};

pub(crate) struct ValidatedCertificateRequest {
    /// The URL for the ACME server, e.g. `"https://acme-staging-v02.api.letsencrypt.org/directory"`
    pub(crate) directory: String,
    pub(crate) domain_names: Vec<String>,
    pub(crate) contacts: Vec<String>,
    pub(crate) auth: CertificateAuthorization,
    pub(crate) storage: Vec<CertificateStorage>,
    pub(crate) state: Option<ValidationState>,
    pub(crate) dir_host: String,
}

impl ValidatedCertificateRequest {
    pub(crate) async fn run_workflow(&self) -> Result<Response, LambdaError> {
        if self.state.is_none() {
            self.handle_initial_request().await
        } else {
            self.handle_pending_validation_request().await
        }
    }

    async fn handle_initial_request(&self) -> Result<Response, LambdaError> {
        let mut db = DirectoryBuilder::new(self.directory.clone());
        let dir: Arc<Directory> = db.build().await?;

        let mut account_builder = AccountBuilder::new(dir);
        account_builder.contact(self.contacts.clone());
        account_builder.terms_of_service_agreed(true);

        self.set_private_key(&mut account_builder).await?;

        info!("Creating/finding existing account from directory {}", self.directory);
        let account: Arc<Account> = account_builder.build().await?;

        // Account established -- go ahead and generate the order.
        let mut order_builder = OrderBuilder::new(account);
        for domain_name in &self.domain_names {
            order_builder.add_dns_identifier(domain_name.clone());
        }

        info!("Creating order for domain names: {:?}", self.domain_names);
        let order = order_builder.build().await?;
        info!("Order created");
        debug!("Order details: {:?}", order);

        // Order generated; get the authorizations. There will be one for each domain.
        info!("Getting authorizations for order");
        let authorizations = order.authorizations().await?;
        info!("Authorizations retrieved");

        let mut auth_futures = FuturesOrdered::new();
        for auth in authorizations {
            // Perform each authorization asynchronously.
            auth_futures.push(self.auth.auth(auth));
        }

        let mut incomplete_auths = false;
        while let Some(result) = auth_futures.next().await {
            match result {
                Ok(maybe_auth) => {
                    if let Some(_) = maybe_auth {
                        incomplete_auths = true;
                    }
                },
                Err(e) => {
                    error!("Authorization failed: {}", e);
                    return Err(e)
                }
            }
        }

        if incomplete_auths {
            return Ok(Response::Certificate(CertificateResponse {
                finished: false,
                status: CertificateResponseStatus::PendingValidation,
                storage: vec![],
                state: Some(ValidationState {
                    order: order,
                    private_key: None,
                    n_tries: 1,
                })
            }))
        }
        
        // Update the order status.
        let order = match order.poll().await {
            Ok(order) => order,
            Err(e) => {
                error!("Failed to update order status: {}", e);
                return Err(Box::new(e));
            }
        };

        match &order.status {
            OrderStatus::Pending => {
                info!("Order is still pending");
                Ok(Response::Certificate(CertificateResponse {
                    finished: false,
                    status: CertificateResponseStatus::PendingValidation,
                    storage: vec![],
                    state: Some(ValidationState {
                        order: order,
                        private_key: None,
                        n_tries: 1,
                    })
                }))
            }
            OrderStatus::Ready => self.finalize_order(order, 0).await,
            OrderStatus::Invalid => {
                error!("Order has become invalid");
                Err(CertificateRequestError::order_failed())
            }
            OrderStatus::Processing | OrderStatus::Valid => {
                error!("Order is processing or valid, but we have not finalized it yet! status = {:?}", order.status);
                Err(CertificateRequestError::order_failed())
            }
        }
    }

    async fn finalize_order(&self, order: Order, n_tries: u32) -> Result<Response, LambdaError> {
        info!("Finalizing order");

        // All authorizations passed successfully. Finalize the order.
        // Generate a 2048-bit RSA private key for the certificate.
        let private_key = match Rsa::<Private>::generate(2048) {
            Ok(pk) => pk,
            Err(e) => {
                error!("Unable to generate 2048 bit RSA key: {:#}", e);
                return Err(Box::new(e));
            }
        };

        let pkey = PKey::from_rsa(private_key)?;
        let pkey_pem = match pkey.private_key_to_pem_pkcs8() {
            Ok(pem) => from_utf8(&pem)?.to_string(),
            Err(e) => {
                error!("Failed to convert RSA private key to PEM format: {:#}", e);
                return Err(Box::new(e));
            }
        };

        // Generate the certificate signing request (CSR).
        let order = match order.finalize(Csr::Automatic(pkey.clone())).await {
            Ok(o) => {
                info!("Order finalizalization submitted.");
                o
            }
            Err(e) => {
                error!("Failed to finalize order: {:#}", e);
                return Err(Box::new(e));
            }
        };

        let order = match order.poll().await {
            Ok(order) => order,
            Err(e) => {
                error!("Failed to get current status of order: {}", e);
                return Err(Box::new(e))
            }
        };

        match &order.status {
            OrderStatus::Invalid => {
                error!("Error has become invalid");
                Err(CertificateRequestError::order_failed())
            }
            OrderStatus::Valid => self.retrieve_order(order, pkey_pem).await,
            _ => {
                info!("Order not ready yet; status is {:?}", order.status);
                Ok(Response::Certificate(CertificateResponse {
                    finished: false,
                    status: CertificateResponseStatus::PendingOrderFulfillment,
                    storage: vec![],
                    state: Some(ValidationState {
                        order: order,
                        private_key: Some(pkey_pem),
                        n_tries: 1 + n_tries,
                    })
                }))
            }
        }
    }

    async fn retrieve_order(&self, order: Order, pkey_pem: String) -> Result<Response, LambdaError> {
        // Ready -- download the certificates. We expect at least 2 -- our certificate and the
        // intermediate that signed it.
        info!("Downloading certificates");
        let certs = match order.certificate().await {
            Ok(maybe_certs) => match maybe_certs {
                None => {
                    error!("No certificates returned");
                    return Err(CertificateRequestError::empty_certificate_result());
                }
                Some(certs) => {
                    debug!("{} certificates returned", certs.len());
                    certs
                }
            },
            Err(e) => {
                error!("Failed to download certificates: {:#}", e);
                return Err(Box::new(e));
            }
        };

        if certs.len() < 2 {
            error!("Expected at least 2 certificates to be returned: {:#}", certs.len());
            return Err(CertificateRequestError::empty_certificate_result());
        }

        let mut certs_pem = Vec::with_capacity(certs.len());

        for cert in certs {
            match cert.to_pem() {
                Ok(pem) => certs_pem.push(from_utf8(&pem)?.to_string()),
                Err(e) => {
                    error!("Failed to convert certificate to PEM: {:#}", e);
                    return Err(Box::new(e));
                }
            }
        }

        let chain_pem = certs_pem[1..].join("\n");
        let cert_pem = certs_pem[0].clone();
        let fullchain_pem = format!("{}\n{}", cert_pem, chain_pem);
        let domain_names = order.identifiers.iter().map(|i| i.value.clone()).collect::<Vec<String>>();

        let components = CertificateComponents {
            cert_pem,
            chain_pem,
            fullchain_pem,
            pkey_pem,
        };

        save_certificates(self.storage.clone(), domain_names, components).await
    }

    async fn handle_pending_validation_request(&self) -> Result<Response, LambdaError> {
        unimplemented!()
    }

    async fn set_private_key(&self, account_builder: &mut AccountBuilder) -> Result<(), LambdaError> {
        // Get the existing private key for this account.
        let ssm_parameter_path = ssm_acme_parameter_path();
        let ssm = SsmClient::new(Region::default());
        let pk_param = format!(
            "{}/PrivateKeys/{}/{}",
            ssm_parameter_path,
            self.contacts[0].replace(":", "-").replace("/", "-").replace("@", "_"),
            self.dir_host,
        );

        info!("Looking for existing account private key in SSM parameter {}", pk_param);

        let gp_request = GetParameterRequest {
            name: pk_param.clone(),
            with_decryption: Some(true),
        };

        match ssm.get_parameter(gp_request).await {
            Ok(result) => match result.parameter {
                None => (),
                Some(param) => {
                    // We got a private key from SSM; parse it here.
                    debug!("Parsing private key as PEM data");
                    let pkey_str = match param.value {
                        Some(s) => s,
                        None => {
                            error!("No value returned by SSM for {}", pk_param);
                            return Err(CertificateRequestError::unexpected_aws_response(format!("No value returned for SSM parameter {}", pk_param)))
                        }
                    };

                    match PKey::private_key_from_pem(&pkey_str.as_bytes()) {
                        Ok(pkey) => {
                            // Parsed ok -- set it and return.
                            account_builder.private_key(pkey);
                            account_builder.only_return_existing(true);
                            return Ok(())
                        }
                        Err(e) => {
                            error!("Failed to parse private key from SSM: {:#}", e);
                            return Err(Box::new(e));
                        }
                    }
                }
            },
            Err(e1) => {
                debug!("SSM error: {:#}", e1);
                match e1 {
                    // No private key exists -- this is ok; we'll let the ACME client generate one.
                    RusotoError::Service(GetParameterError::ParameterNotFound(_)) => (),

                    // Unexpected error -- just propagate it up.
                    _ => return Err(Box::new(e1)),
                }
            }
        };

        // No private key exists. Generate one.
        let rsa = match Rsa::generate(2048) {
            Ok(rsa) => rsa,
            Err(e) => {
                error!("Failed to generate 2048-bit RSA key: {}", e);
                return Err(Box::new(e))
            }
        };

        let pkey = match PKey::from_rsa(rsa) {
            Ok(pkey) => pkey,
            Err(e) => {
                error!("Failed to convert RSA private key to PKey<Private>: {}", e);
                return Err(Box::new(e))
            }
        };

        // Save this to SSM first.
        let pem = match pkey.private_key_to_pem_pkcs8() {
            Ok(pem) => pem,
            Err(e) => {
                error!("Failed to convert RSA private key to PEM: {}", e);
                return Err(Box::new(e))
            }
        };

        let pem_str = match from_utf8(&pem) {
            Ok(pem_str) => pem_str.to_string(),
            Err(e) => {
                error!("Generated RSA private key contains non-UTF8 characters: {}", e);
                return Err(Box::new(e))
            }
        };

        let pp_request = PutParameterRequest {
            name: pk_param.clone(),
            description: Some(format!("ACMEv02 private key for {}", self.contacts[0])),
            overwrite: Some(true),
            type_: Some("SecureString".into()),
            value: pem_str,
            ..Default::default()
        };

        info!("Saving account private key to SSM parameter {}", pk_param);
        match ssm.put_parameter(pp_request).await {
            Ok(_) => info!("Private key saved"),
            Err(e) => {
                error!("Failed to save private key: {:#}", e);
                return Err(Box::new(e));
            }
        }
        
        // And now set this for the account builder.
        account_builder.private_key(pkey);
        Ok(())
    }
}

async fn save_certificates(storage: Vec<CertificateStorage>, domain_names: Vec<String>, components: CertificateComponents) -> Result<Response, LambdaError> {
    let mut n_successes = 0u32;
    let mut n_failures = 0u32;

    let mut futures = FuturesOrdered::new();
    for storage_provider in &storage {
        futures.push(storage_provider.save_certificate(
            domain_names.clone(), components.clone()
        ));
    }

    let mut results = Vec::new();

    while let Some(result) = futures.next().await {
        match result {
            Ok(result_set) => {
                for result in result_set {
                    match &result {
                        CertificateStorageResult::Error(_) => n_failures += 1,
                        _ => n_successes += 1,
                    }

                    results.push(result);
                }
            }
            Err(e) => {
                error!("Failed to save certificate: {:#}", e);
                n_failures += 1;
                results.push(CertificateStorageResult::Error(format!("Failed to save certificate: {:#}", e)));
            }
        }
    }

    let status = if n_failures > 0 {
        if n_successes > 0 { CertificateResponseStatus::PartialSuccess }
        else { CertificateResponseStatus::Failed } 
    } else {
        CertificateResponseStatus::Success
    };

    let cr = CertificateResponse {
        finished: true,
        status,
        storage: results,
        state: None,
    };
    Ok(Response::Certificate(cr))
}
