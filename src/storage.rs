use {
    crate::{
        constants::{ACM_STATUS_EXPIRED, ACM_STATUS_ISSUED, ACM_TYPE_IMPORTED, S3_ENCRYPTION_AES, S3_ENCRYPTION_KMS},
        errors::{CertificateRequestError, InvalidCertificateRequest},
        utils::{
            CertificateComponents,
            default_aes256, default_false, empty_string, s3_bucket_location_constraint_to_region, validate_and_sanitize_ssm_parameter_path,
        },
    },
    bytes::Bytes,
    futures::{
        future::ready,
        stream::{FuturesOrdered, StreamExt},
    },
    lamedh_runtime::Error as LambdaError,
    log::{error, info},
    rusoto_acm::{
        Acm, AcmClient, DescribeCertificateRequest, ImportCertificateRequest,
        ListCertificatesRequest,
    },
    rusoto_core::Region,
    rusoto_s3::{GetBucketLocationRequest, PutObjectRequest, S3Client, S3, StreamingBody},
    rusoto_ssm::{GetParameterRequest, PutParameterRequest, Ssm, SsmClient},
    serde::{self, Deserialize, Serialize},
    std::{
        str::FromStr,
    },
};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "Type")]
pub(crate) enum CertificateStorage {
    Acm(AcmStorage),
    S3(S3Storage),
    SsmParameter(SsmParameterStorage),
}

impl CertificateStorage {
    pub(crate) async fn validate(&mut self) -> Result<(), LambdaError> {
        match self {
            CertificateStorage::Acm(storage) => storage.validate().await,
            CertificateStorage::S3(storage) => storage.validate().await,
            CertificateStorage::SsmParameter(storage) => storage.validate().await,
        }
    }

    pub(crate) async fn save_certificate(
        &self,
        domain_names: Vec<String>,
        components: CertificateComponents
    ) -> Result<Vec<CertificateStorageResult>, LambdaError> {
        match self {
            CertificateStorage::Acm(storage) => {
                storage.save_certificate(domain_names, components).await
            }
            CertificateStorage::S3(storage) => {
                storage.save_certificate(domain_names, components).await
            }
            CertificateStorage::SsmParameter(storage) => {
                storage.save_certificate(domain_names, components).await
            }
        }
    }
}

/// Configuration for storing a certificate in an AWS Certificate Manager (ACM) certificate. In JSON:
///
///     {
///         // The type of storage to use. This must be "Acm".
///         "Type": "Acm",
///
///         // The ARNs of the certificate to reimport the certificate into. This cannot be specified
///         // if ForceNewImport is true.
///         "CertificateArns": [str],
///
///         // If true, always import a new certificate into ACM. Otherwise, the certificate is reimported
///         // over CertificateArn (if specified) or a certificate that matches the domain name(s) if found.
///         // If no matching certificate is found, a new one is imported. The default is false.
///         "ForceNewImport": bool,
///     }
#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct AcmStorage {
    #[serde(rename = "CertificateArns", default)]
    pub(crate) certificate_arns: Option<Vec<String>>,

    #[serde(rename = "ForceNewImport", default = "default_false")]
    pub(crate) force_new_import: bool,
}

impl AcmStorage {
    pub(crate) async fn validate(&mut self) -> Result<(), LambdaError> {
        if let Some(existing_arns) = &self.certificate_arns {
            if self.force_new_import {
                return Err(InvalidCertificateRequest::invalid_acm_configuration(
                    "Cannot specify CertificateArn and ForceNewImport",
                ));
            }

            for arn_str in existing_arns {
                // Should be arn:aws...:acm:region:account:certificate/certificate-id
                let parts = arn_str.split(':').collect::<Vec<&str>>();
                if parts.len() == 6
                    && parts[0] == "arn"
                    && parts[1].len() > 0
                    && parts[2] == "acm"
                    && parts[4].len() == 12
                    && parts[5].starts_with("certificate/")
                {
                    let region_str = parts[3];
                    if Region::from_str(region_str).is_ok() {
                        continue;
                    }
                }
                return Err(InvalidCertificateRequest::invalid_acm_certificate_arn(arn_str));
            }
        }

        Ok(())
    }

    /// Write the certificate and all of its components to AWS Certificate Manager (ACM).
    pub(crate) async fn save_certificate(
        &self,
        domain_names: Vec<String>,
        components: CertificateComponents
    ) -> Result<Vec<CertificateStorageResult>, LambdaError> {
        if self.force_new_import {
            self.import_new_certificate(domain_names, components).await
        } else if let Some(existing_arns) = &self.certificate_arns {
            self.reimport_certificate(domain_names, existing_arns.clone(), components).await
        } else {
            let existing_arns = self.find_matching_certificate(&domain_names).await?;
            if existing_arns.len() == 0 {
                self.import_new_certificate(domain_names, components).await
            } else {
                self.reimport_certificate(domain_names, existing_arns, components).await
            }
        }
    }

    async fn find_matching_certificate(&self, domain_names: &Vec<String>) -> Result<Vec<String>, LambdaError> {
        let acm = AcmClient::new(Region::default());
        let mut lc_request = ListCertificatesRequest {
            certificate_statuses: Some(vec![ACM_STATUS_ISSUED.to_string(), ACM_STATUS_EXPIRED.to_string()]),
            ..Default::default()
        };
        let mut candidates = Vec::new();

        loop {
            match acm.list_certificates(lc_request.clone()).await {
                Err(e) => {
                    error!("Failed to list ACM certificates: {:#}", e);
                    return Err(Box::new(e));
                }
                Ok(resp) => {
                    if let Some(summaries) = resp.certificate_summary_list {
                        for summary in summaries {
                            if let Some(summary_domain_name) = summary.domain_name {
                                if summary_domain_name == domain_names[0] {
                                    let summary_cert_arn = summary.certificate_arn.unwrap();
                                    info!("Found existing certificate {}", summary_cert_arn);
                                    candidates.push(summary_cert_arn);
                                }
                            }
                        }
                    }

                    match resp.next_token {
                        None => break,
                        Some(token) => lc_request.next_token = Some(token),
                    }
                }
            }
        }

        let mut domain_names_sorted = domain_names.clone();
        domain_names_sorted.sort();

        // Check the candidates to see if they have the same domain names.
        let mut futures = FuturesOrdered::new();

        for candidate in candidates {
            let dc_request = DescribeCertificateRequest {
                certificate_arn: candidate.clone(),
            };
            futures.push(Box::pin(acm.describe_certificate(dc_request)));
        }

        let results: Vec<String> = futures
            .filter_map(|result| {
                ready(match result {
                    Err(e) => {
                        error!("Failed to describe ACM certificate {}", e);
                        None
                    }
                    Ok(response) => match response.certificate {
                        None => None,
                        Some(detail) => {
                            if detail.type_.is_some() && detail.type_.unwrap() == ACM_TYPE_IMPORTED {
                                if let Some(alt_names) = detail.subject_alternative_names {
                                    let mut alt_names_sorted = alt_names.clone();
                                    alt_names_sorted.sort();
                                    if &alt_names_sorted == domain_names {
                                        Some(detail.certificate_arn.unwrap())
                                    } else {
                                        None
                                    }
                                } else {
                                    None
                                }
                            } else {
                                None
                            }
                        }
                    },
                })
            })
            .collect::<Vec<String>>()
            .await;

        Ok(results)
    }

    async fn import_new_certificate(
        &self,
        domain_names: Vec<String>,
        components: CertificateComponents
    ) -> Result<Vec<CertificateStorageResult>, LambdaError> {
        info!("Importing certificate to ACM for {}", domain_names.join(" "));
        let acm = AcmClient::new(Region::default());
        let imp_req = ImportCertificateRequest {
            certificate: Bytes::from(components.cert_pem),
            certificate_chain: Some(Bytes::from(components.chain_pem)),
            private_key: Bytes::from(components.pkey_pem),
            tags: None,
            ..Default::default()
        };

        match acm.import_certificate(imp_req).await {
            Ok(response) => {
                let certificate_arn = response.certificate_arn.unwrap();
                info!("Certificate imported as {}", certificate_arn);
                Ok(vec![CertificateStorageResult::Acm(AcmStorageResult {
                    certificate_arn,
                })])
            }
            Err(e) => {
                error!("Failed to import certificate: {:#}", e);
                Ok(vec![CertificateStorageResult::Error(format!("Failed to import certificate: {:#}", e))])
            }
        }
    }

    async fn reimport_certificate(
        &self,
        domain_names: Vec<String>,
        existing_arns: Vec<String>,
        components: CertificateComponents,
    ) -> Result<Vec<CertificateStorageResult>, LambdaError> {
        let mut futures = FuturesOrdered::new();
        let n_arns = domain_names.len();
        
        for arn in existing_arns {
            futures.push(self.reimport_certificate_for_arn(domain_names.clone(), arn, components.clone()));
        }

        let mut results = Vec::with_capacity(n_arns);

        while let Some(result) = futures.next().await {
            match result {
                Ok(arn) => results.push(CertificateStorageResult::Acm(AcmStorageResult { certificate_arn: arn })),
                Err(e) => {
                    error!("Failed to reimport certificate: {:#}", e);
                    results.push(CertificateStorageResult::Error(format!("Failed to reimport certificate: {:#}", e)));
                }
            }
        }

        Ok(results)
    }
    
    async fn reimport_certificate_for_arn(
        &self,
        domain_names: Vec<String>,
        cert_arn: String,
        components: CertificateComponents
    ) -> Result<String, LambdaError> {
        info!("Reimporting certificate for {} over {}", domain_names.join(" "), cert_arn);
        let acm = AcmClient::new(Region::default());
        let imp_req = ImportCertificateRequest {
            certificate: Bytes::from(components.cert_pem.clone()),
            certificate_arn: Some(cert_arn.clone()),
            certificate_chain: Some(Bytes::from(components.chain_pem.clone())),
            private_key: Bytes::from(components.pkey_pem.clone()),
            tags: None,
        };

        match acm.import_certificate(imp_req).await {            
            Err(e) => {
                error!("Failed to reimport certificate: {:#}", e);
                Err(Box::new(e))
            }

            Ok(_) => {
                info!("Certificate re-imported as {}", cert_arn);
                Ok(cert_arn)
            }
        }
    }
}

/// Configuration for storing a certificate in Amazon S3. In JSON:
///
///     {
///         // The type of storage to use. This must be "S3".
///         "Type": "S3",
///
///         // The bucket to store the certificate into. This is required.
///         "Bucket": str,
///
///         // The prefix to use for the certificate keys. Note that a "/" is not automatically
///         // appended.
///         "Prefix": str,
/// 
///         // The encryption type to use for the certificate components. This must be either "AES256" or "aws:kms". This defaults to "AES256".
///         "ComponentEncryptionType": str,
/// 
///         // If ComponentEncryptionType is "aws:kms", this is the KMS key ARN to use for encryption. If
///         // not specified, the default "aws/s3" key is used.
///         "ComponentKmsKey": str,
/// 
///         // The encryption type to use for the private key. This must be either "AES256" or "aws:kms". This defaults to "AES256".
///         "PrivateKeyEncryptionType": str,
/// 
///         // If PrivateKeyEncryptionType is "aws:kms", this is the KMS key ARN to use for encryption. If
///         // not specified, the default "aws/s3" key is used.
///         "PrivateKeyKmsKey": str,
///     }
#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct S3Storage {
    #[serde(rename = "Bucket")]
    pub(crate) bucket: String,

    #[serde(rename = "Prefix", default = "empty_string")]
    pub(crate) prefix: String,

    #[serde(rename = "ComponentEncryptionType", default = "default_aes256")]
    pub(crate) component_encryption_type: String,

    #[serde(rename = "ComponentKmsKey", default)]
    pub(crate) component_kms_key: Option<String>,

    #[serde(rename = "PrivateKeyEncryptionType", default = "default_aes256")]
    pub(crate) pkey_encryption_type: String,

    #[serde(rename = "PrivateKeyKmsKey", default)]
    pub(crate) pkey_kms_key: Option<String>,

    #[serde(skip)]
    pub(crate) region: Option<Region>,
}

impl S3Storage {
    pub(crate) async fn validate(&mut self) -> Result<(), LambdaError> {
        if self.bucket.is_empty() {
            return Err(InvalidCertificateRequest::invalid_s3_bucket(self.bucket.clone()));
        }

        match self.component_encryption_type.as_ref() {
            S3_ENCRYPTION_AES | S3_ENCRYPTION_KMS => {}
            _ => {
                return Err(InvalidCertificateRequest::invalid_s3_encryption_algorithm(
                    self.component_encryption_type.clone(),
                ));
            }
        }

        match self.pkey_encryption_type.as_ref() {
            S3_ENCRYPTION_AES | S3_ENCRYPTION_KMS => {}
            _ => {
                return Err(InvalidCertificateRequest::invalid_s3_encryption_algorithm(
                    self.component_encryption_type.clone(),
                ));
            }
        }

        let s3_client = S3Client::new(Region::default());
        let gblr = GetBucketLocationRequest {
            bucket: self.bucket.clone(),
            ..Default::default()
        };
        match s3_client.get_bucket_location(gblr).await {
            Ok(response) => {
                self.region = Some(s3_bucket_location_constraint_to_region(response.location_constraint)?);
                Ok(())
            }
            Err(e) => {
                error!("Failed to get location for S3 bucket {}: {}", self.bucket, e);
                Err(InvalidCertificateRequest::invalid_s3_bucket(self.bucket.clone()))
            }
        }
    }

    pub(crate) async fn save_certificate(
        &self,
        domain_names: Vec<String>,
        components: CertificateComponents,
    ) -> Result<Vec<CertificateStorageResult>, LambdaError> {
        let s3_client = S3Client::new(self.region.clone().expect("Region should be set here"));
        let cert_key = format!("{}cert.pem", self.prefix);
        let chain_key = format!("{}chain.pem", self.prefix);
        let fullchain_key = format!("{}fullchain.pem", self.prefix);
        let pkey_key = format!("{}privkey.pem", self.prefix);

        info!("Saving certificate for {} to s3://{}/{}", domain_names.join(" "), self.bucket, cert_key);
        let cert_por = PutObjectRequest{
            bucket: self.bucket.clone(),
            key: cert_key.clone(),
            server_side_encryption: Some(self.component_encryption_type.clone()),
            ssekms_key_id: self.component_kms_key.clone(),
            body: Some(StreamingBody::from(components.cert_pem.into_bytes())),
            ..Default::default()
        };

        info!("Saving certificate chain for {} to s3://{}/{}", domain_names.join(" "), self.bucket, chain_key);
        let chain_por = PutObjectRequest{
            bucket: self.bucket.clone(),
            key: chain_key.clone(),
            server_side_encryption: Some(self.component_encryption_type.clone()),
            ssekms_key_id: self.component_kms_key.clone(),
            body: Some(StreamingBody::from(components.chain_pem.into_bytes())),
            ..Default::default()
        };

        info!("Saving certificate fullchain for {} to s3://{}/{}", domain_names.join(" "), self.bucket, fullchain_key);
        let fullchain_por = PutObjectRequest{
            bucket: self.bucket.clone(),
            key: fullchain_key.clone(),
            server_side_encryption: Some(self.component_encryption_type.clone()),
            ssekms_key_id: self.component_kms_key.clone(),
            body: Some(StreamingBody::from(components.fullchain_pem.into_bytes())),
            ..Default::default()
        };

        info!("Saving private key for {} to s3://{}/{}", domain_names.join(" "), self.bucket, pkey_key);
        let pkey_por = PutObjectRequest{
            bucket: self.bucket.clone(),
            key: pkey_key.clone(),
            server_side_encryption: Some(self.pkey_encryption_type.clone()),
            ssekms_key_id: self.pkey_kms_key.clone(),
            body: Some(StreamingBody::from(components.pkey_pem.into_bytes())),
            ..Default::default()
        };
        
        let (cert_result, chain_result, fullchain_result, pkey_result) = tokio::join!(
            s3_client.put_object(cert_por),
            s3_client.put_object(chain_por),
            s3_client.put_object(fullchain_por),
            s3_client.put_object(pkey_por),
        );

        if let Err(e) = cert_result {
            error!("Failed to save certificate: {}", e);
            Err(Box::new(e))
        } else if let Err(e) = chain_result {
            error!("Failed to save certificate chain: {}", e);
            Err(Box::new(e))
        } else if let Err(e) = fullchain_result {
            error!("Failed to save full certificate chain: {}", e);
            Err(Box::new(e))
        } else if let Err(e) = pkey_result {
            error!("Failed to save private key: {}", e);
            Err(Box::new(e))
        } else {
            let s3sr = S3StorageResult {
                bucket: self.bucket.clone(),
                certificate: cert_key,
                chain: chain_key,
                fullchain: fullchain_key,
                pkey: pkey_key,
            };
            Ok(vec![CertificateStorageResult::S3(s3sr)])
        }
    }
}

/// Configuration for storing a certificate in AWS Systems Manager parameter store. In JSON:
///
///     {
///         // The type of storage to use. This must be "SsmParameter".
///         "Type": "SsmParameter",
///
///         // The path to store the certificate in. This must start with a "/".
///         "Path": str,
///     }
#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct SsmParameterStorage {
    #[serde(rename = "Path")]
    pub(crate) path: String,
}

impl SsmParameterStorage {
    pub(crate) async fn validate(&mut self) -> Result<(), LambdaError> {
        match validate_and_sanitize_ssm_parameter_path(&self.path) {
            Some(path) => {
                self.path = path;
                Ok(())
            }
            None => Err(InvalidCertificateRequest::invalid_ssm_parameter_path(self.path.clone())),
        }
    }

    pub(crate) async fn save_certificate(
        &self,
        domain_names: Vec<String>,
        components: CertificateComponents,
    ) -> Result<Vec<CertificateStorageResult>, LambdaError> {
        let (cert, chain, fullchain, pkey) = tokio::join!(
            self.write_cert_component_to_ssm(domain_names[0].clone(), components.cert_pem, "Certificate", false),
            self.write_cert_component_to_ssm(domain_names[0].clone(), components.chain_pem, "Chain", false),
            self.write_cert_component_to_ssm(domain_names[0].clone(), components.fullchain_pem, "FullChain", false),
            self.write_cert_component_to_ssm(domain_names[0].clone(), components.pkey_pem, "PrivateKey", true),
        );

        let (cert_param, cert_arn) = cert?;
        let (chain_param, chain_arn) = chain?;
        let (fullchain_param, fullchain_arn) = fullchain?;
        let (pkey_param, pkey_arn) = pkey?;
        let ssm_result = SsmParameterStorageResult {
            cert_param,
            chain_param,
            fullchain_param,
            pkey_param,
            cert_arn,
            chain_arn,
            fullchain_arn,
            pkey_arn,
        };
        Ok(vec![CertificateStorageResult::SsmParameter(ssm_result)])
    }

    /// Write a PEM certificate to SSM.
    async fn write_cert_component_to_ssm(
        &self,
        domain_name: String,
        data: String,
        component: &'static str,
        secure: bool,
    ) -> Result<(String, String), LambdaError> {
        let ssm = SsmClient::new(Region::default());
        let path_with_slash = if self.path.ends_with('/') {
            self.path.to_string()
        } else {
            format!("{}/", self.path)
        };

        let param_name = format!("{}Certificate/{}/{}", path_with_slash, domain_name, component);
        let param_type = if secure {
            Some("SecureString".to_string())
        } else {
            Some("String".to_string())
        };

        let pp_request = PutParameterRequest {
            name: param_name.clone(),
            description: Some(format!("SSL {} for {}", component, domain_name)),
            overwrite: Some(true),
            type_: param_type,
            value: data,
            tier: Some("Intelligent-Tiering".to_string()),
            ..Default::default()
        };

        let gp_request = GetParameterRequest {
            name: param_name.clone(),
            ..Default::default()
        };

        info!("Writing SSM parameter {}", param_name);

        match ssm.put_parameter(pp_request).await {
            Ok(_) => {
                info!("SSM parameter {} written successfully", param_name);

                match ssm.get_parameter(gp_request).await {
                    Ok(response) => match response.parameter {
                        None => {
                            error!("Unable to get ARN for parameter {}: no parameter returned", param_name);
                            Err(CertificateRequestError::unexpected_aws_response(format!(
                                "Unable to get ARN for parameter {}: no parameter returned",
                                param_name
                            )))
                        }
                        Some(parameter) => match parameter.arn {
                            None => {
                                error!("Unable to get ARN for parameter {}: no ARN returned", param_name);
                                Err(CertificateRequestError::unexpected_aws_response(format!(
                                    "Unable to get ARN for parameter {}: no ARN returned",
                                    param_name
                                )))
                            }
                            Some(arn) => Ok((param_name, arn)),
                        },
                    },
                    Err(e) => {
                        error!("Unable to get ARN for parameter {}: {}", param_name, e);
                        Err(CertificateRequestError::unexpected_aws_response(format!(
                            "Unable to get ARN for parameter {}: {}",
                            param_name, e   
                        )))
                    }
                }
            }
            Err(e) => {
                error!("Failed to write SSM parameter {}: {:#}", param_name, e);
                Err(Box::new(e))
            }
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "Type")]
pub(crate) enum CertificateStorageResult {
    Acm(AcmStorageResult),
    S3(S3StorageResult),
    SsmParameter(SsmParameterStorageResult),
    Error(String),
}

/// The results of storing a certificate in ACM. In JSON:
///
///     {
///         // The type of storage. Always "Acm".
///         "Type": "Acm",
///
///         // The ARN of the certificate.
///         "CertificateArn": str
///     }
#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct AcmStorageResult {
    #[serde(rename = "CertificateArn")]
    pub(crate) certificate_arn: String,
}

/// The results of storing a certificate in S3. In JSON:
///
///     {
///         // The type of storage. Always "S3".
///         "Type": "S3",
///
///         // The bucket where the certificate is stored.
///         "Bucket": str,
///
///         // The S3 key for the certificate itself.
///         "Certificate": str,
///
///         // The S3 key for the intermediate certificate chain.
///         "Chain": str,
///
///         // The S3 key for the concatenated certificate and intermediate chain.
///         "FullChain": str,
///
///         // The S3 key for the certificate private key.
///         "PrivateKey": str,
///     }
#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct S3StorageResult {
    #[serde(rename = "Bucket")]
    pub(crate) bucket: String,

    #[serde(rename = "Certificate")]
    pub(crate) certificate: String,

    #[serde(rename = "Chain")]
    pub(crate) chain: String,

    #[serde(rename = "FullChain")]
    pub(crate) fullchain: String,

    #[serde(rename = "PrivateKey")]
    pub(crate) pkey: String,
}

/// The results of storaing a certificate in the AWS Systems Manager parameter store. In JSON:
///
///     {
///         // The type of storage. Always "SsmParameter".
///         "Type": "SsmParameter",
///
///         // The name of the parameter containing the certificate.
///         "CertificateParameterName": str,
///
///         // The name opf the parameter containing the intermediate certificate(s).
///         "ChainParameterName": str,
///
///         // The name of the parameter containing the concatenated certificate and intermediate chain.
///         "FullChainParameterName": str,
///
///         // The name of the parameter containing the certificate private key.
///         "PrivateKeyParameterName": str,
///
///         // The ARN of the parameter for the certificate.
///         "CertificateArn": str,
///
///         // The ARN of the parameter for the intermediate certificate chain.
///         "ChainArn": str,
///
///         // The ARN of the parameter for the concatenated certificate and intermediate chain.
///         "FullChainArn": str,
///
///         // The ARN of the parameter for the certificate private key.
///         "PrivateKeyArn": str,
///     }
#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct SsmParameterStorageResult {
    #[serde(rename = "CertificateParameterName")]
    pub(crate) cert_param: String,

    #[serde(rename = "ChainParameterName")]
    pub(crate) chain_param: String,

    #[serde(rename = "FullChainParameterName")]
    pub(crate) fullchain_param: String,

    #[serde(rename = "PrivateKeyParameterName")]
    pub(crate) pkey_param: String,

    #[serde(rename = "CertificateArn")]
    pub(crate) cert_arn: String,

    #[serde(rename = "ChainArn")]
    pub(crate) chain_arn: String,

    #[serde(rename = "FullChainArn")]
    pub(crate) fullchain_arn: String,

    #[serde(rename = "PrivateKeyArn")]
    pub(crate) pkey_arn: String,
}
