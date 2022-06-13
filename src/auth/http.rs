use {
    super::{get_challenge_token_for_auth, AuthorizationHandler, CleanupDirective},
    crate::{
        constants::{
            CHALLENGE_TYPE_HTTP01, S3_ENCRYPTION_AES, S3_ENCRYPTION_KMS, SSM_TIER_ADVANCED,
            SSM_TIER_INTELLIGENT_TIERING, SSM_TIER_STANDARD, SSM_TYPE_SECURE_STRING,
        },
        errors::{CertificateRequestError, InvalidCertificateRequest},
        utils::{s3_bucket_location_constraint_to_region, ssm_acme_parameter_path},
    },
    acme2::{Authorization, AuthorizationStatus, Challenge, ChallengeStatus},
    async_trait::async_trait,
    lambda_runtime::Error as LambdaError,
    log::{debug, error, info},
    rusoto_core::Region,
    rusoto_s3::{DeleteObjectRequest, GetBucketLocationRequest, PutObjectRequest, S3Client, S3},
    rusoto_ssm::{DeleteParameterRequest, PutParameterRequest, Ssm, SsmClient},
    serde::{Deserialize, Serialize},
};

/// Configuration for HTTP-01 authorization using S3 to serve a website. In JSON:
///
///      {
///         // The type of authorization to perform. This must be "HttpS3".
///         "Type": "HttpS3",
///
///         // Write ACME HTTP-01 challenges to this S3 bucket. This is required.
///         "Bucket": str,
///         
///         // Prefix URLs with this string. Note that a '/' is *not*
///         // automatically appended. Instances of "{{DomainName}}" in the prefix will be
///         // replaced with the domain name being requested.
///         "Prefix": str,
///         
///         // Encrypt S3 objects using this S3 server-side encryption algorithm. Valid
///         // values are "AES256" and "aws:kms". Defaults to "AES256".
///         "EncryptionAlgorithm": str,
///         
///         // If EncryptionAlgorithm is "aws:kms", this KMS key will be used to encrypt the
///         // ACME HTTP-01 challenge written to S3. If unset, the default "aws/s3" key will be used.
///         "S3KmsKeyId": str
///     }
#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct HttpS3Authorization {
    #[serde(rename = "Bucket")]
    pub(crate) bucket: String,

    #[serde(rename = "Prefix", default)]
    pub(crate) prefix: Option<String>,

    #[serde(rename = "EncryptionAlgorithm", default)]
    pub(crate) enc_alg: Option<String>,

    #[serde(rename = "KmsKeyId", default)]
    pub(crate) kms_key_id: Option<String>,

    #[serde(skip)]
    pub(crate) region: Option<Region>,
}

impl Default for HttpS3Authorization {
    fn default() -> Self {
        Self {
            bucket: "".to_string(),
            prefix: None,
            enc_alg: None,
            kms_key_id: None,
            region: None,
        }
    }
}

impl HttpS3Authorization {
    fn get_s3_key_for_token(&self, token: &str) -> String {
        match &self.prefix {
            None => format!(".well-known/acme-challenge/{}", token),
            Some(prefix) => format!("{}.well-known/acme-challenge/{}", prefix, token),
        }
    }
}

#[async_trait]
impl AuthorizationHandler for HttpS3Authorization {
    async fn setup(&mut self) -> Result<(), LambdaError> {
        self.enc_alg = match &self.enc_alg {
            None => Some(S3_ENCRYPTION_AES.to_string()),
            Some(alg_name) => match alg_name.as_ref() {
                S3_ENCRYPTION_AES | S3_ENCRYPTION_KMS => Some(alg_name.to_string()),
                _ => return Err(InvalidCertificateRequest::invalid_s3_encryption_algorithm(alg_name.clone())),
            },
        };

        // Figure out where the S3 bucket resides; we'll need to use this for making S3 calls.
        let s3_client = S3Client::new(Region::default());
        let gbr_req = GetBucketLocationRequest {
            bucket: self.bucket.clone(),
            expected_bucket_owner: None,
        };

        self.region = match s3_client.get_bucket_location(gbr_req).await {
            Ok(output) => Some(s3_bucket_location_constraint_to_region(output.location_constraint)?),
            Err(e) => {
                error!("Unable to determine location of bucket {}: {:#?}", self.bucket, e);
                return Err(InvalidCertificateRequest::invalid_s3_bucket(self.bucket.clone()));
            }
        };

        Ok(())
    }

    async fn auth(
        &self,
        auth: Authorization,
    ) -> Result<(Authorization, Challenge, Vec<CleanupDirective>), LambdaError> {
        debug!("Handling authorization: {:?}", auth);
        let domain_name: &str = &auth.identifier.value;
        let (challenge, token) = get_challenge_token_for_auth(&auth, CHALLENGE_TYPE_HTTP01)?;

        let key_auth = match challenge.key_authorization() {
            Ok(maybe_key_auth) => match maybe_key_auth {
                Some(ka) => ka,
                None => {
                    error!("No {} key authorization found for {}", CHALLENGE_TYPE_HTTP01, domain_name);
                    return Err(CertificateRequestError::token_not_available(CHALLENGE_TYPE_HTTP01, domain_name));
                }
            },
            Err(e) => {
                error!("Failed to get ACME key authorization for {}: {}", domain_name, e);
                return Err(Box::new(e));
            }
        };

        // Write the challenge to S3.
        let s3_client = S3Client::new(self.region.as_ref().expect("Region not initialized").clone());
        let s3_key = self.get_s3_key_for_token(&token);

        let mut po_request = PutObjectRequest {
            body: Some(key_auth.as_bytes().to_vec().into()),
            bucket: self.bucket.clone(),
            cache_control: Some("no-store, max-age=0".to_string()),
            content_type: Some("text/plain; charset=utf-8".to_string()),
            key: s3_key.clone(),
            server_side_encryption: Some(self.enc_alg.as_ref().expect("Encryption algorithm not initialized").clone()),
            ..Default::default()
        };

        if self.enc_alg.as_ref().unwrap() == S3_ENCRYPTION_KMS {
            if let Some(kms_key) = &self.kms_key_id {
                po_request.ssekms_key_id = Some(kms_key.clone());
            }
        }

        info!("Writing key authorization for {} to s3://{}/{}", domain_name, self.bucket, s3_key);
        match s3_client.put_object(po_request).await {
            Ok(_) => info!("Key authorization for {} written to s3://{}/{} written", domain_name, self.bucket, s3_key),
            Err(e) => {
                error!(
                    "Failed to write key authorization for {} to s3://{}/{}: {}",
                    domain_name, self.bucket, s3_key, e
                );
                return Err(Box::new(e));
            }
        }

        info!("Informing ACME server that http-01 validation is ready for  {}", domain_name);
        // Signal to the ACME server that we're ready for verification.
        match challenge.validate().await {
            Ok(c) => c,
            Err(e) => {
                error!("Failed to send validation request to ACME server for {}: {}", domain_name, e);
                return Err(Box::new(e));
            }
        };

        let cleanup = vec![CleanupDirective::DeleteS3Object {
            bucket: self.bucket.clone(),
            key: s3_key,
        }];

        Ok((auth, challenge, cleanup))
    }

    async fn check(
        &self,
        auth: Authorization,
        challenge: Challenge,
    ) -> Result<(Authorization, Challenge, bool), LambdaError> {
        let domain_name: String = auth.identifier.value.clone();
        let (challenge_result, auth_result) = tokio::join!(challenge.poll(), auth.poll(),);

        let challenge: Challenge = match challenge_result {
            Ok(c) => c,
            Err(e) => {
                error!("Failed to update challenge status for {}: {}", domain_name, e);
                return Err(Box::new(e));
            }
        };

        let auth: Authorization = match auth_result {
            Ok(a) => a,
            Err(e) => {
                error!("Failed to update authorization status for {}: {}", domain_name, e);
                return Err(Box::new(e));
            }
        };

        let challenge_valid: bool = match challenge.status {
            ChallengeStatus::Invalid => {
                error!("Challenge for {} is invalid", domain_name);
                return Err(CertificateRequestError::challenge_failed(domain_name));
            }
            ChallengeStatus::Valid => true,
            _ => false,
        };

        let auth_valid: bool = match auth.status {
            AuthorizationStatus::Invalid => {
                error!("Authorization for {} is invalid", domain_name);
                return Err(CertificateRequestError::authorization_failed(domain_name));
            }
            AuthorizationStatus::Valid => true,
            _ => false,
        };

        Ok((auth, challenge, challenge_valid && auth_valid))
    }

    async fn cleanup(&self, directives: Vec<CleanupDirective>) -> Result<(), LambdaError> {
        let s3_client = S3Client::new(self.region.as_ref().expect("Region not initialized").clone());

        for directive in directives {
            match directive {
                CleanupDirective::DeleteS3Object {
                    bucket,
                    key,
                } => {
                    let do_request = DeleteObjectRequest {
                        bucket: bucket.clone(),
                        key: key.clone(),
                        ..Default::default()
                    };
                    if let Err(e) = s3_client.delete_object(do_request).await {
                        error!("Failed to delete challenge token from s3://{}/{}: {}", bucket, key, e);
                    }
                }
                _ => {
                    error!("Unsupported cleanup directive: {:?}", directive);
                }
            }
        }

        Ok(())
    }
}

/// Configuration for HTTP-01 authorization using API Gateway to serve a website. In JSON:
///
///      {
///         // The type of authorization to perform. This must be "HttpS3".
///         "Type": "HttpApiGateway",
///
///         // The KMS key to use to encrypt the parameter value. If not specified, defaults to "aws/ssm"
///         "KmsKeyId": str,
///
///         // The SSM tier to use to store the parameter. Allowed values are "Standard", "Advanced",  and
///         // "Intelligent-Tiering". This defaults to the account default, which is "Standard" unless
///         // UpdateServiceSetting has been called to change it.
///         "SsmTier": str,
///     }
#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct HttpApiGatewayAuthorization {
    #[serde(rename = "KmsKeyId", default)]
    pub(crate) kms_key_id: Option<String>,

    #[serde(rename = "SsmTier", default)]
    pub(crate) ssm_tier: Option<String>,
}

#[async_trait]
impl AuthorizationHandler for HttpApiGatewayAuthorization {
    async fn setup(&mut self) -> Result<(), LambdaError> {
        match &self.ssm_tier {
            None => (),
            Some(value) => match value.as_ref() {
                SSM_TIER_STANDARD | SSM_TIER_ADVANCED | SSM_TIER_INTELLIGENT_TIERING => (),
                _ => return Err(InvalidCertificateRequest::invalid_ssm_tier(value)),
            },
        }

        Ok(())
    }

    async fn auth(
        &self,
        auth: Authorization,
    ) -> Result<(Authorization, Challenge, Vec<CleanupDirective>), LambdaError> {
        debug!("Handling authorization: {:?}", auth);
        let domain_name: &str = &auth.identifier.value;
        let (challenge, token) = get_challenge_token_for_auth(&auth, CHALLENGE_TYPE_HTTP01)?;

        let key_auth = match challenge.key_authorization() {
            Ok(maybe_key_auth) => match maybe_key_auth {
                Some(ka) => ka,
                None => {
                    error!("No {} key authorization found for {}", CHALLENGE_TYPE_HTTP01, domain_name);
                    return Err(CertificateRequestError::token_not_available(CHALLENGE_TYPE_HTTP01, domain_name));
                }
            },
            Err(e) => {
                error!("Failed to get ACME key authorization for {}: {}", domain_name, e);
                return Err(Box::new(e));
            }
        };

        // Write the challenge to SSM.
        let ssm_client = SsmClient::new(Region::default());
        let parameter_name = get_ssm_parameter_for_token(&token);

        let ppr = PutParameterRequest {
            description: Some(format!("Key authorization for {}", domain_name)),
            key_id: self.kms_key_id.clone(),
            name: parameter_name.clone(),
            overwrite: Some(true),
            tier: self.ssm_tier.clone(),
            type_: Some(SSM_TYPE_SECURE_STRING.to_string()),
            value: key_auth,
            ..Default::default()
        };

        info!("Writing key authorization for {} to SSM parameter {}", domain_name, parameter_name);
        match ssm_client.put_parameter(ppr).await {
            Ok(_) => info!("Key authorization for {} written to SSM parameter {}", domain_name, parameter_name),
            Err(e) => {
                error!(
                    "Failed to write key authorization for {} to SSM parameter {}: {}",
                    domain_name, parameter_name, e
                );
                return Err(Box::new(e));
            }
        }

        info!("Informing ACME server that http-01 validation is ready for  {}", domain_name);
        // Signal to the ACME server that we're ready for verification.
        match challenge.validate().await {
            Ok(c) => c,
            Err(e) => {
                error!("Failed to send validation request to ACME server for {}: {}", domain_name, e);
                return Err(Box::new(e));
            }
        };

        let cleanup = vec![CleanupDirective::DeleteSSMParameter {
            parameter_name,
        }];

        Ok((auth, challenge, cleanup))
    }

    async fn check(
        &self,
        auth: Authorization,
        challenge: Challenge,
    ) -> Result<(Authorization, Challenge, bool), LambdaError> {
        let domain_name: String = auth.identifier.value.clone();
        let (challenge_result, auth_result) = tokio::join!(challenge.poll(), auth.poll(),);

        let challenge: Challenge = match challenge_result {
            Ok(c) => c,
            Err(e) => {
                error!("Failed to update challenge status for {}: {}", domain_name, e);
                return Err(Box::new(e));
            }
        };

        let auth: Authorization = match auth_result {
            Ok(a) => a,
            Err(e) => {
                error!("Failed to update authorization status for {}: {}", domain_name, e);
                return Err(Box::new(e));
            }
        };

        let challenge_valid: bool = match challenge.status {
            ChallengeStatus::Invalid => {
                error!("Challenge for {} is invalid", domain_name);
                return Err(CertificateRequestError::challenge_failed(domain_name));
            }
            ChallengeStatus::Valid => true,
            _ => false,
        };

        let auth_valid: bool = match auth.status {
            AuthorizationStatus::Invalid => {
                error!("Authorization for {} is invalid", domain_name);
                return Err(CertificateRequestError::authorization_failed(domain_name));
            }
            AuthorizationStatus::Valid => true,
            _ => false,
        };

        Ok((auth, challenge, challenge_valid && auth_valid))
    }

    async fn cleanup(&self, directives: Vec<CleanupDirective>) -> Result<(), LambdaError> {
        let ssm_client = SsmClient::new(Region::default());
        for directive in directives {
            match directive {
                CleanupDirective::DeleteSSMParameter {
                    parameter_name,
                } => {
                    let dpr = DeleteParameterRequest {
                        name: parameter_name.clone(),
                        ..Default::default()
                    };

                    if let Err(e) = ssm_client.delete_parameter(dpr).await {
                        error!("Failed to delete key authorization from SSM parameter {}: {}", parameter_name, e);
                    }
                }

                _ => error!("Unsupported cleanup directive: {:?}", directive),
            }
        }

        Ok(())
    }
}

fn get_ssm_parameter_for_token(token: &str) -> String {
    format!("{}/AcmeChallenge/{}", ssm_acme_parameter_path(), token)
}
