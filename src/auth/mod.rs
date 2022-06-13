mod dns_route53;
mod http;

use {
    self::{
        dns_route53::DnsRoute53Authorization,
        http::{HttpApiGatewayAuthorization, HttpS3Authorization},
    },
    crate::errors::CertificateRequestError,
    acme2::{Authorization, Challenge},
    async_trait::async_trait,
    lambda_runtime::Error as LambdaError,
    log::error,
    serde::{Deserialize, Serialize},
};

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "Type")]
pub(crate) enum CertificateAuthorization {
    DnsRoute53(DnsRoute53Authorization),
    HttpApiGateway(HttpApiGatewayAuthorization),
    HttpS3(HttpS3Authorization),
}

#[async_trait]
pub(crate) trait AuthorizationHandler {
    async fn setup(&mut self) -> Result<(), LambdaError> {
        Ok(())
    }
    async fn auth(&self, auth: Authorization)
        -> Result<(Authorization, Challenge, Vec<CleanupDirective>), LambdaError>;
    async fn check(
        &self,
        auth: Authorization,
        challenge: Challenge,
    ) -> Result<(Authorization, Challenge, bool), LambdaError>;
    async fn cleanup(&self, _directives: Vec<CleanupDirective>) -> Result<(), LambdaError> {
        Ok(())
    }
}

#[async_trait]
impl AuthorizationHandler for CertificateAuthorization {
    async fn setup(&mut self) -> Result<(), LambdaError> {
        match self {
            Self::DnsRoute53(inner) => inner.setup().await,
            Self::HttpApiGateway(inner) => inner.setup().await,
            Self::HttpS3(inner) => inner.setup().await,
        }
    }

    async fn auth(
        &self,
        auth: Authorization,
    ) -> Result<(Authorization, Challenge, Vec<CleanupDirective>), LambdaError> {
        match self {
            Self::DnsRoute53(inner) => inner.auth(auth).await,
            Self::HttpApiGateway(inner) => inner.auth(auth).await,
            Self::HttpS3(inner) => inner.auth(auth).await,
        }
    }

    async fn check(
        &self,
        auth: Authorization,
        challenge: Challenge,
    ) -> Result<(Authorization, Challenge, bool), LambdaError> {
        match self {
            Self::DnsRoute53(inner) => inner.check(auth, challenge).await,
            Self::HttpApiGateway(inner) => inner.check(auth, challenge).await,
            Self::HttpS3(inner) => inner.check(auth, challenge).await,
        }
    }

    async fn cleanup(&self, auth: Vec<CleanupDirective>) -> Result<(), LambdaError> {
        match self {
            Self::DnsRoute53(inner) => inner.cleanup(auth).await,
            Self::HttpApiGateway(inner) => inner.cleanup(auth).await,
            Self::HttpS3(inner) => inner.cleanup(auth).await,
        }
    }
}

#[derive(Debug)]
pub(crate) enum CleanupDirective {
    DeleteRoute53Record {
        hosted_zone_id: String,
        record_name: String,
        record_type: String,
        record_value: String,
        ttl: i64,
    },

    DeleteS3Object {
        bucket: String,
        key: String,
    },

    DeleteSSMParameter {
        parameter_name: String,
    },
}

fn get_challenge_token_for_auth(
    auth: &Authorization,
    challenge_type: &str,
) -> Result<(Challenge, String), LambdaError> {
    let domain_name: &str = &auth.identifier.value;

    // Look for the challenge based on the challenge type.
    let challenge = match auth.get_challenge(challenge_type) {
        Some(c) => c,
        None => {
            error!("No {} challenge found for {}", challenge_type, domain_name);
            return Err(CertificateRequestError::challenge_not_available(challenge_type, domain_name));
        }
    };

    let token = match &challenge.token {
        Some(t) => t.clone(),
        None => {
            error!("No {} token found for {}", challenge_type, domain_name);
            return Err(CertificateRequestError::token_not_available(challenge_type, domain_name));
        }
    };

    Ok((challenge, token))
}
