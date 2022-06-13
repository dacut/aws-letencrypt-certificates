use std::{
    error::Error,
    fmt::{Display, Error as FormatError, Formatter},
};

/// Error respresenting the reasons why a certificate request failed.
#[derive(Debug)]
pub(crate) enum CertificateRequestError {
    /// Authorization unexpectedly failed for the specified domain.
    AuthorizationFailed(String),

    /// Challenge failed for the specified domain.
    ChallengeFailed(String),

    /// The specified challenge type was not presented as an option for the specified domain.
    ChallengeNotAvailable(String, String),

    /// No certificates were returned by the ACME server; this is unexpected.
    EmptyCertificateResult,

    /// The certificate order (request) failed unexpectedly.
    OrderFailed,

    /// The ACME server unexpectedly did not present challenge tokens for the specified challenge type for the
    /// specified domain.
    TokenNotAvailable(String, String),

    /// A response from AWS was unexpected.
    UnexpectedAwsResponse(String),
}

impl CertificateRequestError {
    pub(crate) fn authorization_failed<S: Into<String>>(domain_name: S) -> Box<Self> {
        Box::new(Self::AuthorizationFailed(domain_name.into()))
    }

    pub(crate) fn challenge_failed<S: Into<String>>(domain_name: S) -> Box<Self> {
        Box::new(Self::ChallengeFailed(domain_name.into()))
    }

    pub(crate) fn challenge_not_available<S1: Into<String>, S2: Into<String>>(
        challenge_type: S1,
        domain_name: S2,
    ) -> Box<Self> {
        Box::new(Self::ChallengeNotAvailable(challenge_type.into(), domain_name.into()))
    }

    pub(crate) fn empty_certificate_result() -> Box<Self> {
        Box::new(Self::EmptyCertificateResult)
    }

    pub(crate) fn order_failed() -> Box<Self> {
        Box::new(Self::OrderFailed)
    }

    pub(crate) fn token_not_available<S1: Into<String>, S2: Into<String>>(
        challenge_type: S1,
        domain_name: S2,
    ) -> Box<Self> {
        Box::new(Self::TokenNotAvailable(challenge_type.into(), domain_name.into()))
    }

    pub(crate) fn unexpected_aws_response<S: Into<String>>(msg: S) -> Box<Self> {
        Box::new(Self::UnexpectedAwsResponse(msg.into()))
    }
}

impl Display for CertificateRequestError {
    fn fmt(&self, f: &mut Formatter) -> Result<(), FormatError> {
        match self {
            Self::AuthorizationFailed(domain_name) => write!(f, "Authorization failed for domain {}", domain_name),
            Self::ChallengeFailed(domain_name) => write!(f, "Challenge failed for domain {}", domain_name),
            Self::ChallengeNotAvailable(challenge_type, domain_name) => {
                write!(f, "Challenge type {} not available for domain {}", challenge_type, domain_name)
            }
            Self::EmptyCertificateResult => write!(f, "No certificates returned"),
            Self::OrderFailed => write!(f, "Order failed"),
            Self::TokenNotAvailable(challenge_type, domain_name) => {
                write!(f, "No token available for {} challenge for {}", challenge_type, domain_name)
            }
            Self::UnexpectedAwsResponse(msg) => write!(f, "Unexpected AWS response: {}", msg),
        }
    }
}

impl Error for CertificateRequestError {}

#[derive(Debug)]
pub(crate) enum InvalidCertificateRequest {
    ContactsEmpty,
    DirectoryEmpty,
    DomainNamesEmpty,
    InvalidAcmCertificateArn(String),
    InvalidAcmConfiguration(String),
    InvalidContact(String),
    InvalidDirectoryUrl(String),

    /// The Route 53 hosted zone does not match the domain name.
    InvalidRoute53HostedZone(String),

    InvalidS3EncryptionAlgorithm(String),

    /// The location of the S3 bucket could not be determined.
    InvalidS3Bucket(String),

    /// The SSM path specified was invalid.
    InvalidSsmParameterPath(String),

    /// The SSM tier specified was invalid.
    InvalidSsmTier(String),

    /// No Route 53 hosted zones were found that match the domain name.
    NoMatchingRoute53Zones(String),
}

impl InvalidCertificateRequest {
    pub(crate) fn contacts_empty() -> Box<Self> {
        Box::new(Self::ContactsEmpty)
    }

    pub(crate) fn directory_empty() -> Box<Self> {
        Box::new(Self::DirectoryEmpty)
    }

    pub(crate) fn domain_names_empty() -> Box<Self> {
        Box::new(Self::DomainNamesEmpty)
    }

    pub(crate) fn invalid_acm_certificate_arn<S: Into<String>>(arn: S) -> Box<Self> {
        Box::new(Self::InvalidAcmCertificateArn(arn.into()))
    }

    pub(crate) fn invalid_acm_configuration<S: Into<String>>(msg: S) -> Box<Self> {
        Box::new(Self::InvalidAcmConfiguration(msg.into()))
    }

    pub(crate) fn invalid_contact<S: Into<String>>(msg: S) -> Box<Self> {
        Box::new(Self::InvalidContact(msg.into()))
    }

    pub(crate) fn invalid_directory_url<S: Into<String>>(msg: S) -> Box<Self> {
        Box::new(Self::InvalidDirectoryUrl(msg.into()))
    }

    pub(crate) fn invalid_route53_hosted_zone<S: Into<String>>(msg: S) -> Box<Self> {
        Box::new(Self::InvalidRoute53HostedZone(msg.into()))
    }

    pub(crate) fn invalid_s3_bucket<S: Into<String>>(bucket: S) -> Box<Self> {
        Box::new(Self::InvalidS3Bucket(bucket.into()))
    }

    pub(crate) fn invalid_s3_encryption_algorithm<S: Into<String>>(alg: S) -> Box<Self> {
        Box::new(Self::InvalidS3EncryptionAlgorithm(alg.into()))
    }

    pub(crate) fn invalid_ssm_parameter_path<S: Into<String>>(path: S) -> Box<Self> {
        Box::new(Self::InvalidSsmParameterPath(path.into()))
    }

    pub(crate) fn invalid_ssm_tier<S: Into<String>>(tier: S) -> Box<Self> {
        Box::new(Self::InvalidSsmTier(tier.into()))
    }

    pub(crate) fn no_matching_route53_zones<S: Into<String>>(msg: S) -> Box<Self> {
        Box::new(Self::NoMatchingRoute53Zones(msg.into()))
    }
}

impl Display for InvalidCertificateRequest {
    fn fmt(&self, f: &mut Formatter) -> Result<(), FormatError> {
        match self {
            Self::ContactsEmpty => f.write_str("Contacts cannot be empty"),
            Self::DirectoryEmpty => f.write_str("Directory cannot be empty"),
            Self::DomainNamesEmpty => f.write_str("DomainNames cannot be empty"),
            Self::InvalidAcmCertificateArn(arn) => write!(f, "Invalid ACM certificate ARN: {}", arn),
            Self::InvalidAcmConfiguration(msg) => write!(f, "Invalid ACM configuration: {}", msg),
            Self::InvalidContact(msg) => write!(f, "Invalid contact: {}", msg),
            Self::InvalidDirectoryUrl(msg) => write!(f, "Invalid directory URL: {}", msg),
            Self::InvalidRoute53HostedZone(msg) => write!(f, "Invalid Route 53 hosted zone: {}", msg),
            Self::InvalidS3EncryptionAlgorithm(alg) => write!(f, "Invalid S3EncryptionAlgorithm: {}", alg),
            Self::InvalidS3Bucket(bucket) => write!(f, "Invalid S3 bucket: {}", bucket),
            Self::InvalidSsmParameterPath(path) => write!(f, "Invalid SSM parameter path: {}", path),
            Self::InvalidSsmTier(tier) => write!(f, "Invalid SSM tier: {}", tier),
            Self::NoMatchingRoute53Zones(domain) => write!(f, "No matching Route 53 zones for domain: {}", domain),
        }
    }
}

impl Error for InvalidCertificateRequest {}
