pub(crate) const ACM_STATUS_ISSUED: &str = "ISSUED";
pub(crate) const ACM_STATUS_EXPIRED: &str = "EXPIRED";
pub(crate) const ACM_TYPE_IMPORTED: &str = "IMPORTED";

pub(crate) const CHALLENGE_TYPE_DNS01: &str = "dns-01";
pub(crate) const CHALLENGE_TYPE_HTTP01: &str = "http-01";

pub(crate) const DEFAULT_SSM_ACME_PATH: &str = "/AcmeParameters";
pub(crate) const ENV_SSM_PARAMETER_PATH: &str = "AcmeParameterPath";

pub(crate) const S3_ENCRYPTION_AES: &str = "AES256";
pub(crate) const S3_ENCRYPTION_KMS: &str = "aws:kms";

pub(crate) const SSM_TIER_STANDARD: &str = "Standard";
pub(crate) const SSM_TIER_ADVANCED: &str = "Advanced";
pub(crate) const SSM_TIER_INTELLIGENT_TIERING: &str = "Intelligent-Tiering";
pub(crate) const SSM_TYPE_SECURE_STRING: &str = "SecureString";