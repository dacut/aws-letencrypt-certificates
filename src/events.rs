use {
    crate::{
        auth::CertificateAuthorization,
        storage::{CertificateStorage, CertificateStorageResult},
    },
    aws_lambda_events::event::{
        alb::{AlbTargetGroupRequest, AlbTargetGroupResponse},
        apigw::{ApiGatewayProxyRequest, ApiGatewayProxyResponse, ApiGatewayV2httpRequest, ApiGatewayV2httpResponse},
    },
    serde::{
        self,
        de::{
            self,
            value::{MapAccessDeserializer, SeqAccessDeserializer},
            Deserializer, MapAccess, SeqAccess, Visitor,
        },
        Deserialize, Serialize,
    },
    std::fmt::{Formatter, Result as FmtResult},
};

/// The incoming Lambda request.
///
/// This Lambda function can be called via AWS Step Functions (to keep the state machine powering the certficate
/// request/renewal going); an AWS Application Load Balancer integrated directly with
#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub(crate) enum Request {
    Certificate(Box<CertificateRequest>),
    ApiGatewayV1(Box<ApiGatewayProxyRequest>),
    ApiGatewayV2(Box<ApiGatewayV2httpRequest>),
    Alb(Box<AlbTargetGroupRequest>),
}

/// Structure for requesting a new certificate. For Lambda, this is a JSON structure (annotated below;
/// do not include comments in your JSON):
///
///     {
///         // The URL for the ACME server, e.g. "https://acme-staging-v02.api.letsencrypt.org/directory"
///         "Directory": str,
///         
///         // List of domain names to request/renew certificates for.       
///         "DomainNames": [str, ...]
///         
///         // List of contact URLs. Note that Let's Encrypt only supports one contact, and it must be a
///         // "mailto:user@domain" URL.
///         "Contacts": [str, ...]
///
///         // Instruction for handling authorization. See HttpS3Authorization.
///         "Authorization": { ... }
///
///         // An array of storage mechanisms for the certificate. See AcmStorage, S3Storage, and SsmStorage.
///         "Storage": []
///
///         // The current state of the request. This should be unset in the initial request. Pass the state
///         // from an incomplete response back into this value. All other values must be passed in unchanged
///         // from the initial request.
///         "State": {}
///     }
#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct CertificateRequest {
    /// The URL for the ACME server, e.g. `"https://acme-staging-v02.api.letsencrypt.org/directory"`
    #[serde(rename = "Directory")]
    pub(crate) directory: String,

    #[serde(rename = "DomainNames", deserialize_with = "string_or_vec")]
    pub(crate) domain_names: Vec<String>,

    #[serde(rename = "Contacts", deserialize_with = "string_or_vec")]
    pub(crate) contacts: Vec<String>,

    #[serde(rename = "Authorization")]
    pub(crate) auth: CertificateAuthorization,

    #[serde(rename = "Storage", deserialize_with = "cert_storage_or_vec")]
    pub(crate) storage: Vec<CertificateStorage>,
}

/// The types of responses we can send back.
#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub(crate) enum Response {
    Certificate(CertificateResponse),
    ApiGatewayV1(ApiGatewayProxyResponse),
    ApiGatewayV2(ApiGatewayV2httpResponse),
    Alb(AlbTargetGroupResponse),
}

impl From<ApiGatewayProxyResponse> for Response {
    fn from(api_gateway_proxy_response: ApiGatewayProxyResponse) -> Self {
        Self::ApiGatewayV1(api_gateway_proxy_response)
    }
}

impl From<ApiGatewayV2httpResponse> for Response {
    fn from(api_gatewayv2_http_response: ApiGatewayV2httpResponse) -> Self {
        Self::ApiGatewayV2(api_gatewayv2_http_response)
    }
}

impl From<AlbTargetGroupResponse> for Response {
    fn from(alb_target_group_response: AlbTargetGroupResponse) -> Self {
        Self::Alb(alb_target_group_response)
    }
}

/// The response to a certificate request. For Lambda, this is a JSON structure (annotated below;
/// do not include comments in your JSON):
///
///     {
///         // Inidicates whether the request is completed or additional steps are required.
///         "Completed": bool,
///
///         // If the request is completed, this indicates the status of the certificate.
///         "Status": str,
///
///         // If the request is completed, this holds information about where the certificate is
///         // stored. See AcmStorageResult, S3StorageResult, and SsmParameterStorageResult for details.
///         "StorageResults": []
///
///         // If the request is incomplete, this is the state parameter to pass into the subsequent
///         // invocation.
///         "State": {}
///     }
#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct CertificateResponse {
    #[serde(rename = "Finished")]
    pub(crate) finished: bool,

    #[serde(rename = "Status")]
    pub(crate) status: CertificateResponseStatus,

    #[serde(rename = "StorageResults")]
    pub(crate) storage: Vec<CertificateStorageResult>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub(crate) enum CertificateResponseStatus {
    Success,
    PartialSuccess,
    PendingValidation,
    PendingOrderFulfillment,
    Failed,
}

/// StringOrVec allows a string or a list of strings to be passed via JSON.
struct StringOrVec;
impl<'de> Visitor<'de> for StringOrVec {
    type Value = Vec<String>;

    fn expecting(&self, formatter: &mut Formatter) -> FmtResult {
        formatter.write_str("string or list of strings")
    }

    fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(vec![s.to_owned()])
    }

    fn visit_seq<S>(self, seq: S) -> Result<Self::Value, S::Error>
    where
        S: SeqAccess<'de>,
    {
        Deserialize::deserialize(SeqAccessDeserializer::new(seq))
    }
}

/// string_or_vec is a helper function to deserialize a string or a list of strings.
fn string_or_vec<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_any(StringOrVec)
}

/// CertStorageOrVec allows a CertificateStorage or a list of CertificateStorage objects to be passed via JSON.
struct CertStorageOrVec;
impl<'de> Visitor<'de> for CertStorageOrVec {
    type Value = Vec<CertificateStorage>;

    fn expecting(&self, formatter: &mut Formatter) -> FmtResult {
        formatter.write_str("CertificateStorage or list of CertificateStorage objects")
    }

    fn visit_map<M>(self, map: M) -> Result<Self::Value, M::Error>
    where
        M: MapAccess<'de>,
    {
        Deserialize::deserialize(MapAccessDeserializer::new(map))
    }

    fn visit_seq<S>(self, seq: S) -> Result<Self::Value, S::Error>
    where
        S: SeqAccess<'de>,
    {
        Deserialize::deserialize(SeqAccessDeserializer::new(seq))
    }
}

/// cert_or_vec is a helper function to deserialize a CertificateStorage object or a list of CertificateStorage objects
fn cert_storage_or_vec<'de, D>(deserializer: D) -> Result<Vec<CertificateStorage>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_any(CertStorageOrVec)
}

#[allow(unused_imports, dead_code)]
mod test {
    use {
        super::{CertificateRequest, Request},
        log::LevelFilter,
    };

    const BASIC_CERT_REQUEST: &str = r#"{
    "Directory": "https://acme-staging-v02.api.letsencrypt.org/directory",
    "DomainNames": ["example.com"],
    "Contacts": ["mailto:hello@example.com"],
    "Authorization": {
        "Type": "DnsRoute53"
    },
    "Storage": [
        {
            "Type": "Acm"
        }
    ]
}"#;

    const NON_LIST_REQUEST: &str = r#"{
        "Directory": "https://acme-staging-v02.api.letsencrypt.org/directory",
        "DomainNames": "example.com",
        "Contacts": "mailto:hello@example.com",
        "Authorization": {
            "Type": "DnsRoute53"
        },
        "Storage": {
            "Type": "Acm"
        }
    }"#;

    #[tokio::test]
    async fn test_deser_basic_certificate_request() {
        env_logger::builder().filter_level(LevelFilter::Debug).init();
        let result = serde_json::from_str::<CertificateRequest>(&BASIC_CERT_REQUEST);
        assert!(result.is_ok(), "Error: {:?}", result);

        let result = serde_json::from_str::<Request>(&BASIC_CERT_REQUEST);
        assert!(result.is_ok(), "Error: {:?}", result);
    }

    #[tokio::test]
    async fn test_deser_non_list_certificate_request() {
        env_logger::builder().filter_level(LevelFilter::Debug).init();
        let result = serde_json::from_str::<CertificateRequest>(&NON_LIST_REQUEST);
        assert!(result.is_ok(), "Error: {:?}", result);

        let result = serde_json::from_str::<Request>(&NON_LIST_REQUEST);
        assert!(result.is_ok(), "Error: {:?}", result);
    }
}
