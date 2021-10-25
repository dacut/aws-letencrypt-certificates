use crate::{
    auth::CertificateAuthorization,
    storage::{CertificateStorage, CertificateStorageResult},
};
use acme2::Order;
use aws_lambda_events::event::{
    alb::{AlbTargetGroupRequest, AlbTargetGroupResponse},
    apigw::{ApiGatewayProxyRequest, ApiGatewayProxyResponse, ApiGatewayV2httpRequest, ApiGatewayV2httpResponse},
};
use serde::{self, Deserialize, Serialize};

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

    #[serde(rename = "DomainNames")]
    pub(crate) domain_names: Vec<String>,

    #[serde(rename = "Contacts")]
    pub(crate) contacts: Vec<String>,

    #[serde(rename = "Authorization")]
    pub(crate) auth: CertificateAuthorization,

    #[serde(rename = "Storage")]
    pub(crate) storage: Vec<CertificateStorage>,

    #[serde(rename = "State")]
    pub(crate) state: Option<ValidationState>,
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

    #[serde(rename = "State")]
    pub(crate) state: Option<ValidationState>,
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

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct ValidationState {
    #[serde(rename = "Order")]
    pub(crate) order: Order,

    #[serde(rename = "PrivateKey")]
    pub(crate) private_key: Option<String>,

    #[serde(rename = "NumTries")]
    pub(crate) n_tries: u32,
}
