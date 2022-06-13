#![warn(clippy::all)]
#![allow(clippy::redundant_field_names)]

mod auth;
mod constants;
mod errors;
mod events;
mod storage;
mod utils;
mod workflow;

use {
    crate::{
        auth::AuthorizationHandler,
        errors::InvalidCertificateRequest,
        events::{CertificateRequest, Request, Response},
        utils::ssm_acme_parameter_path,
        workflow::ValidatedCertificateRequest,
    },
    aws_lambda_events::{
        encodings::Body,
        event::{
            alb::{AlbTargetGroupRequest, AlbTargetGroupResponse},
            apigw::{
                ApiGatewayProxyRequest, ApiGatewayProxyResponse, ApiGatewayV2httpRequest, ApiGatewayV2httpResponse,
            },
        },
    },
    http::{HeaderMap, HeaderValue},
    lambda_runtime::{self, Error as LambdaError, LambdaEvent},
    log::{error, info},
    rusoto_core::Region,
    rusoto_ssm::{GetParameterRequest, Ssm, SsmClient},
    serde::{Deserialize, Serialize},
    serde_json::{Deserializer as JsonDeserializer, Serializer as JsonSerializer, Value},
    url::Url,
};

/// Main entrypoint for the runtime. This just dispatches to the Lambda handler.
#[tokio::main]
async fn main() {
    env_logger::init();
    let service = lambda_runtime::service_fn(handler_main);
    match lambda_runtime::run(service).await {
        Ok(()) => println!("lambda_runtime exited successfully"),
        Err(e) => eprintln!("lambda_runtime failed: {:#}", e),
    }
}

/// Entrypoint for Lambda events.
async fn handler_main(req_and_context: LambdaEvent<Value>) -> Result<Response, LambdaError> {
    let basic = req_and_context.payload;
    eprintln!("Incoming value: {}", basic);
    let basic_bytes = Vec::new();
    let mut ser = JsonSerializer::new(basic_bytes);
    basic.serialize(&mut ser)?;

    let mut basic_vec: Vec<u8> = ser.into_inner();
    let basic_bytes: &[u8] = basic_vec.as_mut_slice();
    let mut des = JsonDeserializer::from_slice(basic_bytes);

    let req = Request::deserialize(&mut des)?;

    match req {
        Request::Certificate(req) => handle_certificate_request(*req).await,
        Request::ApiGatewayV1(req) => handle_apigatewayv1_request(req).await,
        Request::ApiGatewayV2(req) => handle_apigatewayv2_request(req).await,
        Request::Alb(req) => handle_alb_request(req).await,
    }
}

/// Handler for a new certificate request. This is invoked by EventBridge or directly through a lambda:Invoke
/// call.
async fn handle_certificate_request(mut req: CertificateRequest) -> Result<Response, LambdaError> {
    // Perform some basic parameter validation.
    if req.directory.is_empty() {
        return Err(InvalidCertificateRequest::directory_empty());
    }

    if req.domain_names.is_empty() {
        return Err(InvalidCertificateRequest::domain_names_empty());
    }

    if req.contacts.is_empty() {
        return Err(InvalidCertificateRequest::contacts_empty());
    }

    let dir_url =
        Url::parse(&req.directory).map_err(|e| InvalidCertificateRequest::invalid_directory_url(format!("{}", e)))?;

    match dir_url.scheme() {
        "http" | "https" => (),
        _ => {
            return Err(InvalidCertificateRequest::invalid_directory_url(format!(
                "Directory URL scheme must be http or https: {}",
                &req.directory
            )))
        }
    }

    let dir_host = dir_url
        .host_str()
        .ok_or_else(|| {
            InvalidCertificateRequest::invalid_directory_url(format!(
                "Directory URL must have a host: {}",
                &req.directory
            ))
        })?
        .to_string();

    // Let's Encrypt requires all contacts to be mailto: contacts.
    if dir_host.ends_with(".letsencrypt.org") {
        for ref contact in &req.contacts {
            if !contact.starts_with("mailto:") {
                return Err(InvalidCertificateRequest::invalid_contact(format!(
                    "Let's Encrypt only supports \"mailto:\" contacts: {:#?}",
                    contact
                )));
            }
        }
    }

    // Check each storage provider.
    for provider in req.storage.iter_mut() {
        match provider.validate().await {
            Ok(()) => (),
            Err(e) => {
                error!("Failed to validate storage provider: {}", e);
                return Err(e);
            }
        }
    }

    // And check the authorization provider.
    match req.auth.setup().await {
        Ok(()) => (),
        Err(e) => {
            error!("Failed to setup authorization provider: {}", e);
            return Err(e);
        }
    }

    let mut req = ValidatedCertificateRequest {
        directory: req.directory,
        domain_names: req.domain_names,
        contacts: req.contacts,
        auth: req.auth,
        storage: req.storage,
        dir_host: dir_host.to_string(),
    };

    req.run_workflow().await
}

/// Return the key authentication for a given token from SSM.
async fn get_key_auth_for_token(token: &str) -> Option<String> {
    // Get the key authorization from SSM
    let ssm = SsmClient::new(Region::default());
    let token_param_name = format!("{}/Tokens/{}", ssm_acme_parameter_path(), token);
    let gp_request = GetParameterRequest {
        name: token_param_name.clone(),
        with_decryption: Some(true),
    };
    info!("Getting key authorization from SSM parameter {}", token_param_name);
    match ssm.get_parameter(gp_request).await {
        Ok(result) => match result.parameter {
            Some(parameter) => match parameter.value {
                Some(token) => {
                    info!("Found key authorization for token {}", token_param_name);
                    return Some(token);
                }
                None => {
                    error!("Found key authorization parameter for token {} but no associated value", token_param_name);
                    None
                }
            },
            None => {
                error!("No parameter returned for SSM parameter {}", token_param_name);
                None
            }
        },
        Err(e) => {
            error!("Failed to retrieve SSM parameter {}: {:#}", token_param_name, e);
            None
        }
    }
}

/// Handle an HTTP-01 challenge made via an API Gateway v1 request.
async fn handle_apigatewayv1_request(req: Box<ApiGatewayProxyRequest>) -> Result<Response, LambdaError> {
    let mut headers = HeaderMap::with_capacity(1);
    let multi_value_headers = HeaderMap::new();
    headers.insert("Content-Type", HeaderValue::from_static("text/plain; charset=utf-8"));

    match req.path_parameters.get("token") {
        None => Ok(ApiGatewayProxyResponse {
            status_code: 500,
            headers: headers,
            multi_value_headers: multi_value_headers,
            body: Some(Body::Text("token parameter missing in proxy integration".to_string())),
            is_base64_encoded: Some(false),
        }
        .into()),
        Some(token) => match get_key_auth_for_token(&token).await {
            None => Ok(ApiGatewayProxyResponse {
                status_code: 404,
                headers: headers,
                multi_value_headers: multi_value_headers,
                body: Some(Body::Text("Not found".to_string())),
                is_base64_encoded: Some(false),
            }
            .into()),
            Some(auth_value) => Ok(ApiGatewayProxyResponse {
                status_code: 200,
                headers: headers,
                multi_value_headers: multi_value_headers,
                body: Some(Body::Text(auth_value)),
                is_base64_encoded: Some(false),
            }
            .into()),
        },
    }
}

/// Handle an HTTP-01 challenge made via an API Gateway v2 request.
async fn handle_apigatewayv2_request(req: Box<ApiGatewayV2httpRequest>) -> Result<Response, LambdaError> {
    let mut headers = HeaderMap::with_capacity(1);
    let multi_value_headers = HeaderMap::new();
    headers.insert("Content-Type", HeaderValue::from_static("text/plain; charset=utf-8"));

    match req.path_parameters.get("token") {
        None => Ok(ApiGatewayV2httpResponse {
            status_code: 500,
            headers: headers,
            multi_value_headers: multi_value_headers,
            body: Some(Body::Text("token parameter missing in proxy integration".to_string())),
            is_base64_encoded: Some(false),
            cookies: vec![],
        }
        .into()),
        Some(token) => match get_key_auth_for_token(&token).await {
            None => Ok(ApiGatewayV2httpResponse {
                status_code: 404,
                headers: headers,
                multi_value_headers: multi_value_headers,
                body: Some(Body::Text("Not found".to_string())),
                is_base64_encoded: Some(false),
                cookies: vec![],
            }
            .into()),
            Some(auth_value) => Ok(ApiGatewayV2httpResponse {
                status_code: 200,
                headers: headers,
                multi_value_headers: multi_value_headers,
                body: Some(Body::Text(auth_value)),
                is_base64_encoded: Some(false),
                cookies: vec![],
            }
            .into()),
        },
    }
}

/// Handle an HTTP-01 challenge made to an application load balancer (ALB).
async fn handle_alb_request(req: Box<AlbTargetGroupRequest>) -> Result<Response, LambdaError> {
    let mut headers = HeaderMap::with_capacity(1);
    let multi_value_headers = HeaderMap::new();
    headers.insert("Content-Type", HeaderValue::from_static("text/plain; charset=utf-8"));

    match req.path {
        None => {
            error!("No path sent from load balancer");
            Ok(AlbTargetGroupResponse {
                status_code: 400,
                status_description: Some("Bad Request".to_string()),
                headers: headers,
                multi_value_headers: multi_value_headers,
                body: Some(Body::Text("path must be present in request".to_string())),
                is_base64_encoded: false,
            }
            .into())
        }
        Some(mut path) => {
            while path.starts_with('/') {
                path = path.split_at(1).1.to_string();
            }

            let parts: Vec<&str> = path.split('/').collect();
            if parts.len() != 3 || parts[0] != ".well-known" || parts[1] != "acme-challenge" {
                Ok(AlbTargetGroupResponse {
                    status_code: 404,
                    status_description: Some("Not Found".to_string()),
                    headers: headers,
                    multi_value_headers: multi_value_headers,
                    body: Some(Body::Text("Not found".to_string())),
                    is_base64_encoded: false,
                }
                .into())
            } else {
                match get_key_auth_for_token(parts[2]).await {
                    None => Ok(AlbTargetGroupResponse {
                        status_code: 404,
                        status_description: Some("Not Found".to_string()),
                        headers: headers,
                        multi_value_headers: multi_value_headers,
                        body: Some(Body::Text("Not found".to_string())),
                        is_base64_encoded: false,
                    }
                    .into()),
                    Some(auth_value) => Ok(AlbTargetGroupResponse {
                        status_code: 200,
                        status_description: Some("OK".to_string()),
                        headers: headers,
                        multi_value_headers: multi_value_headers,
                        body: Some(Body::Text(auth_value)),
                        is_base64_encoded: false,
                    }
                    .into()),
                }
            }
        }
    }
}
