use crate::constants::{DEFAULT_SSM_ACME_PATH, ENV_SSM_PARAMETER_PATH};
use std::{
    env::var_os,
    str::FromStr,
};
use rusoto_core::{Region, region::ParseRegionError};

#[derive(Clone, Debug)]
pub(crate) struct CertificateComponents {
    pub(crate) cert_pem: String,
    pub(crate) chain_pem: String,
    pub(crate) fullchain_pem: String,
    pub(crate) pkey_pem: String,
}

pub(crate) const fn default_false() -> bool {
    false
}

pub(crate) fn default_aes256() -> String {
    "AES256".to_string()
}

pub(crate) fn empty_string() -> String {
    "".to_string()
}

pub(crate) fn ssm_acme_parameter_path() -> String {
    match var_os(ENV_SSM_PARAMETER_PATH) {
        Some(path) => path.to_string_lossy().into(),
        None => DEFAULT_SSM_ACME_PATH.to_string(),
    }
}

pub(crate) fn validate_and_sanitize_ssm_parameter_path(path: &str) -> Option<String> {
    let path = if path.ends_with("/") {
        &path[..path.len() - 1]
    } else {
        path
    };

    for (i, el) in path.split("/").enumerate() {
        if i == 0 {
            if el.len() != 0 {
                return None;
            }
        } else {
            if i == 1 {
                if el == "aws" || el == "ssm" {
                    return None;
                }
            }

            if el.len() == 0 {
                return None;
            }

            for c in el.bytes() {
                if !c.is_ascii_alphanumeric() && c != b'_' && c != b'.' && c != b'-' {
                    return None;
                }
            }
        }
    }

    Some(path.to_string())
}

pub(crate) fn s3_bucket_location_constraint_to_region(location_constraint: Option<String>) -> Result<Region, ParseRegionError> {
    match location_constraint {
        None => Ok(Region::UsEast1),
        Some(ref name) => match name.as_ref() {
            "" => Ok(Region::UsEast1),
            "EU" => Ok(Region::EuWest1),
            _ => Region::from_str(name),
        },
    }
}