use {
    super::{get_challenge_token_for_auth, AuthorizationHandler, CleanupDirective},
    crate::{
        constants::CHALLENGE_TYPE_DNS01,
        errors::{CertificateRequestError, InvalidCertificateRequest},
    },
    acme2::{Authorization, AuthorizationStatus, Challenge, ChallengeStatus},
    async_trait::async_trait,
    base64,
    lamedh_runtime::{self, Error as LambdaError},
    log::{debug, error, info},
    ring::digest::{digest, SHA256   },
    rusoto_core::Region,
    rusoto_route53::{
        Change, ChangeBatch, ChangeResourceRecordSetsRequest, GetChangeRequest, GetHostedZoneRequest, HostedZone,
        ListHostedZonesRequest, ResourceRecord, ResourceRecordSet, Route53, Route53Client, ListResourceRecordSetsRequest,
    },
    serde::{self, Deserialize, Serialize},
    std::{str::FromStr, time::Duration},
    tokio::time::sleep,
};

/// Configuration for DNS-01 authorization using Route 53.
#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct DnsRoute53Authorization {
    #[serde(rename = "HostedZoneId", default)]
    pub(crate) hosted_zone_id: Option<String>,

    #[serde(rename = "Region", default)]
    pub(crate) region: Option<String>,
}

impl DnsRoute53Authorization {
    async fn get_hosted_zone_id_for_domain_name(
        &self,
        route53_client: &Route53Client,
        domain_name: &str,
    ) -> Result<String, LambdaError> {
        match self.hosted_zone_id {
            Some(ref hosted_zone_id) => {
                let ghzi = GetHostedZoneRequest {
                    id: hosted_zone_id.clone(),
                };

                let ghzo = match route53_client.get_hosted_zone(ghzi).await {
                    Ok(ghzo) => ghzo,
                    Err(e) => {
                        error!("Failed to get hosted zone {}: {}", hosted_zone_id, e);
                        return Err(InvalidCertificateRequest::invalid_route53_hosted_zone(format!(
                            "Failed to get hosted zone {}: {}",
                            hosted_zone_id, e
                        )));
                    }
                };

                if !domain_name_matches_zone(domain_name, ghzo.hosted_zone.name.as_str()) {
                    error!(
                        "Hosted zone {} has domain name {} but certificate requests domain {}",
                        hosted_zone_id, ghzo.hosted_zone.name, domain_name
                    );

                    return Err(InvalidCertificateRequest::invalid_route53_hosted_zone(format!(
                        "Hosted zone {} has domain name {} but certificate requests domain {}",
                        hosted_zone_id, ghzo.hosted_zone.name, domain_name
                    )));
                }

                Ok(hosted_zone_id.clone())
            }

            None => {
                let mut lhzi = ListHostedZonesRequest::default();
                let mut best_match: Option<HostedZone> = None;

                loop {
                    let lhzo = match route53_client.list_hosted_zones(lhzi.clone()).await {
                        Ok(lhzo) => lhzo,
                        Err(e) => {
                            error!("Failed to list hosted zones: {}", e);
                            return Err(CertificateRequestError::unexpected_aws_response(format!(
                                "Failed to list hosted zones: {}",
                                e
                            )));
                        }
                    };

                    for hz in lhzo.hosted_zones {
                        if domain_name_matches_zone(domain_name, hz.name.as_str()) {
                            match best_match {
                                None => best_match = Some(hz),
                                Some(bmhz) if hz.name.len() > bmhz.name.len() => best_match = Some(hz),
                                _ => (),
                            }
                        }
                    }

                    if lhzo.is_truncated {
                        if lhzo.next_marker.is_none() {
                            error!("Route53 indicated the list was truncated but did not provide a marker to continue");
                            return Err(CertificateRequestError::unexpected_aws_response(format!(
                                "Route53 indicated the list was truncated but did not provide a marker to continue"
                            )));
                        }

                        lhzi.marker = lhzo.next_marker;
                    } else {
                        break;
                    }
                }

                best_match
                    .map(|hz| hz.id)
                    .ok_or(InvalidCertificateRequest::no_matching_route53_zones(domain_name.to_string()))
            }
        }
    }

    async fn remove_existing_records(&self, route53_client: &mut Route53Client, hosted_zone_id: &str, record_name: &str) -> Result<(), LambdaError> {
        let mut lrrsi = ListResourceRecordSetsRequest{
            hosted_zone_id: hosted_zone_id.to_string(),
            start_record_name: Some(record_name.to_string()),
            start_record_type: Some("TXT".to_string()),
            ..Default::default()
        };

        let mut records_to_delete = vec![];

        'list_records: loop {
            let lrrso = route53_client.list_resource_record_sets(lrrsi.clone()).await?;
            if !lrrso.is_truncated || lrrso.next_record_name.is_none() {
                break;
            }

            for resource_record in lrrso.resource_record_sets {
                if resource_record.name.as_str() != record_name || resource_record.type_.as_str() != "TXT" {
                    break 'list_records;
                }

                records_to_delete.push(Change{action: "DELETE".to_string(), resource_record_set: resource_record});
            }

            match lrrso.next_record_name {
                None => break,
                Some(ref nrn) if nrn.as_str() != record_name => break,
                _ => (),
            }

            match lrrso.next_record_type {
                None => break,
                Some(ref nrt) if nrt.as_str() != "TXT" => break,
                _ => (),
            }
            
            lrrsi.start_record_identifier = lrrso.next_record_identifier;
        }

        if records_to_delete.len() > 0 {
            info!("Deleting {} record(s) from {}", records_to_delete.len(), hosted_zone_id);
            let crrsi = ChangeResourceRecordSetsRequest{
                hosted_zone_id: hosted_zone_id.to_string(),
                change_batch: ChangeBatch{changes: records_to_delete, comment: None},
            };

            let crrso = route53_client.change_resource_record_sets(crrsi).await?;
            info!("Waiting for Route 53 change {} to propagate", crrso.change_info.id);
            self.wait_for_change_sync(route53_client, &crrso.change_info.id).await?;

            info!("Sleeping for 10 seconds to let Route 53 settle down");
            sleep(Duration::from_secs(10)).await;
        }
        
        Ok(())
    }

    async fn wait_for_change_sync(&self, route53_client: &mut Route53Client, change_id: &str) -> Result<(), LambdaError> {
        // Due to a rusoto bug, we need to trim leading slashes from the change id.
        let gci = GetChangeRequest {
            id: change_id.trim_start_matches('/').to_string(),
        };

        loop {
            let gco = match route53_client.get_change(gci.clone()).await {
                Ok(gco) => gco,
                Err(e) => {
                    error!("Failed to get information on Route 53 change {}: {}", gci.id, e);
                    return Err(CertificateRequestError::unexpected_aws_response(format!(
                        "Failed to get information on Route 53 change {}: {}",
                        gci.id, e
                    )));
                }
            };

            match gco.change_info.status.as_str() {
                "INSYNC" => break,
                "PENDING" => sleep(Duration::from_secs(1)).await,
                other => {
                    error!("Route 53 change {} has unexpected status {}", gci.id, other);
                    return Err(CertificateRequestError::unexpected_aws_response(format!(
                        "Route 53 change {} has unexpected status {}",
                        gci.id, other
                    )));
                }
            }
        }

        Ok(())
    }
}

impl Default for DnsRoute53Authorization {
    fn default() -> Self {
        Self {
            hosted_zone_id: None,
            region: None,
        }
    }
}

#[async_trait]
impl AuthorizationHandler for DnsRoute53Authorization {
    async fn setup(&mut self) -> Result<(), LambdaError> {
        Ok(())
    }

    async fn auth(
        &self,
        auth: Authorization,
    ) -> Result<(Authorization, Challenge, Vec<CleanupDirective>), LambdaError> {
        debug!("Handling authorization: {:?}", auth);
        let domain_name: &str = &auth.identifier.value;
        let (challenge, _token) = get_challenge_token_for_auth(&auth, CHALLENGE_TYPE_DNS01)?;

        let key_auth = match challenge.key_authorization() {
            Ok(maybe_key_auth) => match maybe_key_auth {
                Some(ka) => ka,
                None => {
                    error!("No {} key authorization found for {}", CHALLENGE_TYPE_DNS01, domain_name);
                    return Err(CertificateRequestError::token_not_available(CHALLENGE_TYPE_DNS01, domain_name));
                }
            },
            Err(e) => {
                error!("Failed to get ACME key authorization for {}: {}", domain_name, e);
                return Err(Box::new(e));
            }
        };

        let region = match self.region {
            Some(ref region) => Region::from_str(region.as_str())?,
            None => Region::UsEast1,
        };
        let mut route53_client = Route53Client::new(region);

        // Find the best hosted zone for the domain.
        let hosted_zone_id = self.get_hosted_zone_id_for_domain_name(&route53_client, domain_name).await?;
        let record_name = format!("_acme-challenge.{}", domain_name);

        // Remove any existing records for the domain.
        self.remove_existing_records(&mut route53_client, &hosted_zone_id, &record_name).await?;

        // Write the challenge to Route53.
        // DNS challenges need to SHA256-hash the key again and base64 encode the result without padding.
        let hashed_key = base64::encode_config(digest(&SHA256, key_auth.as_bytes()).as_ref(), base64::URL_SAFE_NO_PAD);
        let record_value = format!(r#""{}""#, hashed_key); // TXT record must be quoted
        info!("Writing key authorization for {} to Route 53 zone {}: {}", record_name, hosted_zone_id, record_value);

        let change_batch = ChangeBatch {
            comment: Some(format!("ACMEv2 Challenge for {}", domain_name)),
            changes: vec![Change {
                action: "UPSERT".to_string(),
                resource_record_set: ResourceRecordSet {
                    name: record_name.clone(),
                    resource_records: Some(vec![ResourceRecord {
                        value: record_value.clone(),
                    }]),
                    ttl: Some(10),
                    type_: "TXT".to_string(),
                    ..Default::default()
                },
            }],
        };
        let crrsi = ChangeResourceRecordSetsRequest {
            hosted_zone_id: hosted_zone_id.clone(),
            change_batch,
        };

        let crrso = match route53_client.change_resource_record_sets(crrsi).await {
            Ok(crrso) => crrso,
            Err(e) => {
                error!(
                    "Failed to write key authorization for {} to Route 53 zone {}: {}",
                    domain_name, hosted_zone_id, e
                );
                return Err(CertificateRequestError::unexpected_aws_response(format!(
                    "Failed to write key authorization for {} to Route 53 zone {}: {}",
                    domain_name, hosted_zone_id, e
                )));
            }
        };

        // Wait for the change to propagate.
        info!("Waiting for Route 53 change to propagate for {}", domain_name);
        self.wait_for_change_sync(&mut route53_client, &crrso.change_info.id).await?;

        let cleanup = vec![CleanupDirective::DeleteRoute53Record {
            hosted_zone_id: hosted_zone_id.clone(),
            record_name: format!("_acme-challenge.{}", domain_name),
            record_type: "TXT".to_string(),
            record_value,
            ttl: 10,
        }];

        info!("Informing ACME server that dns-01 validation is ready for {}", domain_name);
        // Signal to the ACME server that we're ready for verification.
        match challenge.validate().await {
            Ok(c) => c,
            Err(e) => {
                error!("Failed to send validation request to ACME server for {}: {}", domain_name, e);
                return Err(Box::new(e));
            }
        };

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
        let region = match self.region {
            Some(ref region) => Region::from_str(region.as_str())?,
            None => Region::UsEast1,
        };
        let route53_client = Route53Client::new(region);

        for directive in directives {
            match directive {
                CleanupDirective::DeleteRoute53Record {
                    hosted_zone_id,
                    record_name,
                    record_type,
                    record_value,
                    ttl,
                } => {
                    // Remove the challenge from Route 53.
                    let change_batch = ChangeBatch {
                        comment: Some(format!("ACMEv2 Challenge Cleanup for {}", record_name)),
                        changes: vec![Change {
                            action: "DELETE".to_string(),
                            resource_record_set: ResourceRecordSet {
                                name: record_name.clone(),
                                resource_records: Some(vec![ResourceRecord {
                                    value: record_value.clone(),
                                }]),
                                type_: record_type,
                                ttl: Some(ttl),
                                ..Default::default()
                            },
                        }],
                    };

                    let crrsi = ChangeResourceRecordSetsRequest {
                        hosted_zone_id: hosted_zone_id.clone(),
                        change_batch,
                    };

                    info!("Removing Route 53 record {}", record_name);
                    if let Err(e) = route53_client.change_resource_record_sets(crrsi).await {
                        error!(
                            "Failed to delete key authorization for {} in Route 53 zone {}: {}",
                            record_name, hosted_zone_id, e
                        );
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

fn domain_name_matches_zone(domain_name: &str, zone: &str) -> bool {
    let domain_name_with_dot = if domain_name.ends_with('.') {
        domain_name.to_string()
    } else {
        format!("{}.", domain_name)
    };

    let zone_with_dot = if zone.ends_with('.') {
        zone.to_string()
    } else {
        format!("{}.", zone)
    };

    domain_name_with_dot.ends_with(&zone_with_dot)
}
