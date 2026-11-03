use super::dns_name::DaneDnsName;
use chrono::{DateTime, Utc};

use miette::Diagnostic;
use thiserror::Error;

use hickory_proto::rr::{RData, RecordType};
use hickory_resolver::Resolver;
use hickory_resolver::config::{NameServerConfig, ResolverConfig, ResolverOpts};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use std::net::IpAddr;

#[cfg(feature = "tracing")]
use tracing::{Level, event};

#[derive(Error, Diagnostic, Debug)]
pub enum DaneFetchError {
    #[error("DNS resolution failed: {0}")]
    #[diagnostic(code(dane_fetch))]
    DnsResolutionFailed(String),

    #[error("DNSSEC validation failed")]
    #[diagnostic(severity(Error), code(dane_fetch))]
    DnssecValidationFailed,

    #[error("DNSSEC signatures not found — record is not authenticated")]
    #[diagnostic(severity(Warning), code(dane_fetch))]
    DnssecNotEnabled,

    #[error("No OPENPGPKEY (TYPE 61) records found")]
    #[diagnostic(code(dane_fetch))]
    NoOpenpgpkeyRecord,

    #[error("Multiple OPENPGPKEY records found — only the first will be used")]
    #[diagnostic(severity(Warning), code(dane_fetch))]
    MultipleRecords,
}

#[derive(Debug)]
pub enum DaneFetchSuccess {
    DnsResolutionSucceeded,
    DnssecValidationPassed,
    OpenpgpkeyRecordFound,
}

#[derive(Debug)]
pub struct DaneFetch {
    pub errors: Vec<DaneFetchError>,
    pub successes: Vec<DaneFetchSuccess>,
    pub data: Option<Vec<u8>>,
    pub timestamp: DateTime<Utc>,
}

impl DaneFetch {
    #[cfg_attr(feature = "tracing", tracing::instrument)]
    pub async fn fetch(dane_dns_name: &DaneDnsName, dns_server: Option<&str>) -> DaneFetch {
        let mut result = DaneFetch {
            errors: Vec::new(),
            successes: Vec::new(),
            data: None,
            timestamp: Utc::now(),
        };

        let fqdn = &dane_dns_name.fqdn;

        #[cfg(feature = "tracing")]
        event!(Level::TRACE, "Looking up OPENPGPKEY record for: {}", fqdn);

        let resolver = match dns_server {
            Some(ip) => {
                let addr: IpAddr = ip.parse().expect("Invalid DNS_SERVER IP address");
                let ns = vec![NameServerConfig::udp_and_tcp(addr)];
                let config = ResolverConfig::from_parts(None, vec![], ns);
                Resolver::builder_with_config(config, TokioRuntimeProvider::default())
                    .build()
                    .expect("Failed to build DNS resolver")
            }
            None => Resolver::builder_tokio()
                .expect("Failed to create DNS resolver")
                .build()
                .expect("Failed to build DNS resolver"),
        };

        match resolver.lookup(fqdn.as_str(), RecordType::OPENPGPKEY).await {
            Ok(lookup) => {
                result
                    .successes
                    .push(DaneFetchSuccess::DnsResolutionSucceeded);

                #[cfg(feature = "tracing")]
                event!(Level::TRACE, "DNS resolution succeeded for: {}", fqdn);

                let records: Vec<Vec<u8>> = lookup
                    .answers()
                    .iter()
                    .filter_map(|record| match &record.data {
                        RData::OPENPGPKEY(key) => Some(key.public_key.clone()),
                        _ => None,
                    })
                    .collect();

                if records.is_empty() {
                    result.errors.push(DaneFetchError::NoOpenpgpkeyRecord);
                } else {
                    result
                        .successes
                        .push(DaneFetchSuccess::OpenpgpkeyRecordFound);

                    if records.len() > 1 {
                        result.errors.push(DaneFetchError::MultipleRecords);
                    }

                    result.data = Some(records.into_iter().next().unwrap());
                }
            }
            Err(err) => {
                #[cfg(feature = "tracing")]
                event!(Level::TRACE, "DNS resolution failed for {}: {}", fqdn, err);

                result
                    .errors
                    .push(DaneFetchError::DnsResolutionFailed(err.to_string()));
                return result;
            }
        }

        let dnssec_resolver = match dns_server {
            Some(ip) => {
                let addr: IpAddr = ip.parse().expect("Invalid DNS_SERVER IP address");
                let ns = vec![NameServerConfig::udp_and_tcp(addr)];
                let config = ResolverConfig::from_parts(None, vec![], ns);
                Resolver::builder_with_config(config, TokioRuntimeProvider::default())
                    .with_options({
                        let mut opts = ResolverOpts::default();
                        opts.validate = true;
                        opts
                    })
                    .build()
                    .expect("Failed to build DNSSEC resolver")
            }
            None => Resolver::builder_tokio()
                .expect("Failed to create DNSSEC resolver")
                .with_options({
                    let mut opts = ResolverOpts::default();
                    opts.validate = true;
                    opts
                })
                .build()
                .expect("Failed to build DNSSEC resolver"),
        };

        match dnssec_resolver
            .lookup(fqdn.as_str(), RecordType::OPENPGPKEY)
            .await
        {
            Ok(_) => {
                #[cfg(feature = "tracing")]
                event!(Level::TRACE, "DNSSEC validation passed for: {}", fqdn);

                result
                    .successes
                    .push(DaneFetchSuccess::DnssecValidationPassed);
            }
            Err(_) => {
                #[cfg(feature = "tracing")]
                event!(Level::TRACE, "DNSSEC not available for: {}", fqdn);

                result.errors.push(DaneFetchError::DnssecNotEnabled);
            }
        }

        result
    }
}
