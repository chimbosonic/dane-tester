use super::dns_name::DaneDnsName;
use chrono::{DateTime, Utc};

use miette::Diagnostic;
use thiserror::Error;

use hickory_proto::dnssec::Proof;
use hickory_proto::op::Query;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::txt::Parser;
use hickory_resolver::Resolver;
use hickory_resolver::config::{NameServerConfig, ResolverConfig, ResolverOpts};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::net::{DnsError, NetError};
use hickory_resolver::recursor::{
    DnssecConfig, DnssecPolicy, Recursor, RecursorError, RecursorOptions,
};
use std::net::IpAddr;
use std::sync::LazyLock;
use std::time::Instant;

#[cfg(feature = "tracing")]
use tracing::{Level, event};

static ROOT_SERVERS: LazyLock<Vec<IpAddr>> = LazyLock::new(|| {
    let (_, zone) = Parser::new(include_str!("../named.root"), None, Some(Name::root()))
        .parse()
        .expect("embedded named.root is a valid zone file");
    zone.values()
        .flat_map(|rrset| rrset.records_without_rrsigs())
        .filter_map(|record| record.data.ip_addr())
        .collect()
});

fn root_servers() -> &'static [IpAddr] {
    &ROOT_SERVERS
}

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
    pub data: Vec<Vec<u8>>,
    pub timestamp: DateTime<Utc>,
}

enum LookupError {
    NoRecords,
    Bogus,
    Failed(String),
}

impl From<NetError> for LookupError {
    fn from(err: NetError) -> Self {
        match &err {
            NetError::Dns(DnsError::DnssecBogus)
            | NetError::Dns(DnsError::Nsec {
                proof: Proof::Bogus,
                ..
            }) => LookupError::Bogus,
            _ if err.is_no_records_found() || err.is_nx_domain() => LookupError::NoRecords,
            _ => LookupError::Failed(err.to_string()),
        }
    }
}

impl From<RecursorError> for LookupError {
    fn from(err: RecursorError) -> Self {
        match err {
            RecursorError::Net(err) => LookupError::from(err),
            _ if err.is_no_records_found() || err.is_nx_domain() => LookupError::NoRecords,
            _ => LookupError::Failed(err.to_string()),
        }
    }
}

impl DaneFetch {
    #[cfg_attr(feature = "tracing", tracing::instrument)]
    pub async fn fetch(dane_dns_name: &DaneDnsName, dns_server: Option<&str>) -> DaneFetch {
        let mut result = DaneFetch {
            errors: Vec::new(),
            successes: Vec::new(),
            data: Vec::new(),
            timestamp: Utc::now(),
        };

        let fqdn = &dane_dns_name.fqdn;

        #[cfg(feature = "tracing")]
        event!(Level::TRACE, "Looking up OPENPGPKEY record for: {}", fqdn);

        let records = match lookup(fqdn, dns_server).await {
            Ok(records) => records,
            Err(LookupError::NoRecords) => {
                result
                    .successes
                    .push(DaneFetchSuccess::DnsResolutionSucceeded);
                result.errors.push(DaneFetchError::NoOpenpgpkeyRecord);
                return result;
            }
            Err(LookupError::Bogus) => {
                result
                    .successes
                    .push(DaneFetchSuccess::DnsResolutionSucceeded);
                result.errors.push(DaneFetchError::DnssecValidationFailed);
                return result;
            }
            Err(LookupError::Failed(err)) => {
                #[cfg(feature = "tracing")]
                event!(Level::TRACE, "DNS resolution failed for {}: {}", fqdn, err);

                result.errors.push(DaneFetchError::DnsResolutionFailed(err));
                return result;
            }
        };

        result
            .successes
            .push(DaneFetchSuccess::DnsResolutionSucceeded);

        let records: Vec<&Record> = records
            .iter()
            .filter(|record| matches!(record.data, RData::OPENPGPKEY(_)))
            .collect();

        if records.is_empty() {
            result.errors.push(DaneFetchError::NoOpenpgpkeyRecord);
            return result;
        }

        result
            .successes
            .push(DaneFetchSuccess::OpenpgpkeyRecordFound);

        result.data = records
            .iter()
            .filter_map(|record| match &record.data {
                RData::OPENPGPKEY(key) => Some(key.public_key.clone()),
                _ => None,
            })
            .collect();

        let proofs: Vec<Proof> = records.iter().map(|record| record.proof).collect();
        match dnssec_outcome(&proofs) {
            Ok(success) => result.successes.push(success),
            Err(err) => result.errors.push(err),
        }

        result
    }
}

async fn lookup(fqdn: &str, dns_server: Option<&str>) -> Result<Vec<Record>, LookupError> {
    match dns_server {
        Some(ip) => lookup_forwarder(fqdn, ip).await,
        None => lookup_recursive(fqdn).await,
    }
}

async fn lookup_recursive(fqdn: &str) -> Result<Vec<Record>, LookupError> {
    let recursor = Recursor::new(
        root_servers(),
        DnssecPolicy::ValidateWithStaticKey(DnssecConfig::default()),
        None,
        RecursorOptions::default(),
        TokioRuntimeProvider::default(),
    )
    .map_err(|err| LookupError::Failed(err.to_string()))?;

    let name =
        Name::from_ascii(format!("{fqdn}.")).map_err(|err| LookupError::Failed(err.to_string()))?;

    let message = recursor
        .resolve(
            Query::query(name, RecordType::OPENPGPKEY),
            Instant::now(),
            false,
        )
        .await?;

    Ok(message.answers)
}

async fn lookup_forwarder(fqdn: &str, ip: &str) -> Result<Vec<Record>, LookupError> {
    let addr: IpAddr = ip
        .parse()
        .map_err(|err| LookupError::Failed(format!("invalid DNS_SERVER '{ip}': {err}")))?;
    let config =
        ResolverConfig::from_parts(None, vec![], vec![NameServerConfig::udp_and_tcp(addr)]);
    let mut opts = ResolverOpts::default();
    opts.validate = true;

    let resolver = Resolver::builder_with_config(config, TokioRuntimeProvider::default())
        .with_options(opts)
        .build()
        .map_err(|err| LookupError::Failed(err.to_string()))?;

    let lookup = resolver.lookup(fqdn, RecordType::OPENPGPKEY).await?;

    Ok(lookup.answers().to_vec())
}

fn dnssec_outcome(proofs: &[Proof]) -> Result<DaneFetchSuccess, DaneFetchError> {
    if proofs.contains(&Proof::Bogus) {
        Err(DaneFetchError::DnssecValidationFailed)
    } else if !proofs.is_empty() && proofs.iter().all(Proof::is_secure) {
        Ok(DaneFetchSuccess::DnssecValidationPassed)
    } else {
        Err(DaneFetchError::DnssecNotEnabled)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::dnssec::Proof;
    use std::collections::HashSet;

    fn names(errors: &[DaneFetchError]) -> Vec<String> {
        errors.iter().map(|e| format!("{e:?}")).collect()
    }

    #[test]
    fn dnssec_outcome_all_secure() {
        assert!(matches!(
            dnssec_outcome(&[Proof::Secure, Proof::Secure]),
            Ok(DaneFetchSuccess::DnssecValidationPassed)
        ));
    }

    #[test]
    fn dnssec_outcome_any_bogus() {
        assert!(matches!(
            dnssec_outcome(&[Proof::Secure, Proof::Bogus]),
            Err(DaneFetchError::DnssecValidationFailed)
        ));
    }

    #[test]
    fn dnssec_outcome_insecure() {
        assert!(matches!(
            dnssec_outcome(&[Proof::Insecure]),
            Err(DaneFetchError::DnssecNotEnabled)
        ));
    }

    #[test]
    fn dnssec_outcome_indeterminate() {
        assert!(matches!(
            dnssec_outcome(&[Proof::Indeterminate]),
            Err(DaneFetchError::DnssecNotEnabled)
        ));
    }

    #[test]
    fn dnssec_outcome_empty() {
        assert!(matches!(
            dnssec_outcome(&[]),
            Err(DaneFetchError::DnssecNotEnabled)
        ));
    }

    #[test]
    fn root_servers_from_hints() {
        let roots = root_servers();
        let unique: HashSet<_> = roots.iter().collect();
        assert_eq!(unique.len(), 26);
        assert_eq!(roots.iter().filter(|ip| ip.is_ipv4()).count(), 13);
        assert_eq!(roots.iter().filter(|ip| ip.is_ipv6()).count(), 13);
        assert!(roots.contains(&"198.41.0.4".parse().unwrap()));
        assert!(roots.contains(&"2001:503:ba3e::2:30".parse().unwrap()));
        assert!(roots.contains(&"170.247.170.2".parse().unwrap()));
    }

    #[tokio::test]
    async fn fetch_invalid_dns_server() {
        let name = DaneDnsName::new("alexis.lowe@chimbosonic.com").unwrap();
        let result = DaneFetch::fetch(&name, Some("not-an-ip")).await;
        assert!(result.data.is_empty());
        assert!(matches!(
            result.errors.as_slice(),
            [DaneFetchError::DnsResolutionFailed(_)]
        ));
    }

    async fn assert_secure_single_record(dns_server: Option<&str>) {
        let name = DaneDnsName::new("alexis.lowe@chimbosonic.com").unwrap();
        let result = DaneFetch::fetch(&name, dns_server).await;
        assert!(result.errors.is_empty(), "{:?}", names(&result.errors));
        assert_eq!(result.data.len(), 1);
        assert!(matches!(
            result.successes.as_slice(),
            [
                DaneFetchSuccess::DnsResolutionSucceeded,
                DaneFetchSuccess::OpenpgpkeyRecordFound,
                DaneFetchSuccess::DnssecValidationPassed
            ]
        ));
    }

    #[tokio::test]
    async fn fetch_recursive() {
        assert_secure_single_record(None).await;
    }

    #[tokio::test]
    async fn fetch_forwarder() {
        assert_secure_single_record(Some("1.1.1.1")).await;
    }

    #[tokio::test]
    async fn fetch_recursive_no_record() {
        let name = DaneDnsName::new("nobody-xyz@example.com").unwrap();
        let result = DaneFetch::fetch(&name, None).await;
        assert!(result.data.is_empty());
        assert!(matches!(
            result.successes.as_slice(),
            [DaneFetchSuccess::DnsResolutionSucceeded]
        ));
        assert!(matches!(
            result.errors.as_slice(),
            [DaneFetchError::NoOpenpgpkeyRecord]
        ));
    }

    #[tokio::test]
    async fn fetch_recursive_bogus() {
        let name = DaneDnsName::new("test@dnssec-failed.org").unwrap();
        let result = DaneFetch::fetch(&name, None).await;
        assert!(result.data.is_empty());
        assert!(matches!(
            result.successes.as_slice(),
            [DaneFetchSuccess::DnsResolutionSucceeded]
        ));
        assert!(
            matches!(
                result.errors.as_slice(),
                [DaneFetchError::DnssecValidationFailed]
            ),
            "{:?}",
            names(&result.errors)
        );
    }
}
