use chrono::{DateTime, Utc};
use openpgp_tester_lib::load;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Serialize, Deserialize, ToSchema, Debug, Clone)]
pub struct DaneResult {
    user_id: String,
    dns_name: String,
    key: Option<DaneKey>,
    errors: Vec<DaneError>,
    successes: Vec<DaneSuccess>,
    #[schema(value_type = String)]
    timestamp: DateTime<Utc>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, ToSchema, Clone)]
pub struct DaneSuccess(String);

use dane::fetch::DaneFetchSuccess;

impl From<&str> for DaneSuccess {
    fn from(value: &str) -> Self {
        DaneSuccess(value.to_string())
    }
}

impl From<&DaneFetchSuccess> for DaneSuccess {
    fn from(value: &DaneFetchSuccess) -> Self {
        match value {
            DaneFetchSuccess::DnsResolutionSucceeded => {
                DaneSuccess::from("DNS Resolution Succeeded")
            }
            DaneFetchSuccess::DnssecValidationPassed => {
                DaneSuccess::from("DNSSEC Validation Passed")
            }
            DaneFetchSuccess::OpenpgpkeyRecordFound => DaneSuccess::from("OPENPGPKEY Record Found"),
        }
    }
}

#[derive(Serialize, Deserialize, ToSchema, Debug, Clone)]
pub struct DaneError {
    name: String,
    message: String,
}

#[derive(Serialize, Deserialize, ToSchema, Debug, Clone)]
pub struct DaneKey {
    fingerprint: String,
    revocation_status: String,
    expiry: String,
    algorithm: String,
    randomart: String,
}

#[cfg(feature = "dane-cache")]
pub async fn get_dane_cached(
    email: &String,
    cache: &actix_web::web::Data<crate::WebCache>,
    dns_server: Option<&str>,
) -> (DaneResult, Option<impl Future<Output = ()>>) {
    match cache.get(email).await {
        Some(result) => (result, None),
        None => {
            let res = get_dane(email, dns_server).await;
            let cache_set_future = cache.set(email.to_string(), res.clone());
            (res, Some(cache_set_future))
        }
    }
}

#[cfg(feature = "dane-cache")]
pub async fn unwrap_cache_future(cache_set_future: Option<impl Future<Output = ()>>) {
    if let Some(fut) = cache_set_future {
        fut.await
    }
}

pub async fn get_dane(user_id: &str, dns_server: Option<&str>) -> DaneResult {
    let dane_dns_name = match dane::dns_name::DaneDnsName::new(user_id) {
        Ok(dns_name) => dns_name,
        Err(err) => {
            return DaneResult {
                user_id: user_id.to_string(),
                dns_name: "".to_string(),
                key: None,
                errors: vec![DaneError::from(&err)],
                successes: vec![],
                timestamp: Utc::now(),
            };
        }
    };

    let dane_fetch = dane::fetch::DaneFetch::fetch(&dane_dns_name, dns_server).await;

    let key: Option<DaneKey> = match dane_fetch.data {
        Some(ref data) => load::load_key(data.clone().into()).ok().map(DaneKey::from),
        None => None,
    };

    DaneResult {
        user_id: user_id.to_string(),
        dns_name: dane_dns_name.fqdn,
        key,
        errors: dane_fetch.errors.iter().map(DaneError::from).collect(),
        successes: dane_fetch.successes.iter().map(DaneSuccess::from).collect(),
        timestamp: dane_fetch.timestamp,
    }
}

impl DaneError {
    pub fn from<Error: std::error::Error>(error: Error) -> Self {
        DaneError {
            name: format!("{error:?}"),
            message: format!("{error}"),
        }
    }
}

impl DaneKey {
    pub fn from(dane_key: load::Key) -> Self {
        DaneKey {
            fingerprint: dane_key.fingerprint,
            revocation_status: dane_key.revocation_status,
            expiry: dane_key.expiry,
            algorithm: dane_key.algorithm,
            randomart: dane_key.randomart,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dane_key_from() {
        let dane_key = load::Key {
            fingerprint: "fingerprint".to_string(),
            revocation_status: "revocation_status".to_string(),
            expiry: "expiry".to_string(),
            algorithm: "algorithm".to_string(),
            randomart: "randomart".to_string(),
        };
        let key = DaneKey::from(dane_key);
        assert_eq!(key.fingerprint, "fingerprint");
        assert_eq!(key.revocation_status, "revocation_status");
        assert_eq!(key.expiry, "expiry");
        assert_eq!(key.algorithm, "algorithm");
        assert_eq!(key.randomart, "randomart");
    }

    #[test]
    fn test_dane_error_from() {
        let error = dane::fetch::DaneFetchError::NoOpenpgpkeyRecord;
        let dane_error = DaneError::from(error);
        assert_eq!(dane_error.name, "NoOpenpgpkeyRecord");
        assert_eq!(dane_error.message, "No OPENPGPKEY (TYPE 61) records found");
    }

    #[tokio::test]
    async fn test_get_dane_invalid_email() {
        let dane_result = get_dane("something", None).await;
        assert_eq!(dane_result.user_id, "something");
        assert_eq!(dane_result.dns_name, "");
        assert!(dane_result.key.is_none());
        assert!(!dane_result.errors.is_empty());
    }

    #[tokio::test]
    async fn test_get_dane() {
        let dane_result = get_dane("test@example.com", None).await;
        println!("{:#?}", dane_result);
        assert_eq!(dane_result.user_id, "test@example.com");
        assert!(!dane_result.dns_name.is_empty());
        assert!(dane_result.dns_name.contains("._openpgpkey.example.com"));
    }
}
