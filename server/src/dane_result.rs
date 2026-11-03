use chrono::{DateTime, Utc};
use openpgp_tester_lib::load;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Serialize, Deserialize, ToSchema, Debug, Clone)]
pub struct DaneResult {
    user_id: String,
    dns_name: String,
    keys: Vec<DaneKey>,
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
                keys: vec![],
                errors: vec![DaneError::from(&err)],
                successes: vec![],
                timestamp: Utc::now(),
            };
        }
    };

    let dane_fetch = dane::fetch::DaneFetch::fetch(&dane_dns_name, dns_server).await;

    DaneResult::from(dane_fetch, user_id.to_string(), dane_dns_name.fqdn)
}

impl DaneResult {
    pub fn from(dane_fetch: dane::fetch::DaneFetch, user_id: String, dns_name: String) -> Self {
        let mut errors: Vec<DaneError> = dane_fetch.errors.iter().map(DaneError::from).collect();

        let mut keys: Vec<DaneKey> = Vec::new();
        for record in dane_fetch.data {
            match load::load_keys(record.into()) {
                Ok(record_keys) => {
                    if record_keys.len() > 1 {
                        errors.push(DaneError {
                            name: "MultipleKeysInRecord".to_string(),
                            message: format!(
                                "OPENPGPKEY record contains {} keys; RFC 7929 section 2 requires exactly one key per record",
                                record_keys.len()
                            ),
                        });
                    }
                    keys.extend(record_keys.into_iter().map(DaneKey::from));
                }
                Err(err) => errors.push(DaneError {
                    name: "LoadKeyError".to_string(),
                    message: format!("{err}"),
                }),
            }
        }

        DaneResult {
            user_id,
            dns_name,
            keys,
            errors,
            successes: dane_fetch.successes.iter().map(DaneSuccess::from).collect(),
            timestamp: dane_fetch.timestamp,
        }
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

    fn dane_fetch_with(data: Vec<Vec<u8>>) -> dane::fetch::DaneFetch {
        dane::fetch::DaneFetch {
            data,
            errors: vec![],
            successes: vec![],
            timestamp: Utc::now(),
        }
    }

    #[test]
    fn test_dane_result_from_load_key_error() {
        let dane_fetch = dane_fetch_with(vec![b"invalid_key".to_vec()]);
        let result = DaneResult::from(dane_fetch, "user_id".to_string(), "dns_name".to_string());
        assert!(result.keys.is_empty());
        assert_eq!(result.errors.len(), 1);
        assert_eq!(result.errors[0].name, "LoadKeyError");
        assert_eq!(result.errors[0].message, "Failed to parse key");
    }

    #[test]
    fn test_dane_result_from_multiple_records() {
        let dane_fetch = dane_fetch_with(vec![
            std::fs::read("../test_files/test_key").unwrap(),
            std::fs::read("../test_files/test_expired_key").unwrap(),
        ]);
        let result = DaneResult::from(dane_fetch, "user_id".to_string(), "dns_name".to_string());
        assert!(result.errors.is_empty());
        assert_eq!(result.keys.len(), 2);
        assert_eq!(
            result.keys[0].fingerprint,
            "AC48BC1F029B6188D97E2D807C855DB4466DF0C6"
        );
        assert_eq!(
            result.keys[1].fingerprint,
            "A03351F7677A6D0B94F224A636CB3789EAC25E50"
        );
    }

    #[test]
    fn test_dane_result_from_record_with_multiple_keys() {
        let dane_fetch = dane_fetch_with(vec![
            std::fs::read("../test_files/test_multiple_keys").unwrap(),
        ]);
        let result = DaneResult::from(dane_fetch, "user_id".to_string(), "dns_name".to_string());
        assert_eq!(result.keys.len(), 2);
        assert_eq!(result.errors.len(), 1);
        assert_eq!(result.errors[0].name, "MultipleKeysInRecord");
        assert_eq!(
            result.errors[0].message,
            "OPENPGPKEY record contains 2 keys; RFC 7929 section 2 requires exactly one key per record"
        );
    }

    #[test]
    fn test_dane_result_from_valid_and_invalid_records() {
        let dane_fetch = dane_fetch_with(vec![
            b"invalid_key".to_vec(),
            std::fs::read("../test_files/test_key").unwrap(),
        ]);
        let result = DaneResult::from(dane_fetch, "user_id".to_string(), "dns_name".to_string());
        assert_eq!(result.keys.len(), 1);
        assert_eq!(result.errors.len(), 1);
        assert_eq!(result.errors[0].name, "LoadKeyError");
    }

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
        assert!(dane_result.keys.is_empty());
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
