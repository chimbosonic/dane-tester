use sha2::{Digest, Sha256};
use std::fmt::Display;
use std::fmt::Formatter;

#[cfg(feature = "tracing")]
use tracing::{Level, event};

use miette::Diagnostic;
use thiserror::Error;

#[derive(Error, Diagnostic, Debug, PartialEq)]
pub enum DaneDnsNameError {
    #[error("User ID must be in the format '{{local_part}}@{{domain_part}}'")]
    #[diagnostic(
        code(dane_dns_name::parse_email),
        url("https://datatracker.ietf.org/doc/html/rfc7929#section-3")
    )]
    InvalidEmailError,

    #[error("Invalid domain part")]
    #[diagnostic(code(dane_dns_name::parse_email))]
    InvalidDomainError,
}

/// SHA-256 hash of the local part, truncated to 28 octets, hex-encoded per RFC 7929
#[derive(Debug)]
pub struct EmailHash(String);

impl EmailHash {
    fn new(local_part: &str) -> EmailHash {
        let mut hasher = Sha256::new();
        let local_part = local_part.to_ascii_lowercase();
        hasher.update(local_part);
        let sha256_hash = hasher.finalize();
        let truncated = &sha256_hash[..28];
        let hex_encoded = hex::encode(truncated);
        assert!(hex_encoded.len() == 56);

        EmailHash(hex_encoded)
    }
}

impl Display for EmailHash {
    fn fmt(&self, f: &mut Formatter) -> std::result::Result<(), std::fmt::Error> {
        write!(f, "{}", self.0)
    }
}

fn parse_email(email: &str) -> Result<(String, String), DaneDnsNameError> {
    let parts: Vec<&str> = email.split('@').collect();

    if parts.len() != 2 {
        return Err(DaneDnsNameError::InvalidEmailError);
    }

    let local_part = parts[0].to_string();
    let domain_part = parts[1];

    let domain_part = match url::Host::parse(domain_part) {
        Ok(url::Host::Domain(domain)) => domain,
        _ => return Err(DaneDnsNameError::InvalidDomainError),
    };

    Ok((local_part, domain_part))
}

#[derive(Debug)]
pub struct DaneDnsName {
    /// The domain part of the email address
    pub domain_part: String,
    /// The local part of the email address
    pub local_part: String,
    /// SHA-256 hash of the local part, truncated to 28 octets, hex-encoded
    pub email_hash: EmailHash,
    /// The full DNS name: `<hash>._openpgpkey.<domain>`
    pub fqdn: String,
}

impl DaneDnsName {
    #[cfg_attr(feature = "tracing", tracing::instrument)]
    pub fn new(user_id: &str) -> Result<DaneDnsName, DaneDnsNameError> {
        let (local_part, domain_part) = parse_email(user_id)?;
        #[cfg(feature = "tracing")]
        event!(
            Level::TRACE,
            "Parsed email: local_part={}, domain_part={}",
            local_part,
            domain_part
        );
        let email_hash = EmailHash::new(&local_part);
        #[cfg(feature = "tracing")]
        event!(
            Level::TRACE,
            "Generated EmailHash for local_part: {:?}",
            email_hash
        );

        let fqdn = format!("{}._openpgpkey.{}", email_hash, domain_part);
        #[cfg(feature = "tracing")]
        event!(Level::TRACE, "Generated FQDN: {}", fqdn);

        Ok(DaneDnsName {
            domain_part: domain_part.to_string(),
            local_part: local_part.to_string(),
            email_hash,
            fqdn,
        })
    }
}

impl Display for DaneDnsName {
    fn fmt(&self, f: &mut Formatter) -> std::result::Result<(), std::fmt::Error> {
        write!(f, "{}", self.fqdn)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DOMAIN_PART: &str = "example.com";
    const LOCAL_PART: &str = "hugh";

    #[test]
    fn email_hash_new() {
        let test_hash = EmailHash::new(LOCAL_PART);
        assert_eq!(test_hash.to_string().len(), 56);
        assert_eq!(
            test_hash.to_string(),
            "c93f1e400f26708f98cb19d936620da35eec8f72e57f9eec01c1afd6"
        );
    }

    #[test]
    fn dane_dns_name_new() {
        let test_dane_dns_name = DaneDnsName::new(&format!("{LOCAL_PART}@{DOMAIN_PART}"));
        assert!(test_dane_dns_name.is_ok());
        let test_dane_dns_name = test_dane_dns_name.unwrap();

        assert_eq!(test_dane_dns_name.domain_part, DOMAIN_PART);
        assert_eq!(test_dane_dns_name.local_part, LOCAL_PART);
        assert_eq!(
            test_dane_dns_name.fqdn,
            "c93f1e400f26708f98cb19d936620da35eec8f72e57f9eec01c1afd6._openpgpkey.example.com"
        );
    }

    #[test]
    fn dane_dns_name_case_insensitive() {
        let lower = DaneDnsName::new("Hugh@example.com").unwrap();
        let upper = DaneDnsName::new("HUGH@example.com").unwrap();
        assert_eq!(lower.email_hash.to_string(), upper.email_hash.to_string());
    }

    #[test]
    fn parse_email_ok() {
        let test_email = "test@example.org";
        let (local_part, domain_part) = parse_email(test_email).unwrap();
        assert_eq!(local_part, "test");
        assert_eq!(domain_part, "example.org");
    }

    #[test]
    fn parse_email_err() {
        let test_email = "test";
        let result = parse_email(test_email);
        assert!(result.is_err());
    }

    #[test]
    fn parse_email_err_invalid_domain() {
        let test_email = "test@localhost:3000/blah";
        let result = parse_email(test_email);
        assert!(result.is_err());
    }

    #[test]
    fn dane_dns_name_new_invalid_email() {
        let test_dane_dns_name = DaneDnsName::new("test");
        assert!(test_dane_dns_name.is_err());
        assert_eq!(
            test_dane_dns_name.unwrap_err(),
            DaneDnsNameError::InvalidEmailError
        );
    }
}
