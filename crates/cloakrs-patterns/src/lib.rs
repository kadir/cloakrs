//! Universal PII recognizers for cloakrs.
//!
//! This crate provides recognizers for email, phone, credit cards, IBAN, IP
//! addresses, URLs, secrets, MAC addresses, hostnames, user home paths, crypto
//! wallet addresses, and dates of birth.
//!
//! # Examples
//!
//! ```
//! use cloakrs_core::EntityType;
//!
//! let findings = cloakrs_patterns::default_registry().scan_all("email jane@example.com");
//! assert!(findings.iter().any(|finding| finding.entity_type == EntityType::Email));
//! ```

mod api_key;
mod common;
mod credit_card;
mod crypto;
mod date_of_birth;
mod email;
mod hostname;
mod iban;
mod ip_address;
mod mac_address;
mod person_name;
mod phone;
mod physical_address;
mod ssn;
mod url;
mod user_path;

pub use api_key::{ApiKeyRecognizer, AwsAccessKeyRecognizer, JwtRecognizer};
pub use credit_card::{card_brand, luhn_valid, CardBrand, CreditCardRecognizer};
pub use crypto::CryptoAddressRecognizer;
pub use date_of_birth::DateOfBirthRecognizer;
pub use email::EmailRecognizer;
pub use hostname::HostnameRecognizer;
pub use iban::{iban_country_length, iban_mod97_valid, IbanRecognizer};
pub use ip_address::IpAddressRecognizer;
pub use mac_address::MacAddressRecognizer;
pub use person_name::PersonNameRecognizer;
pub use phone::PhoneRecognizer;
pub use physical_address::PhysicalAddressRecognizer;
pub use ssn::SsnRecognizer;
pub use url::UrlRecognizer;
pub use user_path::UserPathRecognizer;

use cloakrs_core::RecognizerRegistry;

/// Returns the crate version.
#[must_use]
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Builds a registry containing the Sprint 2 universal recognizers.
///
/// # Examples
///
/// ```
/// let registry = cloakrs_patterns::default_registry();
/// assert!(!registry.is_empty());
/// ```
#[must_use]
pub fn default_registry() -> RecognizerRegistry {
    let mut registry = RecognizerRegistry::new();
    register_default_recognizers(&mut registry);
    registry
}

/// Registers the Sprint 2 recognizers into an existing registry.
pub fn register_default_recognizers(registry: &mut RecognizerRegistry) {
    registry.register(EmailRecognizer);
    registry.register(PhoneRecognizer);
    registry.register(CreditCardRecognizer);
    registry.register(IbanRecognizer);
    registry.register(IpAddressRecognizer);
    registry.register(UrlRecognizer);
    registry.register(HostnameRecognizer);
    registry.register(UserPathRecognizer);
    registry.register(PersonNameRecognizer);
    registry.register(PhysicalAddressRecognizer);
    registry.register(AwsAccessKeyRecognizer);
    registry.register(JwtRecognizer);
    registry.register(ApiKeyRecognizer);
    registry.register(MacAddressRecognizer);
    registry.register(CryptoAddressRecognizer);
    registry.register(DateOfBirthRecognizer);
    registry.register(url::UrlQueryEmailRecognizer);
    registry.register(url::UrlQuerySsnRecognizer);
    registry.register(SsnRecognizer);
}
