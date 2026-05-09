//! Locale-specific recognizer bundles for cloakrs.
//!
//! Country-specific recognizers such as US SSN, Dutch BSN, and UK NINO.
//!
//! # Examples
//!
//! ```
//! use cloakrs_core::{EntityType, Locale};
//!
//! let scanner = cloakrs_locales::default_registry()
//!     .into_scanner_builder()
//!     .locale(Locale::EU)
//!     .without_masking()
//!     .build()
//!     .unwrap();
//! let result = scanner.scan("BSN 123456782").unwrap();
//! assert!(result.findings.iter().any(|finding| finding.entity_type == EntityType::Bsn));
//! ```

mod br_br;
mod common;
mod de_de;
mod en_gb;
mod eu;
mod fr_fr;
mod in_in;
mod nl_nl;

pub use br_br::{CnpjRecognizer, CpfRecognizer};
pub use de_de::SteuerIdRecognizer;
pub use en_gb::{NhsNumberRecognizer, NinoRecognizer};
pub use fr_fr::InseeNirRecognizer;
pub use in_in::{AadhaarRecognizer, PanRecognizer};
pub use nl_nl::BsnRecognizer;

use cloakrs_core::RecognizerRegistry;

/// Returns the crate version.
#[must_use]
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Builds a registry containing universal recognizers plus locale-specific recognizers.
///
/// # Examples
///
/// ```
/// let registry = cloakrs_locales::default_registry();
/// assert!(!registry.is_empty());
/// ```
#[must_use]
pub fn default_registry() -> RecognizerRegistry {
    let mut registry = cloakrs_patterns::default_registry();
    register_locale_recognizers(&mut registry);
    registry
}

/// Registers locale-specific recognizers into an existing registry.
///
/// # Examples
///
/// ```
/// let mut registry = cloakrs_patterns::default_registry();
/// cloakrs_locales::register_locale_recognizers(&mut registry);
/// assert!(!registry.is_empty());
/// ```
pub fn register_locale_recognizers(registry: &mut RecognizerRegistry) {
    registry.register(BsnRecognizer);
    registry.register(SteuerIdRecognizer);
    registry.register(AadhaarRecognizer);
    registry.register(PanRecognizer);
    registry.register(CpfRecognizer);
    registry.register(CnpjRecognizer);
    registry.register(InseeNirRecognizer);
    registry.register(NinoRecognizer);
    registry.register(NhsNumberRecognizer);
}
