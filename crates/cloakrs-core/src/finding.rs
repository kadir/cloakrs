//! Detection result types.

use crate::{CloakError, Result};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};

/// A detected PII entity within text.
///
/// # Examples
///
/// ```
/// use cloakrs_core::{Confidence, EntityType, PiiEntity, Span};
///
/// let entity = PiiEntity {
///     entity_type: EntityType::Email,
///     span: Span::new(11, 27),
///     text: "user@example.com".to_string(),
///     confidence: Confidence::new(0.95).unwrap(),
///     recognizer_id: "email_regex_v1".to_string(),
/// };
///
/// assert_eq!(entity.span.len(), 16);
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PiiEntity {
    /// The type of PII detected.
    pub entity_type: EntityType,
    /// Byte offset range in the source text, using `[start, end)`.
    pub span: Span,
    /// The matched value.
    pub text: String,
    /// Confidence score from `0.0` to `1.0`.
    pub confidence: Confidence,
    /// Identifier of the recognizer that produced this finding.
    pub recognizer_id: String,
}

/// Byte offset range in source text, using `[start, end)`.
///
/// # Examples
///
/// ```
/// use cloakrs_core::Span;
///
/// let span = Span::new(3, 8);
/// assert_eq!(span.len(), 5);
/// assert!(!span.is_empty());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Span {
    /// Inclusive start byte offset.
    pub start: usize,
    /// Exclusive end byte offset.
    pub end: usize,
}

impl Span {
    /// Creates a new span.
    #[must_use]
    pub const fn new(start: usize, end: usize) -> Self {
        Self { start, end }
    }

    /// Returns the span length in bytes.
    #[must_use]
    pub const fn len(self) -> usize {
        self.end.saturating_sub(self.start)
    }

    /// Returns `true` when this span contains no bytes.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.start >= self.end
    }

    /// Returns `true` if the two spans overlap.
    #[must_use]
    pub const fn overlaps(self, other: Self) -> bool {
        self.start < other.end && other.start < self.end
    }
}

/// Confidence score wrapper guaranteed to contain a value from `0.0` to `1.0`.
///
/// # Examples
///
/// ```
/// use cloakrs_core::Confidence;
///
/// let confidence = Confidence::new(0.8).unwrap();
/// assert_eq!(confidence.value(), 0.8);
/// ```
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Confidence(f64);

impl Confidence {
    /// The lowest possible confidence value.
    pub const ZERO: Self = Self(0.0);

    /// The highest possible confidence value.
    pub const ONE: Self = Self(1.0);

    /// Creates a confidence score if the value is finite and within `0.0..=1.0`.
    pub fn new(value: f64) -> Result<Self> {
        if value.is_finite() && (0.0..=1.0).contains(&value) {
            Ok(Self(value))
        } else {
            Err(CloakError::InvalidConfidence(value))
        }
    }

    /// Returns the wrapped numeric value.
    #[must_use]
    pub const fn value(self) -> f64 {
        self.0
    }
}

impl Default for Confidence {
    fn default() -> Self {
        Self::ONE
    }
}

impl fmt::Display for Confidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:.3}", self.0)
    }
}

impl PartialEq for Confidence {
    fn eq(&self, other: &Self) -> bool {
        self.0.to_bits() == other.0.to_bits()
    }
}

impl Eq for Confidence {}

impl PartialOrd for Confidence {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Confidence {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.total_cmp(&other.0)
    }
}

impl Hash for Confidence {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.to_bits().hash(state);
    }
}

/// All supported PII entity types.
///
/// # Examples
///
/// ```
/// use cloakrs_core::EntityType;
///
/// assert_eq!(EntityType::Email.redaction_tag(), "[EMAIL]");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EntityType {
    /// Email address.
    Email,
    /// Phone number.
    PhoneNumber,
    /// Payment card number.
    CreditCard,
    /// International Bank Account Number.
    Iban,
    /// IP address.
    IpAddress,
    /// URL.
    Url,
    /// Date of birth.
    DateOfBirth,
    /// Generic API key.
    ApiKey,
    /// JSON Web Token.
    Jwt,
    /// AWS access key.
    AwsAccessKey,
    /// Cryptocurrency wallet address.
    CryptoAddress,
    /// MAC address.
    MacAddress,
    /// Passport number.
    PassportNumber,
    /// Driver's license number.
    DriversLicense,
    /// United States Social Security Number.
    Ssn,
    /// Dutch Burgerservicenummer.
    Bsn,
    /// UK National Insurance number.
    Nino,
    /// UK NHS number.
    NhsNumber,
    /// Indian Aadhaar number.
    Aadhaar,
    /// Indian PAN card number.
    Pan,
    /// Brazilian CPF.
    Cpf,
    /// Brazilian CNPJ.
    Cnpj,
    /// German tax identifier.
    SteuerID,
    /// French INSEE/NIR number.
    InseeNir,
    /// User-defined entity type.
    Custom(String),
}

impl EntityType {
    /// Returns the redaction tag for this entity type.
    #[must_use]
    pub fn redaction_tag(&self) -> String {
        match self {
            Self::Email => "[EMAIL]".to_string(),
            Self::PhoneNumber => "[PHONE]".to_string(),
            Self::CreditCard => "[CREDIT_CARD]".to_string(),
            Self::Iban => "[IBAN]".to_string(),
            Self::IpAddress => "[IP_ADDRESS]".to_string(),
            Self::Url => "[URL]".to_string(),
            Self::DateOfBirth => "[DOB]".to_string(),
            Self::ApiKey => "[API_KEY]".to_string(),
            Self::Jwt => "[JWT]".to_string(),
            Self::AwsAccessKey => "[AWS_KEY]".to_string(),
            Self::CryptoAddress => "[CRYPTO_ADDR]".to_string(),
            Self::MacAddress => "[MAC_ADDR]".to_string(),
            Self::PassportNumber => "[PASSPORT]".to_string(),
            Self::DriversLicense => "[DRIVERS_LICENSE]".to_string(),
            Self::Ssn => "[SSN]".to_string(),
            Self::Bsn => "[BSN]".to_string(),
            Self::Nino => "[NINO]".to_string(),
            Self::NhsNumber => "[NHS_NUMBER]".to_string(),
            Self::Aadhaar => "[AADHAAR]".to_string(),
            Self::Pan => "[PAN]".to_string(),
            Self::Cpf => "[CPF]".to_string(),
            Self::Cnpj => "[CNPJ]".to_string(),
            Self::SteuerID => "[STEUER_ID]".to_string(),
            Self::InseeNir => "[INSEE_NIR]".to_string(),
            Self::Custom(name) => format!("[{}]", upper_snake(name)),
        }
    }
}

fn upper_snake(value: &str) -> String {
    value
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect()
}

/// Locale selector used to choose locale-specific recognizers.
///
/// # Examples
///
/// ```
/// use cloakrs_core::Locale;
///
/// assert!(Locale::US.matches(Locale::Universal));
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Locale {
    /// Universal recognizers that apply to all locales.
    Universal,
    /// United States.
    US,
    /// Netherlands.
    NL,
    /// United Kingdom.
    UK,
    /// Germany.
    DE,
    /// France.
    FR,
    /// India.
    IN,
    /// Brazil.
    BR,
    /// European Union meta-locale.
    EU,
    /// Custom BCP-47-like locale string.
    Custom(String),
}

impl Locale {
    /// Returns true if `candidate` is universal or equals this locale.
    #[must_use]
    pub fn matches(&self, candidate: Self) -> bool {
        candidate == Self::Universal || self == &candidate
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_confidence_new_valid_value_constructs() {
        let confidence = Confidence::new(0.75).unwrap();
        assert_eq!(confidence.value(), 0.75);
    }

    #[test]
    fn test_confidence_new_above_one_rejects() {
        assert!(Confidence::new(1.1).is_err());
    }

    #[test]
    fn test_confidence_new_nan_rejects() {
        assert!(Confidence::new(f64::NAN).is_err());
    }

    #[test]
    fn test_confidence_ordering_sorts_low_to_high() {
        let low = Confidence::new(0.2).unwrap();
        let high = Confidence::new(0.9).unwrap();
        assert!(low < high);
    }

    #[test]
    fn test_span_len_with_ordered_offsets_returns_difference() {
        assert_eq!(Span::new(4, 10).len(), 6);
    }

    #[test]
    fn test_span_overlaps_when_ranges_intersect() {
        assert!(Span::new(4, 10).overlaps(Span::new(8, 12)));
    }

    #[test]
    fn test_entity_type_redaction_tag_for_custom_uppercases_name() {
        assert_eq!(
            EntityType::Custom("customer id".to_string()).redaction_tag(),
            "[CUSTOMER_ID]"
        );
    }

    #[test]
    fn test_pii_entity_serializes_to_json() {
        let entity = PiiEntity {
            entity_type: EntityType::Email,
            span: Span::new(0, 16),
            text: "user@example.com".to_string(),
            confidence: Confidence::new(0.95).unwrap(),
            recognizer_id: "email_regex_v1".to_string(),
        };

        let json = serde_json::to_string(&entity).unwrap();
        assert!(json.contains("user@example.com"));
    }
}
