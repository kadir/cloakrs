//! United Kingdom locale recognizers.

use crate::common::{
    alphanumeric_upper, compile_regex, confidence, context_boost, digits, is_boundary,
};
use cloakrs_core::{Confidence, EntityType, Locale, PiiEntity, Recognizer, Span};
use once_cell::sync::Lazy;
use regex::Regex;

static NINO_REGEX: Lazy<Regex> =
    Lazy::new(|| compile_regex(r"(?i)\b[a-z]{2}\s?\d{2}\s?\d{2}\s?\d{2}\s?[a-d]\b"));
static NHS_NUMBER_REGEX: Lazy<Regex> =
    Lazy::new(|| compile_regex(r"\b\d{3}[ -]?\d{3}[ -]?\d{4}\b"));
static UK_LOCALES: &[Locale] = &[Locale::UK];

const NINO_CONTEXT_WORDS: &[&str] = &["national insurance", "ni number", "nino"];
const NHS_CONTEXT_WORDS: &[&str] = &["nhs number"];

/// Recognizes UK National Insurance numbers (NINO).
///
/// # Examples
///
/// ```
/// use cloakrs_core::Recognizer;
/// use cloakrs_locales::NinoRecognizer;
///
/// let findings = NinoRecognizer.scan("national insurance AB 12 34 56 C");
/// assert_eq!(findings.len(), 1);
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct NinoRecognizer;

impl Recognizer for NinoRecognizer {
    fn id(&self) -> &str {
        "uk_nino_regex_v1"
    }

    fn entity_type(&self) -> EntityType {
        EntityType::Nino
    }

    fn supported_locales(&self) -> &[Locale] {
        UK_LOCALES
    }

    fn scan(&self, text: &str) -> Vec<PiiEntity> {
        NINO_REGEX
            .find_iter(text)
            .filter(|matched| self.is_valid_match(text, matched.start(), matched.end()))
            .map(|matched| PiiEntity {
                entity_type: self.entity_type(),
                span: Span::new(matched.start(), matched.end()),
                text: matched.as_str().to_string(),
                confidence: compute_nino_confidence(text, matched.start(), matched.end()),
                recognizer_id: self.id().to_string(),
            })
            .collect()
    }

    fn validate(&self, candidate: &str) -> bool {
        nino_valid(candidate)
    }
}

impl NinoRecognizer {
    fn is_valid_match(&self, text: &str, start: usize, end: usize) -> bool {
        self.validate(&text[start..end]) && is_boundary(text, start, end)
    }
}

/// Recognizes UK NHS numbers with Modulus 11 validation.
///
/// # Examples
///
/// ```
/// use cloakrs_core::Recognizer;
/// use cloakrs_locales::NhsNumberRecognizer;
///
/// let findings = NhsNumberRecognizer.scan("NHS number 943 476 5919");
/// assert_eq!(findings.len(), 1);
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct NhsNumberRecognizer;

impl Recognizer for NhsNumberRecognizer {
    fn id(&self) -> &str {
        "uk_nhs_number_mod11_v1"
    }

    fn entity_type(&self) -> EntityType {
        EntityType::NhsNumber
    }

    fn supported_locales(&self) -> &[Locale] {
        UK_LOCALES
    }

    fn scan(&self, text: &str) -> Vec<PiiEntity> {
        NHS_NUMBER_REGEX
            .find_iter(text)
            .filter(|matched| self.is_valid_match(text, matched.start(), matched.end()))
            .map(|matched| PiiEntity {
                entity_type: self.entity_type(),
                span: Span::new(matched.start(), matched.end()),
                text: matched.as_str().to_string(),
                confidence: compute_nhs_confidence(text, matched.start(), matched.end()),
                recognizer_id: self.id().to_string(),
            })
            .collect()
    }

    fn validate(&self, candidate: &str) -> bool {
        let digits = digits(candidate);
        digits.len() == 10 && nhs_mod11_valid(&digits)
    }
}

impl NhsNumberRecognizer {
    fn is_valid_match(&self, text: &str, start: usize, end: usize) -> bool {
        self.validate(&text[start..end]) && is_boundary(text, start, end)
    }
}

fn compute_nino_confidence(text: &str, start: usize, end: usize) -> Confidence {
    confidence(0.75 + context_boost(text, Span::new(start, end), NINO_CONTEXT_WORDS))
}

fn compute_nhs_confidence(text: &str, start: usize, end: usize) -> Confidence {
    confidence(0.70 + context_boost(text, Span::new(start, end), NHS_CONTEXT_WORDS))
}

fn nino_valid(candidate: &str) -> bool {
    let normalized = alphanumeric_upper(candidate);
    if normalized.len() != 9 {
        return false;
    }

    let bytes = normalized.as_bytes();
    let first = bytes[0];
    let second = bytes[1];
    first.is_ascii_uppercase()
        && second.is_ascii_uppercase()
        && nino_prefix_letters_valid(first, second)
        && bytes[2..8].iter().all(u8::is_ascii_digit)
        && matches!(bytes[8], b'A' | b'B' | b'C' | b'D')
}

fn nino_prefix_letters_valid(first: u8, second: u8) -> bool {
    !matches!(first, b'D' | b'F' | b'I' | b'Q' | b'U' | b'V')
        && !matches!(second, b'D' | b'F' | b'I' | b'O' | b'Q' | b'U' | b'V')
        && !matches!(
            (first, second),
            (b'B', b'G')
                | (b'G', b'B')
                | (b'K', b'N')
                | (b'N', b'K')
                | (b'N', b'T')
                | (b'T', b'N')
                | (b'Z', b'Z')
        )
}

fn nhs_mod11_valid(digits: &str) -> bool {
    let bytes = digits.as_bytes();
    let total: u32 = bytes
        .iter()
        .take(9)
        .enumerate()
        .map(|(index, byte)| u32::from(byte - b'0') * (10 - index as u32))
        .sum();
    let check = 11 - (total % 11);
    let expected = match check {
        11 => 0,
        10 => return false,
        value => value,
    };
    expected == u32::from(bytes[9] - b'0')
}

#[cfg(test)]
mod tests {
    use super::*;
    use cloakrs_core::RecognizerRegistry;

    fn nino_texts(input: &str) -> Vec<String> {
        NinoRecognizer
            .scan(input)
            .into_iter()
            .map(|finding| finding.text)
            .collect()
    }

    fn nhs_texts(input: &str) -> Vec<String> {
        NhsNumberRecognizer
            .scan(input)
            .into_iter()
            .map(|finding| finding.text)
            .collect()
    }

    #[test]
    fn test_nino_spaced_format_detected() {
        assert_eq!(
            nino_texts("national insurance AB 12 34 56 C"),
            ["AB 12 34 56 C"]
        );
    }

    #[test]
    fn test_nino_compact_format_detected() {
        assert_eq!(nino_texts("NINO AB123456C"), ["AB123456C"]);
    }

    #[test]
    fn test_nino_lowercase_format_detected() {
        assert_eq!(nino_texts("ni number ab 12 34 56 d"), ["ab 12 34 56 d"]);
    }

    #[test]
    fn test_nino_first_letter_o_detected() {
        assert_eq!(nino_texts("NINO ON 12 34 56 A"), ["ON 12 34 56 A"]);
    }

    #[test]
    fn test_nino_multiple_values_detected() {
        assert_eq!(
            nino_texts("NINO AB 12 34 56 C and JY 98 76 54 D"),
            ["AB 12 34 56 C", "JY 98 76 54 D"]
        );
    }

    #[test]
    fn test_nino_prefix_bg_rejected() {
        assert!(nino_texts("NINO BG 12 34 56 C").is_empty());
    }

    #[test]
    fn test_nino_prefix_gb_rejected() {
        assert!(nino_texts("NINO GB 12 34 56 C").is_empty());
    }

    #[test]
    fn test_nino_prefix_kn_rejected() {
        assert!(nino_texts("NINO KN 12 34 56 C").is_empty());
    }

    #[test]
    fn test_nino_prefix_nk_rejected() {
        assert!(nino_texts("NINO NK 12 34 56 C").is_empty());
    }

    #[test]
    fn test_nino_prefix_nt_rejected() {
        assert!(nino_texts("NINO NT 12 34 56 C").is_empty());
    }

    #[test]
    fn test_nino_prefix_tn_rejected() {
        assert!(nino_texts("NINO TN 12 34 56 C").is_empty());
    }

    #[test]
    fn test_nino_prefix_zz_rejected() {
        assert!(nino_texts("NINO ZZ 12 34 56 C").is_empty());
    }

    #[test]
    fn test_nino_forbidden_prefix_letter_rejected() {
        assert!(nino_texts("NINO DA 12 34 56 C").is_empty());
    }

    #[test]
    fn test_nino_second_letter_o_rejected() {
        assert!(nino_texts("NINO AO 12 34 56 C").is_empty());
    }

    #[test]
    fn test_nino_invalid_suffix_rejected() {
        assert!(nino_texts("NINO AB 12 34 56 E").is_empty());
    }

    #[test]
    fn test_nino_too_few_digits_rejected() {
        assert!(nino_texts("NINO AB 12 34 5 C").is_empty());
    }

    #[test]
    fn test_nino_embedded_in_word_rejected() {
        assert!(nino_texts("idAB123456C").is_empty());
    }

    #[test]
    fn test_nino_trailing_word_rejected() {
        assert!(nino_texts("AB123456Code").is_empty());
    }

    #[test]
    fn test_nino_national_insurance_context_boosts_confidence() {
        let with_context = NinoRecognizer.scan("national insurance AB 12 34 56 C");
        let without_context = NinoRecognizer.scan("value AB 12 34 56 C");
        assert!(with_context[0].confidence > without_context[0].confidence);
    }

    #[test]
    fn test_nino_ni_number_context_after_boosts_confidence() {
        let with_context = NinoRecognizer.scan("AB 12 34 56 C NI number");
        let without_context = NinoRecognizer.scan("AB 12 34 56 C value");
        assert!(with_context[0].confidence > without_context[0].confidence);
    }

    #[test]
    fn test_nino_supported_locale_is_uk() {
        assert_eq!(NinoRecognizer.supported_locales(), &[Locale::UK]);
    }

    #[test]
    fn test_nhs_compact_format_detected() {
        assert_eq!(nhs_texts("NHS number 9434765919"), ["9434765919"]);
    }

    #[test]
    fn test_nhs_spaced_format_detected() {
        assert_eq!(nhs_texts("NHS number 943 476 5919"), ["943 476 5919"]);
    }

    #[test]
    fn test_nhs_hyphenated_format_detected() {
        assert_eq!(nhs_texts("NHS number 943-476-5919"), ["943-476-5919"]);
    }

    #[test]
    fn test_nhs_second_valid_example_detected() {
        assert_eq!(nhs_texts("NHS number 4010232137"), ["4010232137"]);
    }

    #[test]
    fn test_nhs_multiple_values_detected() {
        assert_eq!(
            nhs_texts("NHS number 4857773457 and 9876543210 NHS number"),
            ["4857773457", "9876543210"]
        );
    }

    #[test]
    fn test_nhs_invalid_checksum_rejected() {
        assert!(nhs_texts("NHS number 9434765910").is_empty());
    }

    #[test]
    fn test_nhs_check_digit_ten_rejected() {
        assert!(nhs_texts("NHS number 1234567890").is_empty());
    }

    #[test]
    fn test_nhs_too_short_rejected() {
        assert!(nhs_texts("NHS number 943476591").is_empty());
    }

    #[test]
    fn test_nhs_too_long_rejected() {
        assert!(nhs_texts("NHS number 94347659190").is_empty());
    }

    #[test]
    fn test_nhs_letters_rejected() {
        assert!(nhs_texts("NHS number 943476591A").is_empty());
    }

    #[test]
    fn test_nhs_embedded_in_word_rejected() {
        assert!(nhs_texts("id9434765919").is_empty());
    }

    #[test]
    fn test_nhs_trailing_word_rejected() {
        assert!(nhs_texts("9434765919id").is_empty());
    }

    #[test]
    fn test_nhs_context_before_boosts_confidence() {
        let with_context = NhsNumberRecognizer.scan("NHS number 9434765919");
        let without_context = NhsNumberRecognizer.scan("value 9434765919");
        assert!(with_context[0].confidence > without_context[0].confidence);
    }

    #[test]
    fn test_nhs_context_after_boosts_confidence() {
        let with_context = NhsNumberRecognizer.scan("9434765919 NHS number");
        let without_context = NhsNumberRecognizer.scan("9434765919 value");
        assert!(with_context[0].confidence > without_context[0].confidence);
    }

    #[test]
    fn test_nhs_supported_locale_is_uk() {
        assert_eq!(NhsNumberRecognizer.supported_locales(), &[Locale::UK]);
    }

    #[test]
    fn test_uk_registry_with_uk_locale_detects_both_entities() {
        let mut registry = RecognizerRegistry::new();
        registry.register(NinoRecognizer);
        registry.register(NhsNumberRecognizer);
        let findings = registry.scan_locale(
            "national insurance AB 12 34 56 C and NHS number 9434765919",
            &Locale::UK,
        );
        assert_eq!(findings.len(), 2);
        assert_eq!(
            registry
                .scan_locale(
                    "NINO AB 12 34 56 C NHS number 9434765919",
                    &Locale::Universal
                )
                .len(),
            0
        );
    }
}
