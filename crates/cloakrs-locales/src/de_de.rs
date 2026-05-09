//! German locale recognizers.

use crate::common::{compile_regex, confidence, context_boost, digits, is_boundary};
use crate::eu::DE_AND_EU_LOCALES;
use cloakrs_core::{Confidence, EntityType, Locale, PiiEntity, Recognizer, Span};
use once_cell::sync::Lazy;
use regex::Regex;

static STEUER_ID_REGEX: Lazy<Regex> = Lazy::new(|| compile_regex(r"\b\d{11}\b"));
const CONTEXT_WORDS: &[&str] = &[
    "steuer-id",
    "steuer id",
    "steuerid",
    "steueridentifikationsnummer",
    "steuerliche identifikationsnummer",
    "identifikationsnummer",
    "idnr",
    "tax id",
];

/// Recognizes German Steuer-ID / Identifikationsnummer values.
///
/// # Examples
///
/// ```
/// use cloakrs_core::Recognizer;
/// use cloakrs_locales::SteuerIdRecognizer;
///
/// let findings = SteuerIdRecognizer.scan("Steuer-ID 48954371207");
/// assert_eq!(findings.len(), 1);
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct SteuerIdRecognizer;

impl Recognizer for SteuerIdRecognizer {
    fn id(&self) -> &str {
        "de_steuer_id_mod11_10_v1"
    }

    fn entity_type(&self) -> EntityType {
        EntityType::SteuerID
    }

    fn supported_locales(&self) -> &[Locale] {
        DE_AND_EU_LOCALES
    }

    fn scan(&self, text: &str) -> Vec<PiiEntity> {
        STEUER_ID_REGEX
            .find_iter(text)
            .filter(|matched| self.is_valid_match(text, matched.start(), matched.end()))
            .map(|matched| PiiEntity {
                entity_type: self.entity_type(),
                span: Span::new(matched.start(), matched.end()),
                text: matched.as_str().to_string(),
                confidence: compute_confidence(text, matched.start(), matched.end()),
                recognizer_id: self.id().to_string(),
            })
            .collect()
    }

    fn validate(&self, candidate: &str) -> bool {
        let digits = digits(candidate);
        digits.len() == 11
            && first_ten_digits_structurally_valid(&digits)
            && steuer_id_checksum_valid(&digits)
    }
}

impl SteuerIdRecognizer {
    fn is_valid_match(&self, text: &str, start: usize, end: usize) -> bool {
        self.validate(&text[start..end]) && is_boundary(text, start, end)
    }
}

fn compute_confidence(text: &str, start: usize, end: usize) -> Confidence {
    confidence(0.55 + context_boost(text, Span::new(start, end), CONTEXT_WORDS))
}

fn first_ten_digits_structurally_valid(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.first() == Some(&b'0') {
        return false;
    }

    let mut counts = [0_u8; 10];
    for byte in bytes.iter().take(10) {
        counts[usize::from(byte - b'0')] += 1;
    }

    let repeated_digits = counts.iter().filter(|&&count| count > 1).count();
    let missing_digits = counts.iter().filter(|&&count| count == 0).count();
    let repeated_count_valid = counts.iter().any(|&count| matches!(count, 2 | 3));
    repeated_digits == 1 && repeated_count_valid && matches!(missing_digits, 1 | 2)
}

fn steuer_id_checksum_valid(value: &str) -> bool {
    let mut product = 10_u32;
    for byte in value.as_bytes().iter().take(10) {
        let digit = u32::from(byte - b'0');
        let mut sum = (digit + product) % 10;
        if sum == 0 {
            sum = 10;
        }
        product = (2 * sum) % 11;
    }

    let mut expected = 11 - product;
    if expected == 10 {
        expected = 0;
    }

    expected == u32::from(value.as_bytes()[10] - b'0')
}

#[cfg(test)]
mod tests {
    use super::*;
    use cloakrs_core::RecognizerRegistry;

    fn texts(input: &str) -> Vec<String> {
        SteuerIdRecognizer
            .scan(input)
            .into_iter()
            .map(|finding| finding.text)
            .collect()
    }

    #[test]
    fn test_steuer_id_first_valid_example_detected() {
        assert_eq!(texts("Steuer-ID 48954371207"), ["48954371207"]);
    }

    #[test]
    fn test_steuer_id_second_valid_example_detected() {
        assert_eq!(
            texts("Steueridentifikationsnummer 55492670836"),
            ["55492670836"]
        );
    }

    #[test]
    fn test_steuer_id_triple_digit_valid_example_detected() {
        assert_eq!(texts("IdNr 65929970489"), ["65929970489"]);
    }

    #[test]
    fn test_steuer_id_multiple_values_detected() {
        assert_eq!(
            texts("Steuer-ID 48954371207 und tax id 55492670836"),
            ["48954371207", "55492670836"]
        );
    }

    #[test]
    fn test_steuer_id_invalid_checksum_rejected() {
        assert!(texts("Steuer-ID 48954371208").is_empty());
    }

    #[test]
    fn test_steuer_id_too_short_rejected() {
        assert!(texts("Steuer-ID 4895437120").is_empty());
    }

    #[test]
    fn test_steuer_id_too_long_rejected() {
        assert!(texts("Steuer-ID 489543712070").is_empty());
    }

    #[test]
    fn test_steuer_id_leading_zero_rejected() {
        assert!(texts("Steuer-ID 08954371207").is_empty());
    }

    #[test]
    fn test_steuer_id_all_unique_first_ten_rejected() {
        assert!(texts("Steuer-ID 12345678903").is_empty());
    }

    #[test]
    fn test_steuer_id_multiple_repeated_digits_rejected() {
        assert!(texts("Steuer-ID 11223345671").is_empty());
    }

    #[test]
    fn test_steuer_id_digit_repeated_four_times_rejected() {
        assert!(texts("Steuer-ID 11112345678").is_empty());
    }

    #[test]
    fn test_steuer_id_letters_rejected() {
        assert!(texts("Steuer-ID 4895437120A").is_empty());
    }

    #[test]
    fn test_steuer_id_embedded_in_word_rejected() {
        assert!(texts("id48954371207").is_empty());
    }

    #[test]
    fn test_steuer_id_trailing_word_rejected() {
        assert!(texts("48954371207id").is_empty());
    }

    #[test]
    fn test_steuer_id_steuer_id_context_boosts_confidence() {
        let with_context = SteuerIdRecognizer.scan("Steuer-ID 48954371207");
        let without_context = SteuerIdRecognizer.scan("value 48954371207");
        assert!(with_context[0].confidence > without_context[0].confidence);
    }

    #[test]
    fn test_steuer_id_tax_id_context_after_boosts_confidence() {
        let with_context = SteuerIdRecognizer.scan("48954371207 tax id");
        let without_context = SteuerIdRecognizer.scan("48954371207 value");
        assert!(with_context[0].confidence > without_context[0].confidence);
    }

    #[test]
    fn test_steuer_id_without_context_has_moderate_confidence() {
        let findings = SteuerIdRecognizer.scan("value 48954371207");
        assert!(findings[0].confidence.value() < 0.7);
    }

    #[test]
    fn test_steuer_id_supported_locale_is_de() {
        assert_eq!(
            SteuerIdRecognizer.supported_locales(),
            &[Locale::DE, Locale::EU]
        );
    }

    #[test]
    fn test_steuer_id_registry_with_de_locale_detects() {
        let mut registry = RecognizerRegistry::new();
        registry.register(SteuerIdRecognizer);
        assert_eq!(
            registry
                .scan_locale("Steuer-ID 48954371207", &Locale::DE)
                .len(),
            1
        );
        assert_eq!(
            registry
                .scan_locale("Steuer-ID 48954371207", &Locale::Universal)
                .len(),
            0
        );
        assert_eq!(
            registry
                .scan_locale("Steuer-ID 48954371207", &Locale::EU)
                .len(),
            1
        );
    }
}
