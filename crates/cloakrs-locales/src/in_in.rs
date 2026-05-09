//! Indian locale recognizers.

use crate::common::{
    alphanumeric_upper, compile_regex, confidence, context_boost, digits, is_boundary,
};
use cloakrs_core::{Confidence, EntityType, Locale, PiiEntity, Recognizer, Span};
use once_cell::sync::Lazy;
use regex::Regex;

static AADHAAR_REGEX: Lazy<Regex> =
    Lazy::new(|| compile_regex(r"\b[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}\b"));
static PAN_REGEX: Lazy<Regex> =
    Lazy::new(|| compile_regex(r"(?i)\b[a-z]{3}[abcfghljpt][a-z]\d{4}[a-z]\b"));
static IN_LOCALES: &[Locale] = &[Locale::IN];

const AADHAAR_CONTEXT_WORDS: &[&str] = &["aadhaar", "aadhar", "uid", "unique identification"];
const PAN_CONTEXT_WORDS: &[&str] = &["pan", "pan card", "permanent account number", "income tax"];

/// Recognizes Indian Aadhaar numbers with Verhoeff checksum validation.
///
/// # Examples
///
/// ```
/// use cloakrs_core::Recognizer;
/// use cloakrs_locales::AadhaarRecognizer;
///
/// let findings = AadhaarRecognizer.scan("Aadhaar 2345 6789 0124");
/// assert_eq!(findings.len(), 1);
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct AadhaarRecognizer;

impl Recognizer for AadhaarRecognizer {
    fn id(&self) -> &str {
        "in_aadhaar_verhoeff_v1"
    }

    fn entity_type(&self) -> EntityType {
        EntityType::Aadhaar
    }

    fn supported_locales(&self) -> &[Locale] {
        IN_LOCALES
    }

    fn scan(&self, text: &str) -> Vec<PiiEntity> {
        AADHAAR_REGEX
            .find_iter(text)
            .filter(|matched| self.is_valid_match(text, matched.start(), matched.end()))
            .map(|matched| PiiEntity {
                entity_type: self.entity_type(),
                span: Span::new(matched.start(), matched.end()),
                text: matched.as_str().to_string(),
                confidence: compute_aadhaar_confidence(text, matched.start(), matched.end()),
                recognizer_id: self.id().to_string(),
            })
            .collect()
    }

    fn validate(&self, candidate: &str) -> bool {
        let digits = digits(candidate);
        digits.len() == 12
            && digits
                .as_bytes()
                .first()
                .is_some_and(|digit| matches!(digit, b'2'..=b'9'))
            && verhoeff_valid(&digits)
    }
}

impl AadhaarRecognizer {
    fn is_valid_match(&self, text: &str, start: usize, end: usize) -> bool {
        self.validate(&text[start..end])
            && is_boundary(text, start, end)
            && !has_separated_digit_before(text, start)
            && !has_separated_digit_after(text, end)
    }
}

/// Recognizes Indian Permanent Account Numbers (PAN).
///
/// # Examples
///
/// ```
/// use cloakrs_core::Recognizer;
/// use cloakrs_locales::PanRecognizer;
///
/// let findings = PanRecognizer.scan("PAN AAAPA1234A");
/// assert_eq!(findings.len(), 1);
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct PanRecognizer;

impl Recognizer for PanRecognizer {
    fn id(&self) -> &str {
        "in_pan_regex_v1"
    }

    fn entity_type(&self) -> EntityType {
        EntityType::Pan
    }

    fn supported_locales(&self) -> &[Locale] {
        IN_LOCALES
    }

    fn scan(&self, text: &str) -> Vec<PiiEntity> {
        PAN_REGEX
            .find_iter(text)
            .filter(|matched| self.is_valid_match(text, matched.start(), matched.end()))
            .map(|matched| PiiEntity {
                entity_type: self.entity_type(),
                span: Span::new(matched.start(), matched.end()),
                text: matched.as_str().to_string(),
                confidence: compute_pan_confidence(text, matched.start(), matched.end()),
                recognizer_id: self.id().to_string(),
            })
            .collect()
    }

    fn validate(&self, candidate: &str) -> bool {
        pan_valid(candidate)
    }
}

impl PanRecognizer {
    fn is_valid_match(&self, text: &str, start: usize, end: usize) -> bool {
        self.validate(&text[start..end]) && is_boundary(text, start, end)
    }
}

fn compute_aadhaar_confidence(text: &str, start: usize, end: usize) -> Confidence {
    confidence(0.65 + context_boost(text, Span::new(start, end), AADHAAR_CONTEXT_WORDS))
}

fn compute_pan_confidence(text: &str, start: usize, end: usize) -> Confidence {
    confidence(0.78 + context_boost(text, Span::new(start, end), PAN_CONTEXT_WORDS))
}

fn pan_valid(candidate: &str) -> bool {
    let normalized = alphanumeric_upper(candidate);
    if normalized.len() != 10 {
        return false;
    }

    let bytes = normalized.as_bytes();
    bytes[0..3].iter().all(u8::is_ascii_uppercase)
        && matches!(
            bytes[3],
            b'A' | b'B' | b'C' | b'F' | b'G' | b'H' | b'L' | b'J' | b'P' | b'T'
        )
        && bytes[4].is_ascii_uppercase()
        && bytes[5..9].iter().all(u8::is_ascii_digit)
        && bytes[5..9] != *b"0000"
        && bytes[9].is_ascii_uppercase()
}

fn verhoeff_valid(value: &str) -> bool {
    let mut checksum = 0_usize;
    for (index, byte) in value.as_bytes().iter().rev().enumerate() {
        let digit = usize::from(byte - b'0');
        checksum = VERHOEFF_D[checksum][VERHOEFF_P[index % 8][digit]];
    }
    checksum == 0
}

fn has_separated_digit_before(text: &str, start: usize) -> bool {
    let mut chars = text[..start].chars().rev();
    matches!(chars.next(), Some(' ' | '-')) && chars.next().is_some_and(|c| c.is_ascii_digit())
}

fn has_separated_digit_after(text: &str, end: usize) -> bool {
    let mut chars = text[end..].chars();
    matches!(chars.next(), Some(' ' | '-')) && chars.next().is_some_and(|c| c.is_ascii_digit())
}

const VERHOEFF_D: [[usize; 10]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
];

const VERHOEFF_P: [[usize; 10]; 8] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
];

#[cfg(test)]
mod tests {
    use super::*;
    use cloakrs_core::RecognizerRegistry;

    fn aadhaar_texts(input: &str) -> Vec<String> {
        AadhaarRecognizer
            .scan(input)
            .into_iter()
            .map(|finding| finding.text)
            .collect()
    }

    fn pan_texts(input: &str) -> Vec<String> {
        PanRecognizer
            .scan(input)
            .into_iter()
            .map(|finding| finding.text)
            .collect()
    }

    #[test]
    fn test_aadhaar_spaced_format_detected() {
        assert_eq!(aadhaar_texts("Aadhaar 2345 6789 0124"), ["2345 6789 0124"]);
    }

    #[test]
    fn test_aadhaar_compact_format_detected() {
        assert_eq!(aadhaar_texts("UID 234567890124"), ["234567890124"]);
    }

    #[test]
    fn test_aadhaar_hyphenated_format_detected() {
        assert_eq!(aadhaar_texts("Aadhaar 2653-8564-4664"), ["2653-8564-4664"]);
    }

    #[test]
    fn test_aadhaar_multiple_values_detected() {
        assert_eq!(
            aadhaar_texts("Aadhaar 2345 6789 0124 and UID 987654321012"),
            ["2345 6789 0124", "987654321012"]
        );
    }

    #[test]
    fn test_aadhaar_invalid_checksum_rejected() {
        assert!(aadhaar_texts("Aadhaar 2345 6789 0123").is_empty());
    }

    #[test]
    fn test_aadhaar_too_short_rejected() {
        assert!(aadhaar_texts("Aadhaar 2345 6789 012").is_empty());
    }

    #[test]
    fn test_aadhaar_too_long_rejected() {
        assert!(aadhaar_texts("Aadhaar 2345 6789 0124 5").is_empty());
    }

    #[test]
    fn test_aadhaar_leading_zero_rejected() {
        assert!(aadhaar_texts("Aadhaar 0345 6789 0129").is_empty());
    }

    #[test]
    fn test_aadhaar_leading_one_rejected() {
        assert!(aadhaar_texts("Aadhaar 1345 6789 0128").is_empty());
    }

    #[test]
    fn test_aadhaar_letters_rejected() {
        assert!(aadhaar_texts("Aadhaar 2345 6789 012A").is_empty());
    }

    #[test]
    fn test_aadhaar_embedded_in_word_rejected() {
        assert!(aadhaar_texts("id234567890124").is_empty());
    }

    #[test]
    fn test_aadhaar_trailing_word_rejected() {
        assert!(aadhaar_texts("234567890124id").is_empty());
    }

    #[test]
    fn test_aadhaar_context_before_boosts_confidence() {
        let with_context = AadhaarRecognizer.scan("Aadhaar 2345 6789 0124");
        let without_context = AadhaarRecognizer.scan("value 2345 6789 0124");
        assert!(with_context[0].confidence > without_context[0].confidence);
    }

    #[test]
    fn test_aadhaar_context_after_boosts_confidence() {
        let with_context = AadhaarRecognizer.scan("2345 6789 0124 unique identification");
        let without_context = AadhaarRecognizer.scan("2345 6789 0124 value");
        assert!(with_context[0].confidence > without_context[0].confidence);
    }

    #[test]
    fn test_aadhaar_supported_locale_is_in() {
        assert_eq!(AadhaarRecognizer.supported_locales(), &[Locale::IN]);
    }

    #[test]
    fn test_pan_individual_format_detected() {
        assert_eq!(pan_texts("PAN AAAPA1234A"), ["AAAPA1234A"]);
    }

    #[test]
    fn test_pan_company_format_detected() {
        assert_eq!(pan_texts("PAN AAACA1234B"), ["AAACA1234B"]);
    }

    #[test]
    fn test_pan_lowercase_format_detected() {
        assert_eq!(pan_texts("pan aaapt1234c"), ["aaapt1234c"]);
    }

    #[test]
    fn test_pan_multiple_values_detected() {
        assert_eq!(
            pan_texts("PAN AAAPA1234A and permanent account number BBBPF9999Z"),
            ["AAAPA1234A", "BBBPF9999Z"]
        );
    }

    #[test]
    fn test_pan_invalid_holder_type_rejected() {
        assert!(pan_texts("PAN AAAZA1234A").is_empty());
    }

    #[test]
    fn test_pan_too_short_rejected() {
        assert!(pan_texts("PAN AAAPA123A").is_empty());
    }

    #[test]
    fn test_pan_too_long_rejected() {
        assert!(pan_texts("PAN AAAPA12345A").is_empty());
    }

    #[test]
    fn test_pan_missing_digits_rejected() {
        assert!(pan_texts("PAN AAAPABCD1A").is_empty());
    }

    #[test]
    fn test_pan_zero_sequence_rejected() {
        assert!(pan_texts("PAN AAAPA0000A").is_empty());
    }

    #[test]
    fn test_pan_last_character_digit_rejected() {
        assert!(pan_texts("PAN AAAPA12345").is_empty());
    }

    #[test]
    fn test_pan_embedded_in_word_rejected() {
        assert!(pan_texts("idAAAPA1234A").is_empty());
    }

    #[test]
    fn test_pan_trailing_word_rejected() {
        assert!(pan_texts("AAAPA1234Aid").is_empty());
    }

    #[test]
    fn test_pan_context_before_boosts_confidence() {
        let with_context = PanRecognizer.scan("PAN AAAPA1234A");
        let without_context = PanRecognizer.scan("value AAAPA1234A");
        assert!(with_context[0].confidence > without_context[0].confidence);
    }

    #[test]
    fn test_pan_context_after_boosts_confidence() {
        let with_context = PanRecognizer.scan("AAAPA1234A permanent account number");
        let without_context = PanRecognizer.scan("AAAPA1234A value");
        assert!(with_context[0].confidence > without_context[0].confidence);
    }

    #[test]
    fn test_pan_supported_locale_is_in() {
        assert_eq!(PanRecognizer.supported_locales(), &[Locale::IN]);
    }

    #[test]
    fn test_india_registry_with_in_locale_detects_both_entities() {
        let mut registry = RecognizerRegistry::new();
        registry.register(AadhaarRecognizer);
        registry.register(PanRecognizer);
        let findings =
            registry.scan_locale("Aadhaar 2345 6789 0124 and PAN AAAPA1234A", &Locale::IN);
        assert_eq!(findings.len(), 2);
        assert_eq!(
            registry
                .scan_locale(
                    "Aadhaar 2345 6789 0124 and PAN AAAPA1234A",
                    &Locale::Universal
                )
                .len(),
            0
        );
    }
}
