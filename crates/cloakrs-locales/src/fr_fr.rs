//! French locale recognizers.

use crate::common::{alphanumeric_upper, compile_regex, confidence, context_boost, is_boundary};
use crate::eu::FR_AND_EU_LOCALES;
use cloakrs_core::{Confidence, EntityType, Locale, PiiEntity, Recognizer, Span};
use once_cell::sync::Lazy;
use regex::Regex;

static INSEE_NIR_REGEX: Lazy<Regex> = Lazy::new(|| {
    compile_regex(
        r"(?i)\b[12][ -]?\d{2}[ -]?\d{2}[ -]?(?:\d{2}|2[ab])[ -]?\d{3}[ -]?\d{3}[ -]?\d{2}\b",
    )
});
const CONTEXT_WORDS: &[&str] = &[
    "nir",
    "insee",
    "securite sociale",
    "numero de securite sociale",
    "social security",
];

/// Recognizes French NIR / INSEE social security numbers.
///
/// # Examples
///
/// ```
/// use cloakrs_core::Recognizer;
/// use cloakrs_locales::InseeNirRecognizer;
///
/// let findings = InseeNirRecognizer.scan("NIR 1 51 02 46 102 043 25");
/// assert_eq!(findings.len(), 1);
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct InseeNirRecognizer;

impl Recognizer for InseeNirRecognizer {
    fn id(&self) -> &str {
        "fr_insee_nir_mod97_v1"
    }

    fn entity_type(&self) -> EntityType {
        EntityType::InseeNir
    }

    fn supported_locales(&self) -> &[Locale] {
        FR_AND_EU_LOCALES
    }

    fn scan(&self, text: &str) -> Vec<PiiEntity> {
        INSEE_NIR_REGEX
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
        let normalized = alphanumeric_upper(candidate);
        normalized.len() == 15
            && nir_body_shape_valid(&normalized[..13])
            && nir_key_valid(&normalized)
    }
}

impl InseeNirRecognizer {
    fn is_valid_match(&self, text: &str, start: usize, end: usize) -> bool {
        self.validate(&text[start..end])
            && is_boundary(text, start, end)
            && !has_separated_digit_before(text, start)
            && !has_separated_digit_after(text, end)
    }
}

fn compute_confidence(text: &str, start: usize, end: usize) -> Confidence {
    confidence(0.65 + context_boost(text, Span::new(start, end), CONTEXT_WORDS))
}

fn nir_body_shape_valid(body: &str) -> bool {
    let bytes = body.as_bytes();
    matches!(bytes[0], b'1' | b'2')
        && bytes[1..6].iter().all(u8::is_ascii_digit)
        && (bytes[6].is_ascii_digit() || matches!(bytes[6], b'A' | b'B'))
        && bytes[7..13].iter().all(u8::is_ascii_digit)
}

fn nir_key_valid(value: &str) -> bool {
    let body = &value[..13];
    let Some(adjusted) = adjusted_nir_number(body) else {
        return false;
    };
    let expected = 97 - (adjusted % 97);
    let key = two_digit_number(&value.as_bytes()[13..15]);
    key == Some(expected as u8)
}

fn adjusted_nir_number(body: &str) -> Option<u64> {
    let mut numeric = String::with_capacity(body.len());
    let mut corsica_adjustment = 0_u64;

    for byte in body.bytes() {
        match byte {
            b'0'..=b'9' => numeric.push(char::from(byte)),
            b'A' => {
                numeric.push('0');
                corsica_adjustment = 1_000_000;
            }
            b'B' => {
                numeric.push('0');
                corsica_adjustment = 2_000_000;
            }
            _ => return None,
        }
    }

    numeric.parse::<u64>().ok()?.checked_sub(corsica_adjustment)
}

fn two_digit_number(bytes: &[u8]) -> Option<u8> {
    if bytes.len() == 2 && bytes.iter().all(u8::is_ascii_digit) {
        Some((bytes[0] - b'0') * 10 + (bytes[1] - b'0'))
    } else {
        None
    }
}

fn has_separated_digit_before(text: &str, start: usize) -> bool {
    let mut chars = text[..start].chars().rev();
    matches!(chars.next(), Some(' ' | '-')) && chars.next().is_some_and(|c| c.is_ascii_digit())
}

fn has_separated_digit_after(text: &str, end: usize) -> bool {
    let mut chars = text[end..].chars();
    matches!(chars.next(), Some(' ' | '-')) && chars.next().is_some_and(|c| c.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cloakrs_core::RecognizerRegistry;

    fn texts(input: &str) -> Vec<String> {
        InseeNirRecognizer
            .scan(input)
            .into_iter()
            .map(|finding| finding.text)
            .collect()
    }

    #[test]
    fn test_insee_nir_spaced_format_detected() {
        assert_eq!(
            texts("NIR 1 51 02 46 102 043 25"),
            ["1 51 02 46 102 043 25"]
        );
    }

    #[test]
    fn test_insee_nir_compact_format_detected() {
        assert_eq!(texts("INSEE 151024610204325"), ["151024610204325"]);
    }

    #[test]
    fn test_insee_nir_hyphenated_format_detected() {
        assert_eq!(
            texts("numero de securite sociale 1-84-12-76-451-089-46"),
            ["1-84-12-76-451-089-46"]
        );
    }

    #[test]
    fn test_insee_nir_corsica_a_format_detected() {
        assert_eq!(
            texts("NIR 1 80 06 2A 123 456 03"),
            ["1 80 06 2A 123 456 03"]
        );
    }

    #[test]
    fn test_insee_nir_corsica_b_format_detected() {
        assert_eq!(
            texts("NIR 2 78 11 2B 050 002 86"),
            ["2 78 11 2B 050 002 86"]
        );
    }

    #[test]
    fn test_insee_nir_multiple_values_detected() {
        assert_eq!(
            texts("NIR 151024610204325 and INSEE 184127645108946"),
            ["151024610204325", "184127645108946"]
        );
    }

    #[test]
    fn test_insee_nir_invalid_checksum_rejected() {
        assert!(texts("NIR 1 51 02 46 102 043 26").is_empty());
    }

    #[test]
    fn test_insee_nir_too_short_rejected() {
        assert!(texts("NIR 1 51 02 46 102 043 2").is_empty());
    }

    #[test]
    fn test_insee_nir_too_long_rejected() {
        assert!(texts("NIR 1 51 02 46 102 043 25 9").is_empty());
    }

    #[test]
    fn test_insee_nir_invalid_sex_digit_rejected() {
        assert!(texts("NIR 3 51 02 46 102 043 23").is_empty());
    }

    #[test]
    fn test_insee_nir_letter_outside_corsica_slot_rejected() {
        assert!(texts("NIR 1 5A 02 46 102 043 25").is_empty());
    }

    #[test]
    fn test_insee_nir_invalid_corsica_letter_rejected() {
        assert!(texts("NIR 1 80 06 2C 123 456 72").is_empty());
    }

    #[test]
    fn test_insee_nir_embedded_in_word_rejected() {
        assert!(texts("id151024610204325").is_empty());
    }

    #[test]
    fn test_insee_nir_trailing_word_rejected() {
        assert!(texts("151024610204325id").is_empty());
    }

    #[test]
    fn test_insee_nir_context_before_boosts_confidence() {
        let with_context = InseeNirRecognizer.scan("NIR 151024610204325");
        let without_context = InseeNirRecognizer.scan("value 151024610204325");
        assert!(with_context[0].confidence > without_context[0].confidence);
    }

    #[test]
    fn test_insee_nir_context_after_boosts_confidence() {
        let with_context = InseeNirRecognizer.scan("151024610204325 securite sociale");
        let without_context = InseeNirRecognizer.scan("151024610204325 value");
        assert!(with_context[0].confidence > without_context[0].confidence);
    }

    #[test]
    fn test_insee_nir_supported_locale_is_fr() {
        assert_eq!(
            InseeNirRecognizer.supported_locales(),
            &[Locale::FR, Locale::EU]
        );
    }

    #[test]
    fn test_insee_nir_registry_with_fr_locale_detects() {
        let mut registry = RecognizerRegistry::new();
        registry.register(InseeNirRecognizer);
        assert_eq!(
            registry
                .scan_locale("NIR 151024610204325", &Locale::FR)
                .len(),
            1
        );
        assert_eq!(
            registry
                .scan_locale("NIR 151024610204325", &Locale::Universal)
                .len(),
            0
        );
        assert_eq!(
            registry
                .scan_locale("NIR 151024610204325", &Locale::EU)
                .len(),
            1
        );
    }
}
