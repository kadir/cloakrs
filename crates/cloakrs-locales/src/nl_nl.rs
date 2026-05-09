//! Dutch locale recognizers.

use crate::common::{compile_regex, confidence, digits, is_boundary};
use crate::eu::NL_AND_EU_LOCALES;
use cloakrs_core::{
    context_score, Confidence, ContextConfig, EntityType, Locale, PiiEntity, Recognizer, Span,
};
use once_cell::sync::Lazy;
use regex::Regex;

static BSN_REGEX: Lazy<Regex> = Lazy::new(|| compile_regex(r"\b\d{9}\b"));
const CONTEXT_WORDS: &[&str] = &["bsn", "burgerservicenummer", "sofinummer"];

/// Recognizes Dutch Burgerservicenummer (BSN) values.
///
/// # Examples
///
/// ```
/// use cloakrs_core::Recognizer;
/// use cloakrs_locales::BsnRecognizer;
///
/// let findings = BsnRecognizer.scan("BSN 123456782");
/// assert_eq!(findings.len(), 1);
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct BsnRecognizer;

impl Recognizer for BsnRecognizer {
    fn id(&self) -> &str {
        "nl_bsn_mod11_v1"
    }

    fn entity_type(&self) -> EntityType {
        EntityType::Bsn
    }

    fn supported_locales(&self) -> &[Locale] {
        NL_AND_EU_LOCALES
    }

    fn scan(&self, text: &str) -> Vec<PiiEntity> {
        BSN_REGEX
            .find_iter(text)
            .filter(|matched| self.is_valid_match(text, matched.start(), matched.end()))
            .map(|matched| PiiEntity {
                entity_type: self.entity_type(),
                span: Span::new(matched.start(), matched.end()),
                text: matched.as_str().to_string(),
                confidence: self.compute_confidence(text, matched.start(), matched.end()),
                recognizer_id: self.id().to_string(),
            })
            .collect()
    }

    fn validate(&self, candidate: &str) -> bool {
        let digits = digits(candidate);
        digits.len() == 9 && bsn_mod11_valid(&digits)
    }
}

impl BsnRecognizer {
    fn is_valid_match(&self, text: &str, start: usize, end: usize) -> bool {
        self.validate(&text[start..end]) && is_boundary(text, start, end)
    }

    fn compute_confidence(&self, text: &str, start: usize, end: usize) -> Confidence {
        let config = ContextConfig {
            words_before: 6,
            words_after: 4,
            single_hit_boost: 0.45,
            multi_hit_boost: 0.55,
            code_context_penalty: 0.20,
        };
        let score = context_score(text, Span::new(start, end), CONTEXT_WORDS, &config);
        confidence(0.35 + score.adjustment)
    }
}

fn bsn_mod11_valid(digits: &str) -> bool {
    let mut total = 0_i32;
    for (index, byte) in digits.as_bytes().iter().take(8).enumerate() {
        total += (9 - index as i32) * i32::from(byte - b'0');
    }
    total -= i32::from(digits.as_bytes()[8] - b'0');
    total % 11 == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use cloakrs_core::RecognizerRegistry;

    fn texts(input: &str) -> Vec<String> {
        BsnRecognizer
            .scan(input)
            .into_iter()
            .map(|finding| finding.text)
            .collect()
    }

    #[test]
    fn test_bsn_valid_example_detected() {
        assert_eq!(texts("BSN 123456782"), ["123456782"]);
    }

    #[test]
    fn test_bsn_second_valid_example_detected() {
        assert_eq!(texts("burgerservicenummer 111222333"), ["111222333"]);
    }

    #[test]
    fn test_bsn_third_valid_example_detected() {
        assert_eq!(texts("sofinummer 999990639"), ["999990639"]);
    }

    #[test]
    fn test_bsn_invalid_checksum_rejected() {
        assert!(texts("BSN 123456789").is_empty());
    }

    #[test]
    fn test_bsn_too_short_rejected() {
        assert!(texts("BSN 12345678").is_empty());
    }

    #[test]
    fn test_bsn_too_long_rejected() {
        assert!(texts("BSN 1234567820").is_empty());
    }

    #[test]
    fn test_bsn_embedded_in_word_not_detected() {
        assert!(texts("id123456782").is_empty());
    }

    #[test]
    fn test_bsn_without_context_has_low_confidence() {
        let findings = BsnRecognizer.scan("value 123456782");
        assert!(findings[0].confidence.value() <= 0.4);
    }

    #[test]
    fn test_bsn_bsn_context_boosts_confidence() {
        let with_context = BsnRecognizer.scan("BSN 123456782");
        let without_context = BsnRecognizer.scan("value 123456782");
        assert!(with_context[0].confidence > without_context[0].confidence);
        assert!(with_context[0].confidence.value() >= 0.8);
    }

    #[test]
    fn test_bsn_burgerservicenummer_context_boosts_confidence() {
        let with_context = BsnRecognizer.scan("burgerservicenummer 123456782");
        let without_context = BsnRecognizer.scan("value 123456782");
        assert!(with_context[0].confidence > without_context[0].confidence);
    }

    #[test]
    fn test_bsn_sofinummer_context_after_boosts_confidence() {
        let with_context = BsnRecognizer.scan("123456782 sofinummer");
        let without_context = BsnRecognizer.scan("123456782 value");
        assert!(with_context[0].confidence > without_context[0].confidence);
    }

    #[test]
    fn test_bsn_supported_locale_is_nl() {
        assert_eq!(BsnRecognizer.supported_locales(), &[Locale::NL, Locale::EU]);
    }

    #[test]
    fn test_bsn_registry_with_nl_locale_detects() {
        let mut registry = RecognizerRegistry::new();
        registry.register(BsnRecognizer);
        assert_eq!(registry.scan_locale("BSN 123456782", &Locale::NL).len(), 1);
        assert_eq!(
            registry
                .scan_locale("BSN 123456782", &Locale::Universal)
                .len(),
            0
        );
        assert_eq!(registry.scan_locale("BSN 123456782", &Locale::EU).len(), 1);
    }
}
