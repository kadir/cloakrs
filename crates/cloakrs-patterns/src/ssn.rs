use crate::common::{compile_regex, confidence, context_boost, digits, is_boundary};
use cloakrs_core::{Confidence, EntityType, Locale, PiiEntity, Recognizer, Span};
use once_cell::sync::Lazy;
use regex::Regex;

static SSN_REGEX: Lazy<Regex> =
    Lazy::new(|| compile_regex(r"\b(?:\d{3}[- ]\d{2}[- ]\d{4}|\d{9})\b"));

static US_LOCALES: &[Locale] = &[Locale::US];

const CONTEXT_WORDS: &[&str] = &["ssn", "social security", "tax id", "taxpayer"];

/// Recognizes United States Social Security Numbers.
#[derive(Debug, Clone, Copy, Default)]
pub struct SsnRecognizer;

impl Recognizer for SsnRecognizer {
    fn id(&self) -> &str {
        "us_ssn_regex_v1"
    }

    fn entity_type(&self) -> EntityType {
        EntityType::Ssn
    }

    fn supported_locales(&self) -> &[Locale] {
        US_LOCALES
    }

    fn scan(&self, text: &str) -> Vec<PiiEntity> {
        SSN_REGEX
            .find_iter(text)
            .filter(|matched| self.is_valid_match(text, matched.start(), matched.end()))
            .map(|matched| PiiEntity {
                entity_type: self.entity_type(),
                span: Span::new(matched.start(), matched.end()),
                text: matched.as_str().to_string(),
                confidence: self.compute_confidence(text, matched.start(), matched.as_str()),
                recognizer_id: self.id().to_string(),
            })
            .collect()
    }

    fn validate(&self, candidate: &str) -> bool {
        let digits = digits(candidate);
        if digits.len() != 9 {
            return false;
        }

        let area = &digits[0..3];
        let group = &digits[3..5];
        let serial = &digits[5..9];

        area != "000"
            && area != "666"
            && !matches!(area.parse::<u16>(), Ok(900..=999))
            && group != "00"
            && serial != "0000"
    }
}

impl SsnRecognizer {
    fn is_valid_match(&self, text: &str, start: usize, end: usize) -> bool {
        self.validate(&text[start..end]) && is_boundary(text, start, end)
    }

    fn compute_confidence(&self, text: &str, start: usize, candidate: &str) -> Confidence {
        let base = if candidate.contains('-') || candidate.contains(' ') {
            0.85
        } else {
            0.50
        };
        confidence(base + context_boost(text, start, CONTEXT_WORDS))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn texts(input: &str) -> Vec<String> {
        SsnRecognizer
            .scan(input)
            .into_iter()
            .map(|finding| finding.text)
            .collect()
    }

    #[test]
    fn test_ssn_dash_format_detected() {
        assert_eq!(texts("SSN 123-45-6789"), ["123-45-6789"]);
    }

    #[test]
    fn test_ssn_space_format_detected() {
        assert_eq!(texts("123 45 6789"), ["123 45 6789"]);
    }

    #[test]
    fn test_ssn_plain_format_detected() {
        assert_eq!(texts("123456789"), ["123456789"]);
    }

    #[test]
    fn test_ssn_area_000_rejected() {
        assert!(texts("000-45-6789").is_empty());
    }

    #[test]
    fn test_ssn_area_666_rejected() {
        assert!(texts("666-45-6789").is_empty());
    }

    #[test]
    fn test_ssn_area_900_rejected() {
        assert!(texts("900-45-6789").is_empty());
    }

    #[test]
    fn test_ssn_group_00_rejected() {
        assert!(texts("123-00-6789").is_empty());
    }

    #[test]
    fn test_ssn_serial_0000_rejected() {
        assert!(texts("123-45-0000").is_empty());
    }

    #[test]
    fn test_ssn_context_boosts_confidence() {
        let with_context = SsnRecognizer.scan("ssn 123-45-6789");
        let without_context = SsnRecognizer.scan("value 123-45-6789");
        assert!(with_context[0].confidence > without_context[0].confidence);
    }

    #[test]
    fn test_ssn_supported_locale_is_us() {
        assert_eq!(SsnRecognizer.supported_locales(), &[Locale::US]);
    }

    #[test]
    fn test_ssn_area_899_detected() {
        assert_eq!(texts("899-45-6789"), ["899-45-6789"]);
    }

    #[test]
    fn test_ssn_area_999_rejected() {
        assert!(texts("999-45-6789").is_empty());
    }

    #[test]
    fn test_ssn_embedded_in_word_not_detected() {
        assert!(texts("id123-45-6789").is_empty());
    }

    #[test]
    fn test_ssn_social_security_context_boosts_confidence() {
        let with_context = SsnRecognizer.scan("social security 123-45-6789");
        let without_context = SsnRecognizer.scan("value 123-45-6789");
        assert!(with_context[0].confidence > without_context[0].confidence);
    }

    #[test]
    fn test_ssn_plain_confidence_lower_than_separated() {
        let plain = SsnRecognizer.scan("123456789");
        let separated = SsnRecognizer.scan("123-45-6789");
        assert!(plain[0].confidence < separated[0].confidence);
    }
}
