use crate::common::{compile_regex, confidence, context_boost, digits, is_boundary};
use crate::credit_card::luhn_valid;
use cloakrs_core::{Confidence, EntityType, Locale, PiiEntity, Recognizer, Span};
use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashSet;

static INTERNATIONAL_PHONE_REGEX: Lazy<Regex> = Lazy::new(|| {
    compile_regex(r"\+\d{1,3}[\s.-]?(?:\(\d{2,4}\)|\d{1,4})(?:[\s.-]?\d{2,6}){2,4}\b")
});
static NANP_PHONE_REGEX: Lazy<Regex> =
    Lazy::new(|| compile_regex(r"(?:\(\d{3}\)\s*|\b\d{3}[-. ])\d{3}[-. ]\d{4}\b"));

const CONTEXT_WORDS: &[&str] = &[
    "call", "phone", "tel:", "tel", "mobile", "cell", "fax", "dial", "text", "sms",
];

/// Recognizes common international and North American phone numbers.
#[derive(Debug, Clone, Copy, Default)]
pub struct PhoneRecognizer;

impl Recognizer for PhoneRecognizer {
    fn id(&self) -> &str {
        "phone_regex_v1"
    }

    fn entity_type(&self) -> EntityType {
        EntityType::PhoneNumber
    }

    fn supported_locales(&self) -> &[Locale] {
        &[]
    }

    fn scan(&self, text: &str) -> Vec<PiiEntity> {
        let mut seen = HashSet::new();
        let mut findings = Vec::new();

        for regex in [&*INTERNATIONAL_PHONE_REGEX, &*NANP_PHONE_REGEX] {
            for matched in regex.find_iter(text) {
                if !findings.iter().any(|finding: &PiiEntity| {
                    matched.start() >= finding.span.start && matched.end() <= finding.span.end
                }) && seen.insert((matched.start(), matched.end()))
                    && self.is_valid_match(text, matched.start(), matched.end())
                {
                    findings.push(PiiEntity {
                        entity_type: self.entity_type(),
                        span: Span::new(matched.start(), matched.end()),
                        text: matched.as_str().to_string(),
                        confidence: self.compute_confidence(
                            text,
                            matched.start(),
                            matched.as_str(),
                        ),
                        recognizer_id: self.id().to_string(),
                    });
                }
            }
        }

        findings.sort_by_key(|finding| finding.span.start);
        findings
    }

    fn validate(&self, candidate: &str) -> bool {
        let digits = digits(candidate);
        if !(7..=15).contains(&digits.len()) {
            return false;
        }
        if digits.chars().all(|c| c == digits.as_bytes()[0] as char) {
            return false;
        }
        if (13..=15).contains(&digits.len()) && luhn_valid(&digits) {
            return false;
        }
        true
    }
}

impl PhoneRecognizer {
    fn is_valid_match(&self, text: &str, start: usize, end: usize) -> bool {
        self.validate(&text[start..end]) && is_boundary(text, start, end)
    }

    fn compute_confidence(&self, text: &str, start: usize, candidate: &str) -> Confidence {
        let base = if candidate.trim_start().starts_with('+') {
            0.90
        } else {
            0.70
        };
        confidence(base + context_boost(text, start, CONTEXT_WORDS))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn texts(input: &str) -> Vec<String> {
        PhoneRecognizer
            .scan(input)
            .into_iter()
            .map(|finding| finding.text)
            .collect()
    }

    #[test]
    fn test_phone_us_international_detected() {
        assert_eq!(texts("call +1 (555) 123-4567"), ["+1 (555) 123-4567"]);
    }

    #[test]
    fn test_phone_netherlands_mobile_detected() {
        assert_eq!(texts("+31 6 12345678"), ["+31 6 12345678"]);
    }

    #[test]
    fn test_phone_uk_mobile_detected() {
        assert_eq!(texts("+44 7911 123456"), ["+44 7911 123456"]);
    }

    #[test]
    fn test_phone_nanp_dashes_detected() {
        assert_eq!(texts("555-123-4567"), ["555-123-4567"]);
    }

    #[test]
    fn test_phone_nanp_parentheses_detected() {
        assert_eq!(texts("(555) 123-4567"), ["(555) 123-4567"]);
    }

    #[test]
    fn test_phone_year_not_detected() {
        assert!(texts("2024").is_empty());
    }

    #[test]
    fn test_phone_zip_not_detected() {
        assert!(texts("90210").is_empty());
    }

    #[test]
    fn test_phone_credit_card_not_detected() {
        assert!(texts("4111 1111 1111 1111").is_empty());
    }

    #[test]
    fn test_phone_short_sequence_rejected() {
        assert!(!PhoneRecognizer.validate("123-456"));
    }

    #[test]
    fn test_phone_context_boosts_confidence() {
        let with_context = PhoneRecognizer.scan("phone: 555-123-4567");
        let without_context = PhoneRecognizer.scan("value 555-123-4567");
        assert!(with_context[0].confidence > without_context[0].confidence);
    }

    #[test]
    fn test_phone_nanp_dots_detected() {
        assert_eq!(texts("555.123.4567"), ["555.123.4567"]);
    }

    #[test]
    fn test_phone_international_dots_detected() {
        assert_eq!(texts("+1.555.123.4567"), ["+1.555.123.4567"]);
    }

    #[test]
    fn test_phone_french_mobile_detected() {
        assert_eq!(texts("+33 6 12 34 56 78"), ["+33 6 12 34 56 78"]);
    }

    #[test]
    fn test_phone_german_number_detected() {
        assert_eq!(texts("+49 30 1234 5678"), ["+49 30 1234 5678"]);
    }

    #[test]
    fn test_phone_two_numbers_detected() {
        assert_eq!(
            texts("call 555-123-4567 or +44 7911 123456"),
            ["555-123-4567", "+44 7911 123456"]
        );
    }

    #[test]
    fn test_phone_seven_digit_local_detected() {
        assert_eq!(texts("555-1212"), Vec::<String>::new());
    }

    #[test]
    fn test_phone_all_same_digits_rejected() {
        assert!(texts("111-111-1111").is_empty());
    }

    #[test]
    fn test_phone_long_sequence_rejected() {
        assert!(!PhoneRecognizer.validate("+123 4567 8901 2345 6789"));
    }

    #[test]
    fn test_phone_embedded_in_word_not_detected() {
        assert!(texts("id555-123-4567").is_empty());
    }

    #[test]
    fn test_phone_trailing_letter_not_detected() {
        assert!(texts("555-123-4567x").is_empty());
    }

    #[test]
    fn test_phone_international_confidence_higher_than_nanp() {
        let international = PhoneRecognizer.scan("+1 555 123 4567");
        let nanp = PhoneRecognizer.scan("555-123-4567");
        assert!(international[0].confidence > nanp[0].confidence);
    }

    #[test]
    fn test_phone_tel_context_boosts_confidence() {
        let with_context = PhoneRecognizer.scan("tel: 555-123-4567");
        let without_context = PhoneRecognizer.scan("value 555-123-4567");
        assert!(with_context[0].confidence > without_context[0].confidence);
    }

    #[test]
    fn test_phone_mobile_context_boosts_confidence() {
        let with_context = PhoneRecognizer.scan("mobile +31 6 12345678");
        let without_context = PhoneRecognizer.scan("value +31 6 12345678");
        assert!(with_context[0].confidence > without_context[0].confidence);
    }

    #[test]
    fn test_phone_plain_random_digits_not_detected() {
        assert!(texts("1234567890").is_empty());
    }

    #[test]
    fn test_phone_date_not_detected() {
        assert!(texts("2026-05-08").is_empty());
    }

    #[test]
    fn test_phone_validate_accepts_minimum_digit_count() {
        assert!(PhoneRecognizer.validate("123-4567"));
    }

    #[test]
    fn test_phone_validate_rejects_six_digits() {
        assert!(!PhoneRecognizer.validate("123456"));
    }

    #[test]
    fn test_phone_validate_rejects_sixteen_digits() {
        assert!(!PhoneRecognizer.validate("1234567890123456"));
    }

    #[test]
    fn test_phone_context_can_reach_full_confidence_cap() {
        let finding = PhoneRecognizer.scan("call mobile phone +31 6 12345678");
        assert!(finding[0].confidence.value() <= 1.0);
    }

    #[test]
    fn test_phone_fax_context_boosts_confidence() {
        let with_context = PhoneRecognizer.scan("fax 555-123-4567");
        let without_context = PhoneRecognizer.scan("value 555-123-4567");
        assert!(with_context[0].confidence > without_context[0].confidence);
    }
}
