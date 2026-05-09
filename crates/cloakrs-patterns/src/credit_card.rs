use crate::common::{compile_regex, confidence, digits};
use cloakrs_core::{Confidence, EntityType, Locale, PiiEntity, Recognizer, Span};
use once_cell::sync::Lazy;
use regex::Regex;

static CREDIT_CARD_REGEX: Lazy<Regex> = Lazy::new(|| compile_regex(r"\b(?:\d[ -.]?){13,19}\b"));

/// Known payment card brand families.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CardBrand {
    /// Visa.
    Visa,
    /// Mastercard.
    Mastercard,
    /// American Express.
    AmericanExpress,
    /// Discover.
    Discover,
}

/// Recognizes credit and debit card numbers with Luhn validation.
#[derive(Debug, Clone, Copy, Default)]
pub struct CreditCardRecognizer;

impl Recognizer for CreditCardRecognizer {
    fn id(&self) -> &str {
        "credit_card_luhn_v1"
    }

    fn entity_type(&self) -> EntityType {
        EntityType::CreditCard
    }

    fn supported_locales(&self) -> &[Locale] {
        &[]
    }

    fn scan(&self, text: &str) -> Vec<PiiEntity> {
        CREDIT_CARD_REGEX
            .find_iter(text)
            .filter(|matched| self.is_valid_match(text, matched.start(), matched.end()))
            .map(|matched| PiiEntity {
                entity_type: self.entity_type(),
                span: Span::new(matched.start(), matched.end()),
                text: matched.as_str().trim().to_string(),
                confidence: compute_confidence(matched.as_str()),
                recognizer_id: self.id().to_string(),
            })
            .collect()
    }

    fn validate(&self, candidate: &str) -> bool {
        let digits = digits(candidate);
        (13..=19).contains(&digits.len()) && luhn_valid(&digits)
    }
}

impl CreditCardRecognizer {
    fn is_valid_match(&self, text: &str, start: usize, end: usize) -> bool {
        self.validate(&text[start..end])
            && !continues_number_backwards(&text[..start])
            && !continues_number_forwards(&text[end..])
    }
}

fn continues_number_backwards(prefix: &str) -> bool {
    let mut chars = prefix.chars().rev();
    match chars.next() {
        Some(c) if c.is_ascii_digit() => true,
        Some(' ' | '-' | '.') => chars.next().is_some_and(|c| c.is_ascii_digit()),
        _ => false,
    }
}

fn continues_number_forwards(suffix: &str) -> bool {
    let mut chars = suffix.chars();
    match chars.next() {
        Some(c) if c.is_ascii_digit() => true,
        Some(' ' | '-' | '.') => chars.next().is_some_and(|c| c.is_ascii_digit()),
        _ => false,
    }
}

fn compute_confidence(candidate: &str) -> Confidence {
    let digits = digits(candidate);
    if card_brand(&digits).is_some() {
        confidence(0.99)
    } else {
        confidence(0.60)
    }
}

/// Returns true when the supplied digits pass the Luhn checksum.
#[must_use]
pub fn luhn_valid(value: &str) -> bool {
    let digits: Vec<u32> = value.chars().filter_map(|c| c.to_digit(10)).collect();
    if digits.len() < 13 {
        return false;
    }

    let mut sum = 0u32;
    let mut double = false;
    for digit in digits.iter().rev() {
        let mut value = *digit;
        if double {
            value *= 2;
            if value > 9 {
                value -= 9;
            }
        }
        sum += value;
        double = !double;
    }
    sum % 10 == 0
}

/// Identifies common payment card brand families from card digits.
#[must_use]
pub fn card_brand(digits: &str) -> Option<CardBrand> {
    if digits.starts_with('4') && (13..=19).contains(&digits.len()) {
        return Some(CardBrand::Visa);
    }
    if digits.len() == 15 && (digits.starts_with("34") || digits.starts_with("37")) {
        return Some(CardBrand::AmericanExpress);
    }
    if digits.len() == 16 && (digits.starts_with("6011") || digits.starts_with("65")) {
        return Some(CardBrand::Discover);
    }
    if digits.len() == 16 {
        let prefix2 = digits[..2].parse::<u32>().ok();
        let prefix4 = digits[..4].parse::<u32>().ok();
        if prefix2.is_some_and(|prefix| (51..=55).contains(&prefix))
            || prefix4.is_some_and(|prefix| (2221..=2720).contains(&prefix))
        {
            return Some(CardBrand::Mastercard);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn texts(input: &str) -> Vec<String> {
        CreditCardRecognizer
            .scan(input)
            .into_iter()
            .map(|finding| finding.text)
            .collect()
    }

    #[test]
    fn test_credit_card_visa_spaces_detected() {
        assert_eq!(texts("card 4111 1111 1111 1111"), ["4111 1111 1111 1111"]);
    }

    #[test]
    fn test_credit_card_visa_dashes_detected() {
        assert_eq!(texts("4111-1111-1111-1111"), ["4111-1111-1111-1111"]);
    }

    #[test]
    fn test_credit_card_visa_plain_detected() {
        assert_eq!(texts("4111111111111111"), ["4111111111111111"]);
    }

    #[test]
    fn test_credit_card_amex_detected() {
        assert_eq!(texts("3782 822463 10005"), ["3782 822463 10005"]);
    }

    #[test]
    fn test_credit_card_mastercard_detected() {
        assert_eq!(texts("5555 5555 5555 4444"), ["5555 5555 5555 4444"]);
    }

    #[test]
    fn test_credit_card_invalid_luhn_rejected() {
        assert!(texts("4111 1111 1111 1112").is_empty());
    }

    #[test]
    fn test_credit_card_short_sequence_rejected() {
        assert!(texts("1234 5678").is_empty());
    }

    #[test]
    fn test_credit_card_luhn_valid_accepts_test_card() {
        assert!(luhn_valid("4111111111111111"));
    }

    #[test]
    fn test_credit_card_brand_identifies_visa() {
        assert_eq!(card_brand("4111111111111111"), Some(CardBrand::Visa));
    }

    #[test]
    fn test_credit_card_brand_identifies_mastercard_2_series() {
        assert_eq!(card_brand("2221000000000009"), Some(CardBrand::Mastercard));
    }

    #[test]
    fn test_credit_card_discover_detected() {
        assert_eq!(texts("6011 1111 1111 1117"), ["6011 1111 1111 1117"]);
    }

    #[test]
    fn test_credit_card_mastercard_2_series_detected() {
        assert_eq!(texts("2221 0000 0000 0009"), ["2221 0000 0000 0009"]);
    }

    #[test]
    fn test_credit_card_amex_compact_detected() {
        assert_eq!(texts("371449635398431"), ["371449635398431"]);
    }

    #[test]
    fn test_credit_card_dotted_detected() {
        assert_eq!(texts("4111.1111.1111.1111"), ["4111.1111.1111.1111"]);
    }

    #[test]
    fn test_credit_card_visa_13_digit_detected() {
        assert_eq!(texts("4222222222222"), ["4222222222222"]);
    }

    #[test]
    fn test_credit_card_random_16_digits_rejected() {
        assert!(texts("1234 5678 9012 3456").is_empty());
    }

    #[test]
    fn test_credit_card_too_long_rejected() {
        assert!(texts("4111 1111 1111 1111 1111").is_empty());
    }

    #[test]
    fn test_credit_card_embedded_in_word_not_detected() {
        assert!(texts("id4111111111111111").is_empty());
    }

    #[test]
    fn test_credit_card_brand_identifies_amex() {
        assert_eq!(
            card_brand("378282246310005"),
            Some(CardBrand::AmericanExpress)
        );
    }

    #[test]
    fn test_credit_card_brand_identifies_discover() {
        assert_eq!(card_brand("6011111111111117"), Some(CardBrand::Discover));
    }

    #[test]
    fn test_credit_card_brand_returns_none_for_unknown() {
        assert_eq!(card_brand("9011111111111111"), None);
    }

    #[test]
    fn test_credit_card_luhn_rejects_invalid_check_digit() {
        assert!(!luhn_valid("4111111111111112"));
    }

    #[test]
    fn test_credit_card_validate_accepts_separators() {
        assert!(CreditCardRecognizer.validate("4111-1111-1111-1111"));
    }

    #[test]
    fn test_credit_card_validate_rejects_letters() {
        assert!(!CreditCardRecognizer.validate("4111-1111-1111-ABCD"));
    }

    #[test]
    fn test_credit_card_known_brand_confidence_is_high() {
        let finding = CreditCardRecognizer.scan("4111 1111 1111 1111");
        assert_eq!(finding[0].confidence.value(), 0.99);
    }
}
