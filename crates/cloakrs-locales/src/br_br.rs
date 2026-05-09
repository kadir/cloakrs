//! Brazilian locale recognizers.

use crate::common::{compile_regex, confidence, context_boost, digits, is_boundary};
use cloakrs_core::{Confidence, EntityType, Locale, PiiEntity, Recognizer, Span};
use once_cell::sync::Lazy;
use regex::Regex;

static CPF_REGEX: Lazy<Regex> =
    Lazy::new(|| compile_regex(r"\b(?:\d{3}\.\d{3}\.\d{3}-\d{2}|\d{11})\b"));
static CNPJ_REGEX: Lazy<Regex> =
    Lazy::new(|| compile_regex(r"\b(?:\d{2}\.\d{3}\.\d{3}/\d{4}-\d{2}|\d{14})\b"));
static BR_LOCALES: &[Locale] = &[Locale::BR];

const CPF_CONTEXT_WORDS: &[&str] = &["cpf", "cadastro de pessoas fisicas", "taxpayer"];
const CNPJ_CONTEXT_WORDS: &[&str] = &["cnpj", "cadastro nacional", "pessoa juridica"];

/// Recognizes Brazilian CPF numbers with two check digits.
///
/// # Examples
///
/// ```
/// use cloakrs_core::Recognizer;
/// use cloakrs_locales::CpfRecognizer;
///
/// let findings = CpfRecognizer.scan("CPF 529.982.247-25");
/// assert_eq!(findings.len(), 1);
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct CpfRecognizer;

impl Recognizer for CpfRecognizer {
    fn id(&self) -> &str {
        "br_cpf_mod11_v1"
    }

    fn entity_type(&self) -> EntityType {
        EntityType::Cpf
    }

    fn supported_locales(&self) -> &[Locale] {
        BR_LOCALES
    }

    fn scan(&self, text: &str) -> Vec<PiiEntity> {
        CPF_REGEX
            .find_iter(text)
            .filter(|matched| self.is_valid_match(text, matched.start(), matched.end()))
            .map(|matched| PiiEntity {
                entity_type: self.entity_type(),
                span: Span::new(matched.start(), matched.end()),
                text: matched.as_str().to_string(),
                confidence: compute_cpf_confidence(text, matched.start(), matched.end()),
                recognizer_id: self.id().to_string(),
            })
            .collect()
    }

    fn validate(&self, candidate: &str) -> bool {
        let digits = digits(candidate);
        digits.len() == 11 && !all_same_digit(&digits) && cpf_check_digits_valid(&digits)
    }
}

impl CpfRecognizer {
    fn is_valid_match(&self, text: &str, start: usize, end: usize) -> bool {
        self.validate(&text[start..end])
            && is_boundary(text, start, end)
            && !has_separated_digit_before(text, start)
            && !has_separated_digit_after(text, end)
    }
}

/// Recognizes Brazilian CNPJ numbers with two check digits.
///
/// # Examples
///
/// ```
/// use cloakrs_core::Recognizer;
/// use cloakrs_locales::CnpjRecognizer;
///
/// let findings = CnpjRecognizer.scan("CNPJ 11.222.333/0001-81");
/// assert_eq!(findings.len(), 1);
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct CnpjRecognizer;

impl Recognizer for CnpjRecognizer {
    fn id(&self) -> &str {
        "br_cnpj_mod11_v1"
    }

    fn entity_type(&self) -> EntityType {
        EntityType::Cnpj
    }

    fn supported_locales(&self) -> &[Locale] {
        BR_LOCALES
    }

    fn scan(&self, text: &str) -> Vec<PiiEntity> {
        CNPJ_REGEX
            .find_iter(text)
            .filter(|matched| self.is_valid_match(text, matched.start(), matched.end()))
            .map(|matched| PiiEntity {
                entity_type: self.entity_type(),
                span: Span::new(matched.start(), matched.end()),
                text: matched.as_str().to_string(),
                confidence: compute_cnpj_confidence(text, matched.start(), matched.end()),
                recognizer_id: self.id().to_string(),
            })
            .collect()
    }

    fn validate(&self, candidate: &str) -> bool {
        let digits = digits(candidate);
        digits.len() == 14 && !all_same_digit(&digits) && cnpj_check_digits_valid(&digits)
    }
}

impl CnpjRecognizer {
    fn is_valid_match(&self, text: &str, start: usize, end: usize) -> bool {
        self.validate(&text[start..end])
            && is_boundary(text, start, end)
            && !has_separated_digit_before(text, start)
            && !has_separated_digit_after(text, end)
    }
}

fn compute_cpf_confidence(text: &str, start: usize, end: usize) -> Confidence {
    confidence(0.65 + context_boost(text, Span::new(start, end), CPF_CONTEXT_WORDS))
}

fn compute_cnpj_confidence(text: &str, start: usize, end: usize) -> Confidence {
    confidence(0.70 + context_boost(text, Span::new(start, end), CNPJ_CONTEXT_WORDS))
}

fn cpf_check_digits_valid(value: &str) -> bool {
    let bytes = value.as_bytes();
    let first = mod11_check_digit(&bytes[..9], 10);
    let second = mod11_check_digit(&bytes[..10], 11);
    first == bytes[9] - b'0' && second == bytes[10] - b'0'
}

fn cnpj_check_digits_valid(value: &str) -> bool {
    const FIRST_WEIGHTS: &[u8] = &[5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2];
    const SECOND_WEIGHTS: &[u8] = &[6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2];

    let bytes = value.as_bytes();
    let first = weighted_mod11_check_digit(&bytes[..12], FIRST_WEIGHTS);
    let second = weighted_mod11_check_digit(&bytes[..13], SECOND_WEIGHTS);
    first == bytes[12] - b'0' && second == bytes[13] - b'0'
}

fn mod11_check_digit(digits: &[u8], start_weight: u8) -> u8 {
    let sum: u32 = digits
        .iter()
        .enumerate()
        .map(|(index, byte)| u32::from(byte - b'0') * u32::from(start_weight - index as u8))
        .sum();
    check_digit_from_mod11_sum(sum)
}

fn weighted_mod11_check_digit(digits: &[u8], weights: &[u8]) -> u8 {
    let sum: u32 = digits
        .iter()
        .zip(weights.iter())
        .map(|(byte, weight)| u32::from(byte - b'0') * u32::from(*weight))
        .sum();
    check_digit_from_mod11_sum(sum)
}

fn check_digit_from_mod11_sum(sum: u32) -> u8 {
    let remainder = sum % 11;
    if remainder < 2 {
        0
    } else {
        (11 - remainder) as u8
    }
}

fn all_same_digit(value: &str) -> bool {
    value
        .as_bytes()
        .first()
        .is_some_and(|first| value.as_bytes().iter().all(|byte| byte == first))
}

fn has_separated_digit_before(text: &str, start: usize) -> bool {
    let mut chars = text[..start].chars().rev();
    matches!(chars.next(), Some(' ' | '-' | '.' | '/'))
        && chars.next().is_some_and(|c| c.is_ascii_digit())
}

fn has_separated_digit_after(text: &str, end: usize) -> bool {
    let mut chars = text[end..].chars();
    matches!(chars.next(), Some(' ' | '-' | '.' | '/'))
        && chars.next().is_some_and(|c| c.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cloakrs_core::RecognizerRegistry;

    fn cpf_texts(input: &str) -> Vec<String> {
        CpfRecognizer
            .scan(input)
            .into_iter()
            .map(|finding| finding.text)
            .collect()
    }

    fn cnpj_texts(input: &str) -> Vec<String> {
        CnpjRecognizer
            .scan(input)
            .into_iter()
            .map(|finding| finding.text)
            .collect()
    }

    #[test]
    fn test_cpf_formatted_value_detected() {
        assert_eq!(cpf_texts("CPF 529.982.247-25"), ["529.982.247-25"]);
    }

    #[test]
    fn test_cpf_compact_value_detected() {
        assert_eq!(cpf_texts("CPF 52998224725"), ["52998224725"]);
    }

    #[test]
    fn test_cpf_second_valid_value_detected() {
        assert_eq!(
            cpf_texts("cadastro de pessoas fisicas 11144477735"),
            ["11144477735"]
        );
    }

    #[test]
    fn test_cpf_multiple_values_detected() {
        assert_eq!(
            cpf_texts("CPF 529.982.247-25 and taxpayer 93541134780"),
            ["529.982.247-25", "93541134780"]
        );
    }

    #[test]
    fn test_cpf_invalid_checksum_rejected() {
        assert!(cpf_texts("CPF 529.982.247-26").is_empty());
    }

    #[test]
    fn test_cpf_repeated_digits_rejected() {
        assert!(cpf_texts("CPF 111.111.111-11").is_empty());
    }

    #[test]
    fn test_cpf_too_short_rejected() {
        assert!(cpf_texts("CPF 529.982.247-2").is_empty());
    }

    #[test]
    fn test_cpf_too_long_rejected() {
        assert!(cpf_texts("CPF 529.982.247-25 9").is_empty());
    }

    #[test]
    fn test_cpf_letters_rejected() {
        assert!(cpf_texts("CPF 529.982.247-2A").is_empty());
    }

    #[test]
    fn test_cpf_embedded_in_word_rejected() {
        assert!(cpf_texts("id52998224725").is_empty());
    }

    #[test]
    fn test_cpf_trailing_word_rejected() {
        assert!(cpf_texts("52998224725id").is_empty());
    }

    #[test]
    fn test_cpf_context_before_boosts_confidence() {
        let with_context = CpfRecognizer.scan("CPF 529.982.247-25");
        let without_context = CpfRecognizer.scan("value 529.982.247-25");
        assert!(with_context[0].confidence > without_context[0].confidence);
    }

    #[test]
    fn test_cpf_context_after_boosts_confidence() {
        let with_context = CpfRecognizer.scan("529.982.247-25 taxpayer");
        let without_context = CpfRecognizer.scan("529.982.247-25 value");
        assert!(with_context[0].confidence > without_context[0].confidence);
    }

    #[test]
    fn test_cpf_supported_locale_is_br() {
        assert_eq!(CpfRecognizer.supported_locales(), &[Locale::BR]);
    }

    #[test]
    fn test_cnpj_formatted_value_detected() {
        assert_eq!(
            cnpj_texts("CNPJ 11.222.333/0001-81"),
            ["11.222.333/0001-81"]
        );
    }

    #[test]
    fn test_cnpj_compact_value_detected() {
        assert_eq!(cnpj_texts("CNPJ 11222333000181"), ["11222333000181"]);
    }

    #[test]
    fn test_cnpj_second_valid_value_detected() {
        assert_eq!(
            cnpj_texts("cadastro nacional 04.252.011/0001-10"),
            ["04.252.011/0001-10"]
        );
    }

    #[test]
    fn test_cnpj_multiple_values_detected() {
        assert_eq!(
            cnpj_texts("CNPJ 11.222.333/0001-81 and 12.345.678/0001-95"),
            ["11.222.333/0001-81", "12.345.678/0001-95"]
        );
    }

    #[test]
    fn test_cnpj_invalid_checksum_rejected() {
        assert!(cnpj_texts("CNPJ 11.222.333/0001-82").is_empty());
    }

    #[test]
    fn test_cnpj_repeated_digits_rejected() {
        assert!(cnpj_texts("CNPJ 11.111.111/1111-11").is_empty());
    }

    #[test]
    fn test_cnpj_too_short_rejected() {
        assert!(cnpj_texts("CNPJ 11.222.333/0001-8").is_empty());
    }

    #[test]
    fn test_cnpj_too_long_rejected() {
        assert!(cnpj_texts("CNPJ 11.222.333/0001-81 9").is_empty());
    }

    #[test]
    fn test_cnpj_letters_rejected() {
        assert!(cnpj_texts("CNPJ 11.222.333/0001-8A").is_empty());
    }

    #[test]
    fn test_cnpj_embedded_in_word_rejected() {
        assert!(cnpj_texts("id11222333000181").is_empty());
    }

    #[test]
    fn test_cnpj_trailing_word_rejected() {
        assert!(cnpj_texts("11222333000181id").is_empty());
    }

    #[test]
    fn test_cnpj_context_before_boosts_confidence() {
        let with_context = CnpjRecognizer.scan("CNPJ 11.222.333/0001-81");
        let without_context = CnpjRecognizer.scan("value 11.222.333/0001-81");
        assert!(with_context[0].confidence > without_context[0].confidence);
    }

    #[test]
    fn test_cnpj_context_after_boosts_confidence() {
        let with_context = CnpjRecognizer.scan("11.222.333/0001-81 pessoa juridica");
        let without_context = CnpjRecognizer.scan("11.222.333/0001-81 value");
        assert!(with_context[0].confidence > without_context[0].confidence);
    }

    #[test]
    fn test_cnpj_supported_locale_is_br() {
        assert_eq!(CnpjRecognizer.supported_locales(), &[Locale::BR]);
    }

    #[test]
    fn test_brazil_registry_with_br_locale_detects_both_entities() {
        let mut registry = RecognizerRegistry::new();
        registry.register(CpfRecognizer);
        registry.register(CnpjRecognizer);
        let findings = registry.scan_locale(
            "CPF 529.982.247-25 and CNPJ 11.222.333/0001-81",
            &Locale::BR,
        );
        assert_eq!(findings.len(), 2);
        assert_eq!(
            registry
                .scan_locale(
                    "CPF 529.982.247-25 and CNPJ 11.222.333/0001-81",
                    &Locale::Universal
                )
                .len(),
            0
        );
    }
}
