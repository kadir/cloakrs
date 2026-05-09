use crate::common::{alphanumeric_upper, compile_regex, confidence, context_boost};
use cloakrs_core::{Confidence, EntityType, Locale, PiiEntity, Recognizer, Span};
use once_cell::sync::Lazy;
use regex::Regex;

static IBAN_REGEX: Lazy<Regex> =
    Lazy::new(|| compile_regex(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]){11,30}\b"));

const CONTEXT_WORDS: &[&str] = &["iban", "account", "bank", "transfer", "wire", "swift"];

/// Recognizes International Bank Account Numbers with MOD-97 validation.
#[derive(Debug, Clone, Copy, Default)]
pub struct IbanRecognizer;

impl Recognizer for IbanRecognizer {
    fn id(&self) -> &str {
        "iban_mod97_v1"
    }

    fn entity_type(&self) -> EntityType {
        EntityType::Iban
    }

    fn supported_locales(&self) -> &[Locale] {
        &[]
    }

    fn scan(&self, text: &str) -> Vec<PiiEntity> {
        IBAN_REGEX
            .find_iter(text)
            .filter(|matched| self.validate(matched.as_str()))
            .map(|matched| {
                let normalized = alphanumeric_upper(matched.as_str());
                PiiEntity {
                    entity_type: self.entity_type(),
                    span: Span::new(matched.start(), matched.end()),
                    text: matched.as_str().to_string(),
                    confidence: compute_confidence(text, matched.start(), &normalized),
                    recognizer_id: self.id().to_string(),
                }
            })
            .collect()
    }

    fn validate(&self, candidate: &str) -> bool {
        let normalized = alphanumeric_upper(candidate);
        has_country_length(&normalized) && iban_mod97_valid(&normalized)
    }
}

fn compute_confidence(text: &str, start: usize, normalized: &str) -> Confidence {
    let base = if has_country_length(normalized) && iban_mod97_valid(normalized) {
        0.99
    } else {
        0.50
    };
    confidence(base + context_boost(text, start, CONTEXT_WORDS))
}

fn has_country_length(normalized: &str) -> bool {
    normalized
        .get(..2)
        .and_then(iban_country_length)
        .is_some_and(|length| normalized.len() == length)
}

/// Returns the expected IBAN length for supported countries.
#[must_use]
pub fn iban_country_length(country: &str) -> Option<usize> {
    match country {
        "AD" => Some(24),
        "AE" => Some(23),
        "AL" => Some(28),
        "AT" => Some(20),
        "AZ" => Some(28),
        "BA" => Some(20),
        "BE" => Some(16),
        "BG" => Some(22),
        "BH" => Some(22),
        "BR" => Some(29),
        "CH" => Some(21),
        "CR" => Some(22),
        "CY" => Some(28),
        "CZ" => Some(24),
        "DE" => Some(22),
        "DK" => Some(18),
        "DO" => Some(28),
        "EE" => Some(20),
        "ES" => Some(24),
        "FI" => Some(18),
        "FO" => Some(18),
        "FR" => Some(27),
        "GB" => Some(22),
        "GE" => Some(22),
        "GI" => Some(23),
        "GL" => Some(18),
        "GR" => Some(27),
        "GT" => Some(28),
        "HR" => Some(21),
        "HU" => Some(28),
        "IE" => Some(22),
        "IL" => Some(23),
        "IS" => Some(26),
        "IT" => Some(27),
        "KW" => Some(30),
        "KZ" => Some(20),
        "LB" => Some(28),
        "LI" => Some(21),
        "LT" => Some(20),
        "LU" => Some(20),
        "LV" => Some(21),
        "MC" => Some(27),
        "MD" => Some(24),
        "ME" => Some(22),
        "MK" => Some(19),
        "MR" => Some(27),
        "MT" => Some(31),
        "MU" => Some(30),
        "NL" => Some(18),
        "NO" => Some(15),
        "PK" => Some(24),
        "PL" => Some(28),
        "PS" => Some(29),
        "PT" => Some(25),
        "QA" => Some(29),
        "RO" => Some(24),
        "RS" => Some(22),
        "SA" => Some(24),
        "SE" => Some(24),
        "SI" => Some(19),
        "SK" => Some(24),
        "SM" => Some(27),
        "TN" => Some(24),
        "TR" => Some(26),
        "UA" => Some(29),
        "VG" => Some(24),
        _ => None,
    }
}

/// Returns true when an IBAN passes ISO 13616 MOD-97 validation.
#[must_use]
pub fn iban_mod97_valid(normalized: &str) -> bool {
    if normalized.len() < 4 {
        return false;
    }
    let rearranged = format!("{}{}", &normalized[4..], &normalized[..4]);
    let mut remainder = 0u32;

    for c in rearranged.chars() {
        if c.is_ascii_digit() {
            let Some(digit) = c.to_digit(10) else {
                return false;
            };
            remainder = (remainder * 10 + digit) % 97;
        } else if c.is_ascii_uppercase() {
            let value = c as u32 - 'A' as u32 + 10;
            remainder = (remainder * 100 + value) % 97;
        } else {
            return false;
        }
    }

    remainder == 1
}

#[cfg(test)]
mod tests {
    use super::*;

    fn texts(input: &str) -> Vec<String> {
        IbanRecognizer
            .scan(input)
            .into_iter()
            .map(|finding| finding.text)
            .collect()
    }

    #[test]
    fn test_iban_de_with_spaces_detected() {
        assert_eq!(
            texts("IBAN DE89 3704 0044 0532 0130 00"),
            ["DE89 3704 0044 0532 0130 00"]
        );
    }

    #[test]
    fn test_iban_nl_without_spaces_detected() {
        assert_eq!(texts("NL91ABNA0417164300"), ["NL91ABNA0417164300"]);
    }

    #[test]
    fn test_iban_gb_with_spaces_detected() {
        assert_eq!(
            texts("GB29 NWBK 6016 1331 9268 19"),
            ["GB29 NWBK 6016 1331 9268 19"]
        );
    }

    #[test]
    fn test_iban_invalid_checksum_rejected() {
        assert!(texts("DE88 3704 0044 0532 0130 00").is_empty());
    }

    #[test]
    fn test_iban_invalid_country_length_rejected() {
        assert!(texts("DE89 3704 0044").is_empty());
    }

    #[test]
    fn test_iban_mod97_valid_accepts_known_example() {
        assert!(iban_mod97_valid("GB29NWBK60161331926819"));
    }

    #[test]
    fn test_iban_country_length_returns_expected_length() {
        assert_eq!(iban_country_length("NL"), Some(18));
    }

    #[test]
    fn test_iban_context_boosts_confidence() {
        let with_context = IbanRecognizer.scan("iban NL91ABNA0417164300");
        let without_context = IbanRecognizer.scan("value NL91ABNA0417164300");
        assert!(with_context[0].confidence >= without_context[0].confidence);
    }

    #[test]
    fn test_iban_fr_with_spaces_detected() {
        assert_eq!(
            texts("FR14 2004 1010 0505 0001 3M02 606"),
            ["FR14 2004 1010 0505 0001 3M02 606"]
        );
    }

    #[test]
    fn test_iban_be_detected() {
        assert_eq!(texts("BE68 5390 0754 7034"), ["BE68 5390 0754 7034"]);
    }

    #[test]
    fn test_iban_es_detected() {
        assert_eq!(
            texts("ES91 2100 0418 4502 0005 1332"),
            ["ES91 2100 0418 4502 0005 1332"]
        );
    }

    #[test]
    fn test_iban_it_detected() {
        assert_eq!(
            texts("IT60 X054 2811 1010 0000 0123 456"),
            ["IT60 X054 2811 1010 0000 0123 456"]
        );
    }

    #[test]
    fn test_iban_ch_detected() {
        assert_eq!(
            texts("CH93 0076 2011 6238 5295 7"),
            ["CH93 0076 2011 6238 5295 7"]
        );
    }

    #[test]
    fn test_iban_lowercase_not_detected() {
        assert!(texts("nl91abna0417164300").is_empty());
    }

    #[test]
    fn test_iban_unknown_country_rejected() {
        assert!(texts("ZZ91ABNA0417164300").is_empty());
    }

    #[test]
    fn test_iban_too_short_rejected() {
        assert!(texts("NL91 ABNA 0417").is_empty());
    }

    #[test]
    fn test_iban_mod97_rejects_known_bad_example() {
        assert!(!iban_mod97_valid("GB28NWBK60161331926819"));
    }

    #[test]
    fn test_iban_country_length_unknown_returns_none() {
        assert_eq!(iban_country_length("ZZ"), None);
    }

    #[test]
    fn test_iban_bank_context_boosts_confidence() {
        let with_context = IbanRecognizer.scan("bank NL91ABNA0417164300");
        let without_context = IbanRecognizer.scan("value NL91ABNA0417164300");
        assert!(with_context[0].confidence >= without_context[0].confidence);
    }

    #[test]
    fn test_iban_transfer_context_boosts_confidence() {
        let with_context = IbanRecognizer.scan("transfer NL91ABNA0417164300");
        let without_context = IbanRecognizer.scan("value NL91ABNA0417164300");
        assert!(with_context[0].confidence >= without_context[0].confidence);
    }
}
