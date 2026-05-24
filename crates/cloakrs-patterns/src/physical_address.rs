use crate::common::{compile_regex, confidence, context_boost};
use cloakrs_core::{Confidence, EntityType, Locale, PiiEntity, Recognizer, Span};
use once_cell::sync::Lazy;
use regex::Regex;

static ADDRESS_REGEX: Lazy<Regex> = Lazy::new(|| {
    compile_regex(
        r"(?x)
        \b
        \d{1,6}
        \s+
        (?:[A-Z][a-z0-9.'-]*\s+){1,4}
        (?:St|Street|Ave|Avenue|Blvd|Boulevard|Rd|Road|Dr|Drive|Ln|Lane|Ct|Court|Way|Pl|Place|Terrace|Ter|Circle|Cir|Parkway|Pkwy)
        \.?
        (?:\s+(?:Apt|Apartment|Suite|Ste|Unit|\#)\s*[A-Za-z0-9-]+)?
        (?:,\s*[A-Z][a-zA-Z .'-]+)?
        (?:,\s*[A-Z]{2})?
        (?:\s+\d{5}(?:-\d{4})?)?
        \b",
    )
});

const CONTEXT_WORDS: &[&str] = &[
    "address",
    "street",
    "ship to",
    "billing",
    "mailing",
    "residence",
    "home",
    "office",
    "located at",
    "deliver",
    "recipient",
];

/// Recognizes physical street addresses with a US-first rule-based pattern.
///
/// # Examples
///
/// ```
/// use cloakrs_core::{EntityType, Recognizer};
/// use cloakrs_patterns::PhysicalAddressRecognizer;
///
/// let findings = PhysicalAddressRecognizer.scan("ship to 123 Main St, Springfield, IL 62704");
/// assert_eq!(findings[0].entity_type, EntityType::PhysicalAddress);
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct PhysicalAddressRecognizer;

impl Recognizer for PhysicalAddressRecognizer {
    fn id(&self) -> &str {
        "physical_address_us_v1"
    }

    fn entity_type(&self) -> EntityType {
        EntityType::PhysicalAddress
    }

    fn supported_locales(&self) -> &[Locale] {
        &[]
    }

    fn scan(&self, text: &str) -> Vec<PiiEntity> {
        ADDRESS_REGEX
            .find_iter(text)
            .filter_map(|matched| {
                let span = trim_span(text, Span::new(matched.start(), matched.end()));
                if span.is_empty() {
                    return None;
                }
                let candidate = &text[span.start..span.end];
                if !self.validate(candidate) || !valid_boundary(text, span.start, span.end) {
                    return None;
                }
                Some(PiiEntity {
                    entity_type: self.entity_type(),
                    span,
                    text: candidate.to_string(),
                    confidence: self.compute_confidence(text, span.start, candidate),
                    recognizer_id: self.id().to_string(),
                })
            })
            .collect()
    }

    fn validate(&self, candidate: &str) -> bool {
        let lower = candidate.to_ascii_lowercase();
        has_street_type(&lower)
            && candidate.chars().any(|c| c.is_ascii_digit())
            && candidate.split_whitespace().count() >= 3
            && !lower.contains(" not found ")
    }
}

impl PhysicalAddressRecognizer {
    fn compute_confidence(&self, text: &str, start: usize, candidate: &str) -> Confidence {
        let lower = candidate.to_ascii_lowercase();
        let city_state_zip_boost = if lower.contains(',') || has_zip(candidate) {
            0.08
        } else {
            0.0
        };
        confidence(0.70 + city_state_zip_boost + context_boost(text, start, CONTEXT_WORDS))
    }
}

fn has_street_type(lower: &str) -> bool {
    [
        " st",
        " street",
        " ave",
        " avenue",
        " blvd",
        " boulevard",
        " rd",
        " road",
        " dr",
        " drive",
        " ln",
        " lane",
        " ct",
        " court",
        " way",
        " pl",
        " place",
        " terrace",
        " ter",
        " circle",
        " cir",
        " parkway",
        " pkwy",
    ]
    .iter()
    .any(|street_type| lower.contains(street_type))
}

fn has_zip(candidate: &str) -> bool {
    candidate
        .split_whitespace()
        .any(|part| part.len() == 5 && part.chars().all(|c| c.is_ascii_digit()))
}

fn trim_span(text: &str, span: Span) -> Span {
    let mut end = span.end;
    while end > span.start {
        let Some(ch) = text[span.start..end].chars().next_back() else {
            break;
        };
        if matches!(ch, '.' | ',' | ';' | ')' | ']') {
            end -= ch.len_utf8();
        } else {
            break;
        }
    }
    Span::new(span.start, end)
}

fn valid_boundary(text: &str, start: usize, end: usize) -> bool {
    let before = text[..start].chars().next_back();
    let after = text[end..].chars().next();
    !before.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
        && !after.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn texts(input: &str) -> Vec<String> {
        PhysicalAddressRecognizer
            .scan(input)
            .into_iter()
            .map(|finding| finding.text)
            .collect()
    }

    #[test]
    fn test_physical_address_simple_street_detected() {
        assert_eq!(texts("address 123 Main St"), ["123 Main St"]);
    }

    #[test]
    fn test_physical_address_full_us_address_detected() {
        assert_eq!(
            texts("ship to 123 Main Street, Springfield, IL 62704"),
            ["123 Main Street, Springfield, IL 62704"]
        );
    }

    #[test]
    fn test_physical_address_apartment_detected() {
        assert_eq!(
            texts("billing 55 Market Ave Apt 4B"),
            ["55 Market Ave Apt 4B"]
        );
    }

    #[test]
    fn test_physical_address_hash_unit_detected() {
        assert_eq!(texts("office 9 Oak Road #12"), ["9 Oak Road #12"]);
    }

    #[test]
    fn test_physical_address_boulevard_detected() {
        assert_eq!(texts("home 700 Sunset Blvd"), ["700 Sunset Blvd"]);
    }

    #[test]
    fn test_physical_address_no_number_rejected() {
        assert!(texts("Main Street").is_empty());
    }

    #[test]
    fn test_physical_address_no_street_type_rejected() {
        assert!(texts("123 Main Building").is_empty());
    }

    #[test]
    fn test_physical_address_lowercase_street_name_rejected() {
        assert!(texts("address 123 main st").is_empty());
    }

    #[test]
    fn test_physical_address_embedded_word_rejected() {
        assert!(texts("x123 Main Sty").is_empty());
    }

    #[test]
    fn test_physical_address_trailing_punctuation_trimmed() {
        assert_eq!(texts("address 123 Main St."), ["123 Main St"]);
    }

    #[test]
    fn test_physical_address_validate_accepts_address() {
        assert!(PhysicalAddressRecognizer.validate("123 Main St"));
    }

    #[test]
    fn test_physical_address_validate_rejects_sentence() {
        assert!(!PhysicalAddressRecognizer.validate("123 Main Building"));
    }

    #[test]
    fn test_physical_address_context_boosts_confidence() {
        let with_context = PhysicalAddressRecognizer.scan("mailing address 123 Main St");
        let without_context = PhysicalAddressRecognizer.scan("value 123 Main St");
        assert!(with_context[0].confidence > without_context[0].confidence);
    }

    #[test]
    fn test_physical_address_zip_boosts_confidence() {
        let with_zip = PhysicalAddressRecognizer.scan("value 123 Main St 62704");
        let without_zip = PhysicalAddressRecognizer.scan("value 123 Main St");
        assert!(with_zip[0].confidence > without_zip[0].confidence);
    }

    #[test]
    fn test_physical_address_supported_locales_are_universal() {
        assert!(PhysicalAddressRecognizer.supported_locales().is_empty());
    }
}
