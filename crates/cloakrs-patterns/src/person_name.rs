use crate::common::{compile_regex, confidence, context_boost};
use cloakrs_core::{Confidence, EntityType, Locale, PiiEntity, Recognizer, Span};
use once_cell::sync::Lazy;
use regex::Regex;

static PERSON_NAME_REGEX: Lazy<Regex> = Lazy::new(|| {
    compile_regex(
        r"\b(?:(?:Mr|Mrs|Ms|Dr)\.?\s+)?([A-Z][a-z]{1,24})(?:\s+[A-Z]\.)?\s+([A-Z][a-z]{1,24}(?:[-'][A-Z][a-z]{1,24})?)\b",
    )
});

const CONTEXT_WORDS: &[&str] = &[
    "name",
    "customer",
    "client",
    "patient",
    "employee",
    "user",
    "contact",
    "person",
    "account holder",
    "full name",
    "signed by",
    "author",
    "recipient",
    "sender",
    "attn",
    "dear",
    "mr",
    "mrs",
    "ms",
    "dr",
];

const FIRST_NAMES: &[&str] = &[
    "aaron",
    "adam",
    "alex",
    "alice",
    "anna",
    "anthony",
    "barbara",
    "benjamin",
    "brian",
    "carla",
    "charles",
    "chris",
    "christopher",
    "daniel",
    "david",
    "elizabeth",
    "emily",
    "emma",
    "eric",
    "fatima",
    "george",
    "hannah",
    "isabella",
    "james",
    "jane",
    "jan",
    "jennifer",
    "john",
    "jose",
    "joseph",
    "julia",
    "kadir",
    "laura",
    "linda",
    "lisa",
    "maria",
    "mark",
    "mary",
    "michael",
    "mohammed",
    "nancy",
    "olivia",
    "patricia",
    "paul",
    "peter",
    "robert",
    "sarah",
    "susan",
    "thomas",
    "william",
];

const LAST_NAMES: &[&str] = &[
    "adams",
    "anderson",
    "brown",
    "clark",
    "davis",
    "evans",
    "garcia",
    "green",
    "hall",
    "harris",
    "jackson",
    "johnson",
    "jones",
    "khan",
    "lee",
    "lewis",
    "martin",
    "martinez",
    "miller",
    "moore",
    "nguyen",
    "patel",
    "perez",
    "roberts",
    "rodriguez",
    "sanchez",
    "smith",
    "taylor",
    "thomas",
    "thompson",
    "walker",
    "white",
    "williams",
    "wilson",
    "wright",
    "young",
];

const NON_NAME_PHRASES: &[&str] = &[
    "api key",
    "aws access",
    "credit card",
    "date of",
    "not found",
    "user path",
    "physical address",
    "social security",
    "json web",
    "united states",
    "new york",
    "san francisco",
    "los angeles",
];

/// Recognizes common person names using a conservative dictionary-backed heuristic.
///
/// # Examples
///
/// ```
/// use cloakrs_core::{EntityType, Recognizer};
/// use cloakrs_patterns::PersonNameRecognizer;
///
/// let findings = PersonNameRecognizer.scan("customer name John Smith");
/// assert_eq!(findings[0].entity_type, EntityType::PersonName);
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct PersonNameRecognizer;

impl Recognizer for PersonNameRecognizer {
    fn id(&self) -> &str {
        "person_name_dictionary_v1"
    }

    fn entity_type(&self) -> EntityType {
        EntityType::PersonName
    }

    fn supported_locales(&self) -> &[Locale] {
        &[]
    }

    fn scan(&self, text: &str) -> Vec<PiiEntity> {
        PERSON_NAME_REGEX
            .captures_iter(text)
            .filter_map(|captures| {
                let matched = captures.get(0)?;
                let first = captures.get(1)?.as_str();
                let last = captures.get(2)?.as_str();
                if !self.validate_parts(first, last)
                    || !valid_boundary(text, matched.start(), matched.end())
                {
                    return None;
                }
                Some(PiiEntity {
                    entity_type: self.entity_type(),
                    span: Span::new(matched.start(), matched.end()),
                    text: matched.as_str().to_string(),
                    confidence: self.compute_confidence(text, matched.start(), first, last),
                    recognizer_id: self.id().to_string(),
                })
            })
            .collect()
    }

    fn validate(&self, candidate: &str) -> bool {
        let Some(captures) = PERSON_NAME_REGEX.captures(candidate) else {
            return false;
        };
        captures
            .get(0)
            .is_some_and(|matched| matched.as_str() == candidate)
            && captures
                .get(1)
                .zip(captures.get(2))
                .is_some_and(|(first, last)| self.validate_parts(first.as_str(), last.as_str()))
    }
}

impl PersonNameRecognizer {
    fn validate_parts(&self, first: &str, last: &str) -> bool {
        let phrase = format!(
            "{} {}",
            first.to_ascii_lowercase(),
            last.to_ascii_lowercase()
        );
        if NON_NAME_PHRASES.contains(&phrase.as_str()) {
            return false;
        }
        FIRST_NAMES.contains(&first.to_ascii_lowercase().as_str())
            && last
                .split(['-', '\''])
                .all(|part| LAST_NAMES.contains(&part.to_ascii_lowercase().as_str()))
    }

    fn compute_confidence(&self, text: &str, start: usize, first: &str, last: &str) -> Confidence {
        let boost = context_boost(text, start, CONTEXT_WORDS);
        let dictionary_strength = if first.len() >= 4 && last.len() >= 4 {
            0.08
        } else {
            0.0
        };
        confidence(0.42 + dictionary_strength + boost)
    }
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
        PersonNameRecognizer
            .scan(input)
            .into_iter()
            .map(|finding| finding.text)
            .collect()
    }

    #[test]
    fn test_person_name_john_smith_detected() {
        assert_eq!(texts("customer name John Smith"), ["John Smith"]);
    }

    #[test]
    fn test_person_name_jane_doe_like_dictionary_rejected() {
        assert!(texts("contact Jane Doe").is_empty());
    }

    #[test]
    fn test_person_name_middle_initial_detected() {
        assert_eq!(texts("patient John A. Smith"), ["John A. Smith"]);
    }

    #[test]
    fn test_person_name_hyphenated_last_detected() {
        assert_eq!(texts("client Maria Garcia-Smith"), ["Maria Garcia-Smith"]);
    }

    #[test]
    fn test_person_name_in_email_rejected() {
        assert!(texts("email john.smith@example.com").is_empty());
    }

    #[test]
    fn test_person_name_lowercase_rejected() {
        assert!(texts("customer john smith").is_empty());
    }

    #[test]
    fn test_person_name_non_dictionary_rejected() {
        assert!(texts("customer River Table").is_empty());
    }

    #[test]
    fn test_person_name_common_phrase_rejected() {
        assert!(texts("United States").is_empty());
    }

    #[test]
    fn test_person_name_embedded_word_rejected() {
        assert!(texts("xJohn Smithy").is_empty());
    }

    #[test]
    fn test_person_name_validate_accepts_known_name() {
        assert!(PersonNameRecognizer.validate("John Smith"));
    }

    #[test]
    fn test_person_name_validate_rejects_unknown_name() {
        assert!(!PersonNameRecognizer.validate("Blue Widget"));
    }

    #[test]
    fn test_person_name_context_boosts_confidence() {
        let with_context = PersonNameRecognizer.scan("customer name John Smith");
        let without_context = PersonNameRecognizer.scan("value John Smith");
        assert!(with_context[0].confidence > without_context[0].confidence);
    }

    #[test]
    fn test_person_name_title_context_boosts_confidence() {
        let with_context = PersonNameRecognizer.scan("Dr. John Smith");
        let without_context = PersonNameRecognizer.scan("value John Smith");
        assert!(with_context[0].confidence > without_context[0].confidence);
    }

    #[test]
    fn test_person_name_supported_locales_are_universal() {
        assert!(PersonNameRecognizer.supported_locales().is_empty());
    }

    #[test]
    fn test_person_name_entity_type_is_person_name() {
        assert_eq!(PersonNameRecognizer.entity_type(), EntityType::PersonName);
    }
}
