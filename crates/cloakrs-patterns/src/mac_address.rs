use crate::common::{compile_regex, confidence, context_boost};
use cloakrs_core::{Confidence, EntityType, Locale, PiiEntity, Recognizer, Span};
use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashSet;

static MAC_COLON_HYPHEN_REGEX: Lazy<Regex> =
    Lazy::new(|| compile_regex(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b"));
static MAC_DOTTED_REGEX: Lazy<Regex> =
    Lazy::new(|| compile_regex(r"\b[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\b"));

const CONTEXT_WORDS: &[&str] = &[
    "mac",
    "mac address",
    "hardware address",
    "ethernet",
    "bssid",
    "adapter",
    "nic",
];

/// Recognizes MAC addresses in common colon, hyphen, and dotted forms.
///
/// # Examples
///
/// ```
/// use cloakrs_core::{EntityType, Recognizer};
/// use cloakrs_patterns::MacAddressRecognizer;
///
/// let findings = MacAddressRecognizer.scan("mac 00:1A:2B:3C:4D:5E");
/// assert_eq!(findings[0].entity_type, EntityType::MacAddress);
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct MacAddressRecognizer;

impl Recognizer for MacAddressRecognizer {
    fn id(&self) -> &str {
        "mac_address_regex_v1"
    }

    fn entity_type(&self) -> EntityType {
        EntityType::MacAddress
    }

    fn supported_locales(&self) -> &[Locale] {
        &[]
    }

    fn scan(&self, text: &str) -> Vec<PiiEntity> {
        let mut seen = HashSet::new();
        let mut findings = Vec::new();

        for regex in [&*MAC_COLON_HYPHEN_REGEX, &*MAC_DOTTED_REGEX] {
            for matched in regex.find_iter(text) {
                if seen.insert((matched.start(), matched.end()))
                    && self.is_valid_match(text, matched.start(), matched.end())
                {
                    findings.push(PiiEntity {
                        entity_type: self.entity_type(),
                        span: Span::new(matched.start(), matched.end()),
                        text: matched.as_str().to_string(),
                        confidence: self.compute_confidence(text, matched.start()),
                        recognizer_id: self.id().to_string(),
                    });
                }
            }
        }

        findings.sort_by_key(|finding| finding.span.start);
        findings
    }

    fn validate(&self, candidate: &str) -> bool {
        let normalized = normalized_hex(candidate);
        normalized.len() == 12 && normalized.chars().all(|c| c.is_ascii_hexdigit())
    }
}

impl MacAddressRecognizer {
    fn is_valid_match(&self, text: &str, start: usize, end: usize) -> bool {
        self.validate(&text[start..end]) && is_mac_boundary(text, start, end)
    }

    fn compute_confidence(&self, text: &str, start: usize) -> Confidence {
        confidence(0.82 + context_boost(text, start, CONTEXT_WORDS))
    }
}

fn normalized_hex(candidate: &str) -> String {
    candidate
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect()
}

fn is_mac_boundary(text: &str, start: usize, end: usize) -> bool {
    let before = text[..start].chars().next_back();
    let after = text[end..].chars().next();
    !before.is_some_and(is_mac_continuation) && !after.is_some_and(is_mac_continuation)
}

fn is_mac_continuation(c: char) -> bool {
    c.is_ascii_hexdigit() || matches!(c, ':' | '-' | '.')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::default_registry;

    fn texts(input: &str) -> Vec<String> {
        MacAddressRecognizer
            .scan(input)
            .into_iter()
            .map(|finding| finding.text)
            .collect()
    }

    #[test]
    fn test_mac_address_colon_uppercase_detected() {
        assert_eq!(texts("mac 00:1A:2B:3C:4D:5E"), ["00:1A:2B:3C:4D:5E"]);
    }

    #[test]
    fn test_mac_address_colon_lowercase_detected() {
        assert_eq!(texts("mac aa:bb:cc:dd:ee:ff"), ["aa:bb:cc:dd:ee:ff"]);
    }

    #[test]
    fn test_mac_address_hyphen_detected() {
        assert_eq!(texts("mac 00-1A-2B-3C-4D-5E"), ["00-1A-2B-3C-4D-5E"]);
    }

    #[test]
    fn test_mac_address_dotted_detected() {
        assert_eq!(texts("mac 001A.2B3C.4D5E"), ["001A.2B3C.4D5E"]);
    }

    #[test]
    fn test_mac_address_multiple_values_detected() {
        assert_eq!(
            texts("a 00:1A:2B:3C:4D:5E b 001A.2B3C.4D5E"),
            ["00:1A:2B:3C:4D:5E", "001A.2B3C.4D5E"]
        );
    }

    #[test]
    fn test_mac_address_invalid_hex_rejected() {
        assert!(texts("mac 00:1G:2B:3C:4D:5E").is_empty());
    }

    #[test]
    fn test_mac_address_too_short_rejected() {
        assert!(texts("mac 00:1A:2B:3C:4D").is_empty());
    }

    #[test]
    fn test_mac_address_too_long_rejected() {
        assert!(texts("mac 00:1A:2B:3C:4D:5E:6F").is_empty());
    }

    #[test]
    fn test_mac_address_embedded_in_word_rejected() {
        assert!(texts("id00:1A:2B:3C:4D:5E").is_empty());
    }

    #[test]
    fn test_mac_address_embedded_in_longer_dotted_rejected() {
        assert!(texts("001A.2B3C.4D5E.6F70").is_empty());
    }

    #[test]
    fn test_mac_address_context_boosts_confidence() {
        let with_context = MacAddressRecognizer.scan("mac address 00:1A:2B:3C:4D:5E");
        let without_context = MacAddressRecognizer.scan("value 00:1A:2B:3C:4D:5E");
        assert!(with_context[0].confidence > without_context[0].confidence);
    }

    #[test]
    fn test_mac_address_bssid_context_boosts_confidence() {
        let with_context = MacAddressRecognizer.scan("bssid 00:1A:2B:3C:4D:5E");
        let without_context = MacAddressRecognizer.scan("value 00:1A:2B:3C:4D:5E");
        assert!(with_context[0].confidence > without_context[0].confidence);
    }

    #[test]
    fn test_mac_address_supported_locales_are_universal() {
        assert!(MacAddressRecognizer.supported_locales().is_empty());
    }

    #[test]
    fn test_mac_address_validate_accepts_dotted() {
        assert!(MacAddressRecognizer.validate("001A.2B3C.4D5E"));
    }

    #[test]
    fn test_mac_address_default_registry_detects_mac_address() {
        let findings = default_registry().scan_all("mac 00:1A:2B:3C:4D:5E");

        assert!(findings
            .iter()
            .any(|finding| finding.entity_type == EntityType::MacAddress));
    }
}
