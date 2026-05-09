use crate::common::{compile_regex, confidence, context_boost};
use cloakrs_core::{Confidence, EntityType, Locale, PiiEntity, Recognizer, Span};
use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashSet;
use std::net::IpAddr;

static IPV4_REGEX: Lazy<Regex> = Lazy::new(|| compile_regex(r"(?:\d{1,3}\.){3}\d{1,3}"));
static IPV6_REGEX: Lazy<Regex> =
    Lazy::new(|| compile_regex(r"[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}"));

const CONTEXT_WORDS: &[&str] = &[
    "ip",
    "ip address",
    "remote_addr",
    "client_ip",
    "source ip",
    "destination ip",
    "host",
    "server",
];

/// Recognizes IPv4 and IPv6 addresses.
///
/// # Examples
///
/// ```
/// use cloakrs_core::{EntityType, Recognizer};
/// use cloakrs_patterns::IpAddressRecognizer;
///
/// let findings = IpAddressRecognizer.scan("client_ip=203.0.113.42");
/// assert_eq!(findings[0].entity_type, EntityType::IpAddress);
/// assert_eq!(findings[0].text, "203.0.113.42");
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct IpAddressRecognizer;

impl Recognizer for IpAddressRecognizer {
    fn id(&self) -> &str {
        "ip_address_std_v1"
    }

    fn entity_type(&self) -> EntityType {
        EntityType::IpAddress
    }

    fn supported_locales(&self) -> &[Locale] {
        &[]
    }

    fn scan(&self, text: &str) -> Vec<PiiEntity> {
        let mut seen = HashSet::new();
        let mut findings = Vec::new();

        for regex in [&*IPV4_REGEX, &*IPV6_REGEX] {
            for matched in regex.find_iter(text) {
                if seen.insert((matched.start(), matched.end()))
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
        parse_ip(candidate).is_some()
    }
}

impl IpAddressRecognizer {
    fn is_valid_match(&self, text: &str, start: usize, end: usize) -> bool {
        self.validate(&text[start..end]) && is_ip_boundary(text, start, end)
    }

    fn compute_confidence(&self, text: &str, start: usize, candidate: &str) -> Confidence {
        let base = match parse_ip(candidate) {
            Some(IpAddr::V4(_)) => 0.85,
            Some(IpAddr::V6(_)) => 0.90,
            None => 0.0,
        };
        confidence(base + context_boost(text, start, CONTEXT_WORDS))
    }
}

fn parse_ip(candidate: &str) -> Option<IpAddr> {
    if candidate == "::" {
        return None;
    }
    candidate.parse::<IpAddr>().ok()
}

fn is_ip_boundary(text: &str, start: usize, end: usize) -> bool {
    let before = text[..start].chars().next_back();
    let after = text[end..].chars().next();
    !before.is_some_and(is_ip_continuation) && !after.is_some_and(is_ip_continuation)
}

fn is_ip_continuation(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ':' | '%')
}

#[cfg(test)]
mod tests {
    use super::*;
    use cloakrs_core::RecognizerRegistry;

    fn texts(input: &str) -> Vec<String> {
        IpAddressRecognizer
            .scan(input)
            .into_iter()
            .map(|finding| finding.text)
            .collect()
    }

    #[test]
    fn test_ip_address_ipv4_public_detected() {
        assert_eq!(texts("client_ip=203.0.113.42"), ["203.0.113.42"]);
    }

    #[test]
    fn test_ip_address_ipv4_private_detected() {
        assert_eq!(texts("host 192.168.1.105"), ["192.168.1.105"]);
    }

    #[test]
    fn test_ip_address_ipv4_loopback_detected() {
        assert_eq!(texts("server 127.0.0.1"), ["127.0.0.1"]);
    }

    #[test]
    fn test_ip_address_ipv4_zero_octets_detected() {
        assert_eq!(texts("remote 0.0.0.0"), ["0.0.0.0"]);
    }

    #[test]
    fn test_ip_address_ipv6_full_detected() {
        assert_eq!(
            texts("addr 2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
            ["2001:0db8:85a3:0000:0000:8a2e:0370:7334"]
        );
    }

    #[test]
    fn test_ip_address_ipv6_compressed_detected() {
        assert_eq!(texts("source ip 2001:db8::1"), ["2001:db8::1"]);
    }

    #[test]
    fn test_ip_address_ipv6_loopback_detected() {
        assert_eq!(texts("host ::1"), ["::1"]);
    }

    #[test]
    fn test_ip_address_ipv4_octet_above_range_rejected() {
        assert!(texts("client_ip=256.168.1.1").is_empty());
    }

    #[test]
    fn test_ip_address_ipv4_partial_octet_range_rejected() {
        assert!(texts("client_ip=999.10.10.10").is_empty());
    }

    #[test]
    fn test_ip_address_ipv6_invalid_shape_rejected() {
        assert!(texts("addr 2001:::1").is_empty());
    }

    #[test]
    fn test_ip_address_ipv6_punctuation_only_rejected() {
        assert!(texts("addr ::").is_empty());
    }

    #[test]
    fn test_ip_address_ipv4_embedded_in_larger_dot_sequence_rejected() {
        assert!(texts("version 192.168.1.1.5").is_empty());
    }

    #[test]
    fn test_ip_address_ipv4_embedded_in_word_rejected() {
        assert!(texts("id192.168.1.1").is_empty());
    }

    #[test]
    fn test_ip_address_ipv6_embedded_in_larger_colon_sequence_rejected() {
        assert!(texts("addr x2001:db8::1").is_empty());
    }

    #[test]
    fn test_ip_address_multiple_findings_detected() {
        assert_eq!(
            texts("client_ip=203.0.113.42 server 2001:db8::5"),
            ["203.0.113.42", "2001:db8::5"]
        );
    }

    #[test]
    fn test_ip_address_context_boosts_ipv4_confidence() {
        let with_context = IpAddressRecognizer.scan("client_ip=203.0.113.42");
        let without_context = IpAddressRecognizer.scan("value 203.0.113.42");
        assert!(with_context[0].confidence > without_context[0].confidence);
    }

    #[test]
    fn test_ip_address_context_boosts_ipv6_confidence() {
        let with_context = IpAddressRecognizer.scan("destination ip 2001:db8::1");
        let without_context = IpAddressRecognizer.scan("value 2001:db8::1");
        assert!(with_context[0].confidence > without_context[0].confidence);
    }

    #[test]
    fn test_ip_address_supported_locales_are_universal() {
        assert!(IpAddressRecognizer.supported_locales().is_empty());
    }

    #[test]
    fn test_ip_address_validate_accepts_valid_ipv4() {
        assert!(IpAddressRecognizer.validate("203.0.113.42"));
    }

    #[test]
    fn test_ip_address_validate_rejects_invalid_ipv6() {
        assert!(!IpAddressRecognizer.validate("2001:::1"));
    }

    #[test]
    fn test_ip_address_registry_integration_detects_default_recognizer() {
        let mut registry = RecognizerRegistry::new();
        crate::register_default_recognizers(&mut registry);

        let findings = registry.scan_all("remote_addr=203.0.113.42");

        assert!(findings
            .iter()
            .any(|finding| finding.entity_type == EntityType::IpAddress));
    }
}
