use crate::common::{compile_regex, confidence, context_boost};
use cloakrs_core::{Confidence, EntityType, Locale, PiiEntity, Recognizer, Span};
use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashSet;

static ETHEREUM_REGEX: Lazy<Regex> = Lazy::new(|| compile_regex(r"\b0x[0-9A-Fa-f]{40}\b"));
static BITCOIN_LEGACY_REGEX: Lazy<Regex> =
    Lazy::new(|| compile_regex(r"\b[13][1-9A-HJ-NP-Za-km-z]{25,34}\b"));
static BITCOIN_BECH32_REGEX: Lazy<Regex> =
    Lazy::new(|| compile_regex(r"\b(?:bc1|BC1)[ac-hj-np-zAC-HJ-NP-Z02-9]{11,71}\b"));

const CONTEXT_WORDS: &[&str] = &[
    "wallet", "crypto", "bitcoin", "btc", "ethereum", "eth", "address", "deposit",
];

/// Recognizes common Bitcoin and Ethereum wallet address shapes.
///
/// # Examples
///
/// ```
/// use cloakrs_core::{EntityType, Recognizer};
/// use cloakrs_patterns::CryptoAddressRecognizer;
///
/// let findings = CryptoAddressRecognizer.scan("eth 0x52908400098527886E0F7030069857D2E4169EE7");
/// assert_eq!(findings[0].entity_type, EntityType::CryptoAddress);
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct CryptoAddressRecognizer;

impl Recognizer for CryptoAddressRecognizer {
    fn id(&self) -> &str {
        "crypto_address_regex_v1"
    }

    fn entity_type(&self) -> EntityType {
        EntityType::CryptoAddress
    }

    fn supported_locales(&self) -> &[Locale] {
        &[]
    }

    fn scan(&self, text: &str) -> Vec<PiiEntity> {
        let mut seen = HashSet::new();
        let mut findings = Vec::new();

        for regex in [
            &*ETHEREUM_REGEX,
            &*BITCOIN_LEGACY_REGEX,
            &*BITCOIN_BECH32_REGEX,
        ] {
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
        validate_ethereum(candidate)
            || validate_bitcoin_legacy(candidate)
            || validate_bitcoin_bech32(candidate)
    }
}

impl CryptoAddressRecognizer {
    fn is_valid_match(&self, text: &str, start: usize, end: usize) -> bool {
        self.validate(&text[start..end]) && is_crypto_boundary(text, start, end)
    }

    fn compute_confidence(&self, text: &str, start: usize, candidate: &str) -> Confidence {
        let base = if candidate.starts_with("0x") || candidate.starts_with("0X") {
            0.92
        } else {
            0.86
        };
        confidence(base + context_boost(text, start, CONTEXT_WORDS))
    }
}

fn validate_ethereum(candidate: &str) -> bool {
    candidate.len() == 42
        && candidate
            .get(..2)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("0x"))
        && candidate[2..].chars().all(|c| c.is_ascii_hexdigit())
}

fn validate_bitcoin_legacy(candidate: &str) -> bool {
    (26..=35).contains(&candidate.len())
        && matches!(candidate.as_bytes().first(), Some(b'1' | b'3'))
        && candidate.chars().all(is_base58_char)
}

fn validate_bitcoin_bech32(candidate: &str) -> bool {
    let has_prefix = candidate
        .get(..3)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("bc1"));
    let is_lower = candidate.chars().all(|c| !c.is_ascii_uppercase());
    let is_upper = candidate.chars().all(|c| !c.is_ascii_lowercase());
    has_prefix
        && (14..=74).contains(&candidate.len())
        && (is_lower || is_upper)
        && candidate[3..].chars().all(is_bech32_char)
}

fn is_base58_char(c: char) -> bool {
    c.is_ascii_alphanumeric() && !matches!(c, '0' | 'O' | 'I' | 'l')
}

fn is_bech32_char(c: char) -> bool {
    matches!(
        c.to_ascii_lowercase(),
        'q' | 'p'
            | 'z'
            | 'r'
            | 'y'
            | '9'
            | 'x'
            | '8'
            | 'g'
            | 'f'
            | '2'
            | 't'
            | 'v'
            | 'd'
            | 'w'
            | '0'
            | 's'
            | '3'
            | 'j'
            | 'n'
            | '5'
            | '4'
            | 'k'
            | 'h'
            | 'c'
            | 'e'
            | '6'
            | 'm'
            | 'u'
            | 'a'
            | '7'
            | 'l'
    )
}

fn is_crypto_boundary(text: &str, start: usize, end: usize) -> bool {
    let before = text[..start].chars().next_back();
    let after = text[end..].chars().next();
    !before.is_some_and(is_crypto_continuation) && !after.is_some_and(is_crypto_continuation)
}

fn is_crypto_continuation(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::default_registry;

    fn texts(input: &str) -> Vec<String> {
        CryptoAddressRecognizer
            .scan(input)
            .into_iter()
            .map(|finding| finding.text)
            .collect()
    }

    #[test]
    fn test_crypto_address_ethereum_detected() {
        assert_eq!(
            texts("eth 0x52908400098527886E0F7030069857D2E4169EE7"),
            ["0x52908400098527886E0F7030069857D2E4169EE7"]
        );
    }

    #[test]
    fn test_crypto_address_ethereum_lowercase_detected() {
        assert_eq!(
            texts("eth 0xde709f2102306220921060314715629080e2fb77"),
            ["0xde709f2102306220921060314715629080e2fb77"]
        );
    }

    #[test]
    fn test_crypto_address_bitcoin_legacy_one_detected() {
        assert_eq!(
            texts("btc 1BoatSLRHtKNngkdXEeobR76b53LETtpyT"),
            ["1BoatSLRHtKNngkdXEeobR76b53LETtpyT"]
        );
    }

    #[test]
    fn test_crypto_address_bitcoin_script_detected() {
        assert_eq!(
            texts("btc 3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"),
            ["3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"]
        );
    }

    #[test]
    fn test_crypto_address_bitcoin_bech32_detected() {
        assert_eq!(
            texts("wallet bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"),
            ["bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"]
        );
    }

    #[test]
    fn test_crypto_address_multiple_values_detected() {
        assert_eq!(
            texts("eth 0xde709f2102306220921060314715629080e2fb77 btc 1BoatSLRHtKNngkdXEeobR76b53LETtpyT"),
            [
                "0xde709f2102306220921060314715629080e2fb77",
                "1BoatSLRHtKNngkdXEeobR76b53LETtpyT"
            ]
        );
    }

    #[test]
    fn test_crypto_address_ethereum_short_rejected() {
        assert!(texts("eth 0x52908400098527886E0F7030069857D2E4169EE").is_empty());
    }

    #[test]
    fn test_crypto_address_ethereum_invalid_hex_rejected() {
        assert!(texts("eth 0x52908400098527886E0F7030069857D2E4169EEZ").is_empty());
    }

    #[test]
    fn test_crypto_address_bitcoin_base58_zero_rejected() {
        assert!(texts("btc 1BoatSLRHtKNngkdXEeobR76b53LETtpy0").is_empty());
    }

    #[test]
    fn test_crypto_address_bech32_mixed_case_rejected() {
        assert!(texts("btc bc1Qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080").is_empty());
    }

    #[test]
    fn test_crypto_address_embedded_in_word_rejected() {
        assert!(texts("id0xde709f2102306220921060314715629080e2fb77").is_empty());
    }

    #[test]
    fn test_crypto_address_context_boosts_confidence() {
        let with_context =
            CryptoAddressRecognizer.scan("wallet 0xde709f2102306220921060314715629080e2fb77");
        let without_context =
            CryptoAddressRecognizer.scan("value 0xde709f2102306220921060314715629080e2fb77");
        assert!(with_context[0].confidence > without_context[0].confidence);
    }

    #[test]
    fn test_crypto_address_bitcoin_context_boosts_confidence() {
        let with_context =
            CryptoAddressRecognizer.scan("bitcoin 1BoatSLRHtKNngkdXEeobR76b53LETtpyT");
        let without_context =
            CryptoAddressRecognizer.scan("value 1BoatSLRHtKNngkdXEeobR76b53LETtpyT");
        assert!(with_context[0].confidence > without_context[0].confidence);
    }

    #[test]
    fn test_crypto_address_supported_locales_are_universal() {
        assert!(CryptoAddressRecognizer.supported_locales().is_empty());
    }

    #[test]
    fn test_crypto_address_default_registry_detects_crypto_address() {
        let findings =
            default_registry().scan_all("eth 0xde709f2102306220921060314715629080e2fb77");

        assert!(findings
            .iter()
            .any(|finding| finding.entity_type == EntityType::CryptoAddress));
    }
}
