use crate::common::{compile_regex, confidence, context_boost, is_boundary};
use cloakrs_core::{Confidence, EntityType, Locale, PiiEntity, Recognizer, Span};
use once_cell::sync::Lazy;
use regex::Regex;

static AWS_ACCESS_KEY_REGEX: Lazy<Regex> = Lazy::new(|| compile_regex(r"\bAKIA[A-Z0-9]{16}\b"));
static JWT_REGEX: Lazy<Regex> =
    Lazy::new(|| compile_regex(r"\b[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"));
static GENERIC_API_KEY_REGEX: Lazy<Regex> = Lazy::new(|| {
    compile_regex(
        r#"(?i)\b(?:api[_-]?key|access[_-]?token|token|secret|authorization)\b\s*(?::|=|=>)\s*(?:bearer\s+)?["']?([A-Za-z0-9][A-Za-z0-9_\-+/=]{19,})["']?"#,
    )
});

const SECRET_CONTEXT_WORDS: &[&str] = &[
    "api_key",
    "api key",
    "access_token",
    "token",
    "secret",
    "authorization",
    "bearer",
    "credential",
];

/// Recognizes AWS access key identifiers with the `AKIA` prefix.
///
/// # Examples
///
/// ```
/// use cloakrs_core::{EntityType, Recognizer};
/// use cloakrs_patterns::AwsAccessKeyRecognizer;
///
/// let findings = AwsAccessKeyRecognizer.scan("aws AKIAIOSFODNN7EXAMPLE");
/// assert_eq!(findings[0].entity_type, EntityType::AwsAccessKey);
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct AwsAccessKeyRecognizer;

impl Recognizer for AwsAccessKeyRecognizer {
    fn id(&self) -> &str {
        "aws_access_key_v1"
    }

    fn entity_type(&self) -> EntityType {
        EntityType::AwsAccessKey
    }

    fn supported_locales(&self) -> &[Locale] {
        &[]
    }

    fn scan(&self, text: &str) -> Vec<PiiEntity> {
        AWS_ACCESS_KEY_REGEX
            .find_iter(text)
            .filter(|matched| self.is_valid_match(text, matched.start(), matched.end()))
            .map(|matched| PiiEntity {
                entity_type: self.entity_type(),
                span: Span::new(matched.start(), matched.end()),
                text: matched.as_str().to_string(),
                confidence: self.compute_confidence(text, matched.start()),
                recognizer_id: self.id().to_string(),
            })
            .collect()
    }

    fn validate(&self, candidate: &str) -> bool {
        candidate.len() == 20
            && candidate.starts_with("AKIA")
            && candidate
                .chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
    }
}

impl AwsAccessKeyRecognizer {
    fn is_valid_match(&self, text: &str, start: usize, end: usize) -> bool {
        self.validate(&text[start..end]) && is_boundary(text, start, end)
    }

    fn compute_confidence(&self, text: &str, start: usize) -> Confidence {
        confidence(0.99 + context_boost(text, start, SECRET_CONTEXT_WORDS))
    }
}

/// Recognizes JSON Web Tokens in `header.payload.signature` form.
///
/// # Examples
///
/// ```
/// use cloakrs_core::{EntityType, Recognizer};
/// use cloakrs_patterns::JwtRecognizer;
///
/// let token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123456789_xyz";
/// let findings = JwtRecognizer.scan(token);
/// assert_eq!(findings[0].entity_type, EntityType::Jwt);
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct JwtRecognizer;

impl Recognizer for JwtRecognizer {
    fn id(&self) -> &str {
        "jwt_regex_v1"
    }

    fn entity_type(&self) -> EntityType {
        EntityType::Jwt
    }

    fn supported_locales(&self) -> &[Locale] {
        &[]
    }

    fn scan(&self, text: &str) -> Vec<PiiEntity> {
        JWT_REGEX
            .find_iter(text)
            .filter(|matched| self.is_valid_match(text, matched.start(), matched.end()))
            .map(|matched| PiiEntity {
                entity_type: self.entity_type(),
                span: Span::new(matched.start(), matched.end()),
                text: matched.as_str().to_string(),
                confidence: self.compute_confidence(text, matched.start()),
                recognizer_id: self.id().to_string(),
            })
            .collect()
    }

    fn validate(&self, candidate: &str) -> bool {
        let mut parts = candidate.split('.');
        let Some(header) = parts.next() else {
            return false;
        };
        let Some(payload) = parts.next() else {
            return false;
        };
        let Some(signature) = parts.next() else {
            return false;
        };
        parts.next().is_none()
            && header.starts_with("ey")
            && payload.starts_with("ey")
            && validate_jwt_segment(header, 8)
            && validate_jwt_segment(payload, 8)
            && validate_jwt_segment(signature, 8)
    }
}

impl JwtRecognizer {
    fn is_valid_match(&self, text: &str, start: usize, end: usize) -> bool {
        self.validate(&text[start..end]) && is_secret_boundary(text, start, end)
    }

    fn compute_confidence(&self, text: &str, start: usize) -> Confidence {
        confidence(0.92 + context_boost(text, start, SECRET_CONTEXT_WORDS))
    }
}

/// Recognizes generic API keys and bearer-style tokens with nearby key context.
///
/// # Examples
///
/// ```
/// use cloakrs_core::{EntityType, Recognizer};
/// use cloakrs_patterns::ApiKeyRecognizer;
///
/// let findings = ApiKeyRecognizer.scan("api_key = sk_live_0123456789abcdef");
/// assert_eq!(findings[0].entity_type, EntityType::ApiKey);
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct ApiKeyRecognizer;

impl Recognizer for ApiKeyRecognizer {
    fn id(&self) -> &str {
        "api_key_context_v1"
    }

    fn entity_type(&self) -> EntityType {
        EntityType::ApiKey
    }

    fn supported_locales(&self) -> &[Locale] {
        &[]
    }

    fn scan(&self, text: &str) -> Vec<PiiEntity> {
        GENERIC_API_KEY_REGEX
            .captures_iter(text)
            .filter_map(|captures| captures.get(1))
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
        validate_generic_secret(candidate)
    }
}

impl ApiKeyRecognizer {
    fn is_valid_match(&self, text: &str, start: usize, end: usize) -> bool {
        self.validate(&text[start..end]) && is_secret_boundary(text, start, end)
    }

    fn compute_confidence(&self, text: &str, start: usize, candidate: &str) -> Confidence {
        let base = if looks_structured_secret(candidate) {
            0.85
        } else {
            0.75
        };
        confidence(base + context_boost(text, start, SECRET_CONTEXT_WORDS))
    }
}

fn validate_jwt_segment(segment: &str, min_len: usize) -> bool {
    segment.len() >= min_len
        && segment
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-'))
}

fn validate_generic_secret(candidate: &str) -> bool {
    let trimmed = candidate.trim_matches(|c| matches!(c, '"' | '\'' | ',' | ';'));
    trimmed.len() >= 20
        && !trimmed.chars().all(|c| c == trimmed.as_bytes()[0] as char)
        && trimmed
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '+' | '/' | '='))
}

fn looks_structured_secret(candidate: &str) -> bool {
    let has_letter = candidate.chars().any(|c| c.is_ascii_alphabetic());
    let has_digit = candidate.chars().any(|c| c.is_ascii_digit());
    let has_symbol = candidate
        .chars()
        .any(|c| matches!(c, '_' | '-' | '+' | '/' | '='));
    has_letter && has_digit && has_symbol
}

fn is_secret_boundary(text: &str, start: usize, end: usize) -> bool {
    let before = text[..start].chars().next_back();
    let after = text[end..].chars().next();
    !before.is_some_and(is_secret_prefix_char) && !after.is_some_and(is_secret_suffix_char)
}

fn is_secret_prefix_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '+' | '/' | '.')
}

fn is_secret_suffix_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '+' | '/' | '=' | '.')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::default_registry;

    fn aws_texts(input: &str) -> Vec<String> {
        AwsAccessKeyRecognizer
            .scan(input)
            .into_iter()
            .map(|finding| finding.text)
            .collect()
    }

    fn jwt_texts(input: &str) -> Vec<String> {
        JwtRecognizer
            .scan(input)
            .into_iter()
            .map(|finding| finding.text)
            .collect()
    }

    fn api_key_texts(input: &str) -> Vec<String> {
        ApiKeyRecognizer
            .scan(input)
            .into_iter()
            .map(|finding| finding.text)
            .collect()
    }

    #[test]
    fn test_aws_access_key_valid_detected() {
        assert_eq!(
            aws_texts("aws AKIAIOSFODNN7EXAMPLE"),
            ["AKIAIOSFODNN7EXAMPLE"]
        );
    }

    #[test]
    fn test_aws_access_key_token_context_detected() {
        assert_eq!(
            aws_texts("access token AKIA1234567890ABCDEF"),
            ["AKIA1234567890ABCDEF"]
        );
    }

    #[test]
    fn test_aws_access_key_lowercase_rejected() {
        assert!(aws_texts("akiaiosfodnn7example").is_empty());
    }

    #[test]
    fn test_aws_access_key_too_short_rejected() {
        assert!(aws_texts("AKIAIOSFODNN7EXAMP").is_empty());
    }

    #[test]
    fn test_aws_access_key_embedded_in_word_rejected() {
        assert!(aws_texts("idAKIAIOSFODNN7EXAMPLE").is_empty());
    }

    #[test]
    fn test_aws_access_key_context_boosts_confidence() {
        let with_context = AwsAccessKeyRecognizer.scan("secret AKIAIOSFODNN7EXAMPLE");
        let without_context = AwsAccessKeyRecognizer.scan("value AKIAIOSFODNN7EXAMPLE");
        assert!(with_context[0].confidence >= without_context[0].confidence);
    }

    #[test]
    fn test_jwt_valid_detected() {
        let token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123456789_xyz";
        assert_eq!(jwt_texts(token), [token]);
    }

    #[test]
    fn test_jwt_with_bearer_context_detected() {
        let token = "eyJ0eXAiOiJKV1QifQ.eyJyb2xlIjoiYWRtaW4ifQ.signature_123456";
        assert_eq!(jwt_texts(&format!("Bearer {token}")), [token]);
    }

    #[test]
    fn test_jwt_short_version_like_value_rejected() {
        assert!(jwt_texts("version 1.2.3").is_empty());
    }

    #[test]
    fn test_jwt_two_segments_rejected() {
        assert!(jwt_texts("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM").is_empty());
    }

    #[test]
    fn test_jwt_embedded_in_larger_secret_rejected() {
        let token = "xeyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123456789_xyz";
        assert!(jwt_texts(token).is_empty());
    }

    #[test]
    fn test_jwt_context_boosts_confidence() {
        let token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123456789_xyz";
        let with_context = JwtRecognizer.scan(&format!("authorization: bearer {token}"));
        let without_context = JwtRecognizer.scan(token);
        assert!(with_context[0].confidence > without_context[0].confidence);
    }

    #[test]
    fn test_api_key_after_api_key_label_detected() {
        assert_eq!(
            api_key_texts("api_key = sk_live_0123456789abcdef"),
            ["sk_live_0123456789abcdef"]
        );
    }

    #[test]
    fn test_api_key_after_token_label_detected() {
        assert_eq!(
            api_key_texts("token: abcdef1234567890ABCDEF12"),
            ["abcdef1234567890ABCDEF12"]
        );
    }

    #[test]
    fn test_api_key_after_authorization_bearer_detected() {
        assert_eq!(
            api_key_texts("Authorization: Bearer abcdef1234567890ABCDEF12"),
            ["abcdef1234567890ABCDEF12"]
        );
    }

    #[test]
    fn test_api_key_after_secret_label_detected() {
        assert_eq!(
            api_key_texts("secret=ZXhhbXBsZS1zZWNyZXQtdmFsdWU="),
            ["ZXhhbXBsZS1zZWNyZXQtdmFsdWU="]
        );
    }

    #[test]
    fn test_api_key_without_context_rejected() {
        assert!(api_key_texts("value abcdef1234567890ABCDEF12").is_empty());
    }

    #[test]
    fn test_api_key_short_value_rejected() {
        assert!(api_key_texts("api_key=abc123").is_empty());
    }

    #[test]
    fn test_api_key_repeated_value_rejected() {
        assert!(api_key_texts("api_key=aaaaaaaaaaaaaaaaaaaa").is_empty());
    }

    #[test]
    fn test_api_key_context_boosts_confidence() {
        let structured = ApiKeyRecognizer.scan("api_key=sk_live_0123456789abcdef");
        let plain = ApiKeyRecognizer.scan("token=abcdef1234567890ABCDEF12");
        assert!(structured[0].confidence > plain[0].confidence);
    }

    #[test]
    fn test_secret_default_registry_detects_all_secret_types() {
        let findings = default_registry().scan_all(concat!(
            "aws AKIAIOSFODNN7EXAMPLE\n",
            "jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123456789_xyz\n",
            "api_key=sk_live_0123456789abcdef\n",
        ));

        assert!(findings
            .iter()
            .any(|finding| finding.entity_type == EntityType::AwsAccessKey));
        assert!(findings
            .iter()
            .any(|finding| finding.entity_type == EntityType::Jwt));
        assert!(findings
            .iter()
            .any(|finding| finding.entity_type == EntityType::ApiKey));
    }
}
