use crate::common::{compile_regex, confidence, context_boost};
use cloakrs_core::{Confidence, EntityType, Locale, PiiEntity, Recognizer, Span};
use once_cell::sync::Lazy;
use regex::Regex;

static EMAIL_REGEX: Lazy<Regex> = Lazy::new(|| {
    compile_regex(
        r#"(?:"[^"\r\n]+"|[A-Za-z0-9.!#$%&'*+=?^_`{|}~-]+)@(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}"#,
    )
});

const CONTEXT_WORDS: &[&str] = &["email:", "e-mail:", "mail:", "contact:", "email", "contact"];

/// Recognizes common email addresses.
#[derive(Debug, Clone, Copy, Default)]
pub struct EmailRecognizer;

impl Recognizer for EmailRecognizer {
    fn id(&self) -> &str {
        "email_regex_v1"
    }

    fn entity_type(&self) -> EntityType {
        EntityType::Email
    }

    fn supported_locales(&self) -> &[Locale] {
        &[]
    }

    fn scan(&self, text: &str) -> Vec<PiiEntity> {
        EMAIL_REGEX
            .find_iter(text)
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
        let Some((local, domain)) = candidate.split_once('@') else {
            return false;
        };
        !local.is_empty()
            && domain.contains('.')
            && !domain.starts_with('-')
            && !domain.ends_with('-')
            && !domain.contains("..")
    }
}

impl EmailRecognizer {
    fn is_valid_match(&self, text: &str, start: usize, end: usize) -> bool {
        let candidate = &text[start..end];
        if !self.validate(candidate) {
            return false;
        }

        let prefix_start = text[..start]
            .char_indices()
            .rev()
            .find(|(_, c)| c.is_whitespace())
            .map_or(0, |(idx, c)| idx + c.len_utf8());
        let prefix = &text[prefix_start..start];
        if prefix.contains("://") {
            return false;
        }

        let before = text[..start].chars().next_back();
        let after = text[end..].chars().next();
        !before.is_some_and(|c| c.is_ascii_alphanumeric() || c == '/' || c == '_')
            && !after.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    }

    fn compute_confidence(&self, text: &str, start: usize, candidate: &str) -> Confidence {
        let base: f64 = if candidate.starts_with('"') {
            0.80
        } else {
            0.95
        };
        confidence(base + context_boost(text, start, CONTEXT_WORDS))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn texts(input: &str) -> Vec<String> {
        EmailRecognizer
            .scan(input)
            .into_iter()
            .map(|finding| finding.text)
            .collect()
    }

    #[test]
    fn test_email_standard_detected() {
        assert_eq!(texts("Contact user@example.com"), ["user@example.com"]);
    }

    #[test]
    fn test_email_plus_tag_detected() {
        assert_eq!(texts("user+tag@example.com"), ["user+tag@example.com"]);
    }

    #[test]
    fn test_email_subdomain_detected() {
        assert_eq!(
            texts("Send to user@mail.sub.example.co.uk"),
            ["user@mail.sub.example.co.uk"]
        );
    }

    #[test]
    fn test_email_quoted_local_detected() {
        assert_eq!(
            texts(r#""quoted"@example.com"#),
            [r#""quoted"@example.com"#]
        );
    }

    #[test]
    fn test_email_multiple_detected() {
        assert_eq!(
            texts("a@example.com b@test.org"),
            ["a@example.com", "b@test.org"]
        );
    }

    #[test]
    fn test_email_at_mention_not_detected() {
        assert!(texts("@username").is_empty());
    }

    #[test]
    fn test_email_inside_url_not_detected() {
        assert!(texts("https://user@example.com/path").is_empty());
    }

    #[test]
    fn test_email_without_tld_not_detected() {
        assert!(texts("user@example").is_empty());
    }

    #[test]
    fn test_email_partial_inside_word_not_detected() {
        assert!(texts("prefix/user@example.com").is_empty());
    }

    #[test]
    fn test_email_context_boosts_confidence() {
        let with_context = EmailRecognizer.scan("email: user@example.com");
        let without_context = EmailRecognizer.scan("value user@example.com");
        assert!(with_context[0].confidence > without_context[0].confidence);
    }

    #[test]
    fn test_email_uppercase_domain_detected() {
        assert_eq!(texts("USER@EXAMPLE.COM"), ["USER@EXAMPLE.COM"]);
    }

    #[test]
    fn test_email_apostrophe_local_detected() {
        assert_eq!(texts("o'hara@example.com"), ["o'hara@example.com"]);
    }

    #[test]
    fn test_email_hyphenated_domain_detected() {
        assert_eq!(
            texts("user@mail-server.example"),
            ["user@mail-server.example"]
        );
    }

    #[test]
    fn test_email_dot_local_detected() {
        assert_eq!(texts("first.last@example.org"), ["first.last@example.org"]);
    }

    #[test]
    fn test_email_trailing_punctuation_excluded() {
        assert_eq!(texts("Send user@example.com."), ["user@example.com"]);
    }

    #[test]
    fn test_email_double_dot_domain_not_detected() {
        assert!(texts("user@example..com").is_empty());
    }

    #[test]
    fn test_email_domain_starting_with_hyphen_not_detected() {
        assert!(texts("user@-example.com").is_empty());
    }

    #[test]
    fn test_email_e_mail_context_boosts_confidence() {
        let with_context = EmailRecognizer.scan("e-mail: user@example.com");
        let without_context = EmailRecognizer.scan("value user@example.com");
        assert!(with_context[0].confidence > without_context[0].confidence);
    }

    #[test]
    fn test_email_quoted_local_has_lower_confidence_than_standard() {
        let quoted = EmailRecognizer.scan(r#""quoted"@example.com"#);
        let standard = EmailRecognizer.scan("user@example.com");
        assert!(quoted[0].confidence < standard[0].confidence);
    }

    #[test]
    fn test_email_validate_rejects_missing_at() {
        assert!(!EmailRecognizer.validate("user.example.com"));
    }
}
