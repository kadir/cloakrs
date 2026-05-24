//! Prompt sanitization helpers for LLM pipelines.

use crate::{CloakError, EntityType, PiiEntity, Result, Scanner};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Sanitizes text before it is sent to an LLM, then restores placeholders later.
///
/// # Examples
///
/// ```
/// use cloakrs_core::{Confidence, EntityType, Locale, PiiEntity, PromptSanitizer, Recognizer, Scanner, Span};
///
/// struct Email;
/// impl Recognizer for Email {
///     fn id(&self) -> &str { "email_test" }
///     fn entity_type(&self) -> EntityType { EntityType::Email }
///     fn supported_locales(&self) -> &[Locale] { &[] }
///     fn scan(&self, text: &str) -> Vec<PiiEntity> {
///         text.find('@').map(|at| PiiEntity {
///             entity_type: EntityType::Email,
///             span: Span::new(0, text[at..].find(' ').map_or(text.len(), |offset| at + offset)),
///             text: text[..text[at..].find(' ').map_or(text.len(), |offset| at + offset)].to_string(),
///             confidence: Confidence::new(0.95).unwrap(),
///             recognizer_id: self.id().to_string(),
///         }).into_iter().collect()
///     }
/// }
///
/// let scanner = Scanner::builder().recognizer(Email).build().unwrap();
/// let sanitizer = PromptSanitizer::new(scanner);
/// let (clean, mapping) = sanitizer.sanitize("jane@example.com said hi").unwrap();
/// assert_eq!(clean, "[EMAIL_1] said hi");
/// assert_eq!(sanitizer.restore("Reply to [EMAIL_1]", &mapping), "Reply to jane@example.com");
/// ```
pub struct PromptSanitizer {
    scanner: Scanner,
}

impl PromptSanitizer {
    /// Creates a prompt sanitizer from an existing scanner.
    #[must_use]
    pub fn new(scanner: Scanner) -> Self {
        Self { scanner }
    }

    /// Replaces PII with numbered placeholders and returns the mapping table.
    pub fn sanitize(&self, prompt: &str) -> Result<(String, PromptMapping)> {
        let scan = self.scanner.scan(prompt)?;
        let mut findings = scan.findings;
        findings.sort_by_key(|finding| finding.span.start);

        let mut counters: HashMap<String, usize> = HashMap::new();
        let mut entries = Vec::with_capacity(findings.len());
        for finding in &findings {
            validate_span(prompt, finding)?;
            let prefix = placeholder_prefix(&finding.entity_type);
            let next = counters.entry(prefix.clone()).or_insert(0);
            *next += 1;
            entries.push(PromptMappingEntry {
                placeholder: format!("[{prefix}_{next}]"),
                entity_type: finding.entity_type.clone(),
                original: finding.text.clone(),
                span_start: finding.span.start,
                span_end: finding.span.end,
                confidence: finding.confidence.value(),
                recognizer_id: finding.recognizer_id.clone(),
            });
        }

        let mut clean_prompt = prompt.to_string();
        for (finding, entry) in findings.iter().zip(entries.iter()).rev() {
            clean_prompt.replace_range(finding.span.start..finding.span.end, &entry.placeholder);
        }

        Ok((clean_prompt, PromptMapping { entries }))
    }

    /// Restores placeholders in model output using a previously returned mapping table.
    #[must_use]
    pub fn restore(&self, text: &str, mapping: &PromptMapping) -> String {
        mapping.restore(text)
    }
}

/// Placeholder mapping returned by [`PromptSanitizer::sanitize`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PromptMapping {
    /// Placeholder entries in source-text order.
    pub entries: Vec<PromptMappingEntry>,
}

impl PromptMapping {
    /// Restores all known placeholders in a string.
    #[must_use]
    pub fn restore(&self, text: &str) -> String {
        let mut result = text.to_string();
        let mut entries = self.entries.clone();
        entries.sort_by(|left, right| {
            right
                .placeholder
                .len()
                .cmp(&left.placeholder.len())
                .then_with(|| right.placeholder.cmp(&left.placeholder))
        });
        for entry in entries {
            result = result.replace(&entry.placeholder, &entry.original);
        }
        result
    }
}

/// One placeholder-to-original-value mapping.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PromptMappingEntry {
    /// Placeholder inserted into the sanitized prompt, such as `[EMAIL_1]`.
    pub placeholder: String,
    /// Entity type represented by this placeholder.
    pub entity_type: EntityType,
    /// Original sensitive value.
    pub original: String,
    /// Source prompt start byte offset.
    pub span_start: usize,
    /// Source prompt end byte offset.
    pub span_end: usize,
    /// Detection confidence.
    pub confidence: f64,
    /// Recognizer that produced the original finding.
    pub recognizer_id: String,
}

fn placeholder_prefix(entity_type: &EntityType) -> String {
    entity_type
        .redaction_tag()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_string()
}

fn validate_span(text: &str, finding: &PiiEntity) -> Result<()> {
    let start = finding.span.start;
    let end = finding.span.end;
    if start <= end
        && end <= text.len()
        && text.is_char_boundary(start)
        && text.is_char_boundary(end)
    {
        Ok(())
    } else {
        Err(CloakError::InvalidSpan {
            start,
            end,
            len: text.len(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Confidence, Locale, Recognizer, Span};

    struct MultiRecognizer;

    impl Recognizer for MultiRecognizer {
        fn id(&self) -> &str {
            "multi_test_v1"
        }

        fn entity_type(&self) -> EntityType {
            EntityType::Email
        }

        fn supported_locales(&self) -> &[Locale] {
            &[]
        }

        fn scan(&self, text: &str) -> Vec<PiiEntity> {
            let mut findings = Vec::new();
            for needle in ["jane@example.com", "john@example.com", "+1 555 010 1234"] {
                if let Some(start) = text.find(needle) {
                    findings.push(PiiEntity {
                        entity_type: if needle.starts_with('+') {
                            EntityType::PhoneNumber
                        } else {
                            EntityType::Email
                        },
                        span: Span::new(start, start + needle.len()),
                        text: needle.to_string(),
                        confidence: Confidence::new(0.95).unwrap(),
                        recognizer_id: self.id().to_string(),
                    });
                }
            }
            findings
        }
    }

    #[test]
    fn test_prompt_sanitizer_replaces_with_numbered_placeholders() {
        let scanner = Scanner::builder()
            .recognizer(MultiRecognizer)
            .build()
            .unwrap();
        let sanitizer = PromptSanitizer::new(scanner);
        let (clean, mapping) = sanitizer
            .sanitize("Email jane@example.com and john@example.com")
            .unwrap();
        assert_eq!(clean, "Email [EMAIL_1] and [EMAIL_2]");
        assert_eq!(mapping.entries[0].original, "jane@example.com");
        assert_eq!(mapping.entries[1].placeholder, "[EMAIL_2]");
    }

    #[test]
    fn test_prompt_sanitizer_restore_reinjects_original_values() {
        let scanner = Scanner::builder()
            .recognizer(MultiRecognizer)
            .build()
            .unwrap();
        let sanitizer = PromptSanitizer::new(scanner);
        let (_, mapping) = sanitizer
            .sanitize("Call +1 555 010 1234 or email jane@example.com")
            .unwrap();
        let restored = sanitizer.restore("Use [PHONE_1] and [EMAIL_1]", &mapping);
        assert_eq!(restored, "Use +1 555 010 1234 and jane@example.com");
    }

    #[test]
    fn test_prompt_mapping_restore_replaces_repeated_placeholders() {
        let mapping = PromptMapping {
            entries: vec![PromptMappingEntry {
                placeholder: "[EMAIL_1]".to_string(),
                entity_type: EntityType::Email,
                original: "jane@example.com".to_string(),
                span_start: 0,
                span_end: 16,
                confidence: 0.95,
                recognizer_id: "test".to_string(),
            }],
        };
        assert_eq!(
            mapping.restore("[EMAIL_1] replied to [EMAIL_1]"),
            "jane@example.com replied to jane@example.com"
        );
    }
}
