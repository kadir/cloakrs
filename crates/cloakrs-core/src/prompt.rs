//! Prompt sanitization helpers for LLM pipelines.

use crate::{CloakError, EntityType, PiiEntity, Result, Scanner};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

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

    /// Replaces PII with numbered `[TYPE_N]` placeholders and returns the mapping table.
    ///
    /// Identical `(entity_type, original_text)` pairs found within this call receive the
    /// same placeholder; the returned mapping contains one entry per unique placeholder.
    pub fn sanitize(&self, prompt: &str) -> Result<(String, PromptMapping)> {
        self.sanitize_with_style(prompt, PlaceholderStyle::Brackets)
    }

    /// Like [`sanitize`](Self::sanitize), but formats placeholders with the given
    /// [`PlaceholderStyle`] instead of the default brackets.
    pub fn sanitize_with_style(
        &self,
        prompt: &str,
        style: PlaceholderStyle,
    ) -> Result<(String, PromptMapping)> {
        let scan = self.scanner.scan(prompt)?;
        let mut findings = scan.findings;
        findings.sort_by_key(|finding| (finding.span.start, std::cmp::Reverse(finding.span.end)));

        for finding in &findings {
            validate_span(prompt, finding)?;
        }

        // Reporting retains nested URL findings. Replace each outer span only once.
        let mut end = 0;
        findings.retain(|finding| {
            if finding.span.start < end {
                return false;
            }
            end = finding.span.end;
            true
        });

        let (open, close) = style.chars();
        let existing_pattern = format!(
            r"{}\s*([^\[\]{{}}]+_[0-9]+)\s*{}",
            regex::escape(&open.to_string()),
            regex::escape(&close.to_string())
        );
        let existing: std::collections::HashSet<String> = Regex::new(&existing_pattern)
            .expect("valid placeholder pattern")
            .captures_iter(prompt)
            .map(|caps| caps[1].trim().to_ascii_uppercase())
            .collect();
        let mut counters: HashMap<String, usize> = HashMap::new();
        // Maps (entity_type, original text) to the index of its entry in `entries`, so
        // repeated values within this call reuse the same placeholder.
        let mut assigned: HashMap<(EntityType, String), usize> = HashMap::new();
        let mut entries: Vec<PromptMappingEntry> = Vec::new();
        let mut placeholder_for_finding: Vec<String> = Vec::with_capacity(findings.len());

        for finding in &findings {
            let key = (finding.entity_type.clone(), finding.text.clone());
            let placeholder = if let Some(&index) = assigned.get(&key) {
                entries[index].placeholder.clone()
            } else {
                let prefix = placeholder_prefix(&finding.entity_type);
                let next = counters.entry(prefix.clone()).or_insert(0);
                *next += 1;
                while existing.contains(&format!("{prefix}_{next}").to_ascii_uppercase()) {
                    *next += 1;
                }
                let placeholder = format!("{open}{prefix}_{next}{close}");
                entries.push(PromptMappingEntry {
                    placeholder: placeholder.clone(),
                    entity_type: finding.entity_type.clone(),
                    original: finding.text.clone(),
                    span_start: finding.span.start,
                    span_end: finding.span.end,
                    confidence: finding.confidence.value(),
                    recognizer_id: finding.recognizer_id.clone(),
                });
                assigned.insert(key, entries.len() - 1);
                placeholder
            };
            placeholder_for_finding.push(placeholder);
        }

        let mut clean_prompt = prompt.to_string();
        for (finding, placeholder) in findings.iter().zip(placeholder_for_finding.iter()).rev() {
            clean_prompt.replace_range(finding.span.start..finding.span.end, placeholder);
        }

        Ok((clean_prompt, PromptMapping { entries }))
    }

    /// Restores placeholders in model output using a previously returned mapping table.
    ///
    /// Uses tolerant matching by default: placeholders that differ from the original only
    /// by ASCII case or interior whitespace (e.g. `[ email_1 ]`) are still restored. Use
    /// [`restore_strict`](Self::restore_strict) to require an exact match.
    #[must_use]
    pub fn restore(&self, text: &str, mapping: &PromptMapping) -> String {
        mapping.restore(text)
    }

    /// Restores placeholders using exact matching only; no case or whitespace tolerance.
    #[must_use]
    pub fn restore_strict(&self, text: &str, mapping: &PromptMapping) -> String {
        mapping.restore_strict(text)
    }
}

/// Bracket style used to format placeholders such as `[EMAIL_1]` or `{EMAIL_1}`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlaceholderStyle {
    /// `[TYPE_N]` (the default).
    #[default]
    Brackets,
    /// `{TYPE_N}`.
    Braces,
}

impl PlaceholderStyle {
    /// Returns the `(open, close)` delimiter characters for this style.
    #[must_use]
    pub const fn chars(self) -> (char, char) {
        match self {
            Self::Brackets => ('[', ']'),
            Self::Braces => ('{', '}'),
        }
    }
}

/// Placeholder mapping returned by [`PromptSanitizer::sanitize`].
///
/// `Debug` output never contains original values; use [`PromptMappingEntry::original_value`]
/// for explicit, greppable access. Serialized JSON (`Serialize`/`Deserialize`) intentionally
/// contains the real values — the mapping file *is* the restore key and is useless without
/// them. Treat serialized mappings as sensitive material.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct PromptMapping {
    /// Placeholder entries in source-text order. Contains sensitive original values.
    /// Prefer [`entries`](Self::entries) when iterating.
    pub entries: Vec<PromptMappingEntry>,
}

impl PromptMapping {
    /// Builds a mapping directly from entries, using [`PlaceholderStyle::Brackets`].
    ///
    /// Mainly useful for tests and callers constructing a mapping outside of
    /// [`PromptSanitizer::sanitize`].
    #[must_use]
    pub fn new(entries: Vec<PromptMappingEntry>) -> Self {
        Self { entries }
    }

    /// Iterates over the mapping's entries in source-text order.
    pub fn entries(&self) -> impl Iterator<Item = &PromptMappingEntry> {
        self.entries.iter()
    }

    /// Looks up the entry for an exact placeholder string, such as `[EMAIL_1]`.
    #[must_use]
    pub fn get(&self, placeholder: &str) -> Option<&PromptMappingEntry> {
        self.entries
            .iter()
            .find(|entry| entry.placeholder == placeholder)
    }

    /// The first entry's delimiter style, or brackets for an empty mapping.
    #[must_use]
    pub fn style(&self) -> PlaceholderStyle {
        if self
            .entries
            .first()
            .is_some_and(|entry| entry.placeholder.starts_with('{'))
        {
            PlaceholderStyle::Braces
        } else {
            PlaceholderStyle::Brackets
        }
    }

    /// Restores all known placeholders in a string, tolerating ASCII case differences and
    /// interior whitespace (`[ EMAIL_1 ]`, `[email_1]`, `[Email_1]` all match `[EMAIL_1]`).
    ///
    /// Placeholder indexes are matched in full: `[EMAIL_1]` never matches within
    /// `[EMAIL_10]`. Unknown placeholders (valid shape, but not present in this mapping)
    /// are left untouched.
    #[must_use]
    pub fn restore(&self, text: &str) -> String {
        self.restore_impl(text)
    }

    /// Restores placeholders using exact matching only; no case or whitespace tolerance.
    #[must_use]
    pub fn restore_strict(&self, text: &str) -> String {
        let mut placeholders: Vec<&str> = self
            .entries
            .iter()
            .map(|entry| entry.placeholder.as_str())
            .filter(|p| !p.is_empty())
            .collect();
        placeholders.sort_by_key(|p| std::cmp::Reverse(p.len()));
        placeholders.dedup();
        if placeholders.is_empty() {
            return text.to_string();
        }
        let pattern = placeholders
            .iter()
            .map(|p| regex::escape(p))
            .collect::<Vec<_>>()
            .join("|");
        let Ok(regex) = Regex::new(&pattern) else {
            return text.to_string();
        };
        let mut lookup = HashMap::new();
        for entry in &self.entries {
            lookup
                .entry(entry.placeholder.as_str())
                .or_insert(entry.original.as_str());
        }
        regex
            .replace_all(text, |caps: &regex::Captures<'_>| {
                lookup
                    .get(&caps[0])
                    .map_or_else(|| caps[0].to_string(), |value| (*value).to_string())
            })
            .into_owned()
    }

    fn restore_impl(&self, text: &str) -> String {
        let mut lookup = HashMap::new();
        let mut patterns = Vec::new();
        let mut prefixes: HashMap<(char, char), Vec<String>> = HashMap::new();
        for entry in &self.entries {
            if entry.placeholder.is_empty() {
                continue;
            }
            lookup
                .entry(normalize_placeholder(&entry.placeholder))
                .or_insert(entry.original.as_str());
            let mut numbered = false;
            for (open, close) in [('[', ']'), ('{', '}')] {
                if let Some((prefix, _)) = parse_placeholder(&entry.placeholder, open, close) {
                    prefixes.entry((open, close)).or_default().push(prefix);
                    numbered = true;
                    break;
                }
            }
            if !numbered {
                patterns.push(regex::escape(&entry.placeholder));
            }
        }
        // One branch per prefix, not per entry: large mappings stay compact.
        for ((open, close), mut names) in prefixes {
            names.sort();
            names.dedup();
            names.sort_by_key(|name| std::cmp::Reverse(name.len()));
            let names = names
                .iter()
                .map(|name| regex::escape(name))
                .collect::<Vec<_>>()
                .join("|");
            patterns.push(format!(
                r"{}\s*(?i-u:{})_[0-9]+\s*{}",
                regex::escape(&open.to_string()),
                names,
                regex::escape(&close.to_string())
            ));
        }
        patterns.sort_by_key(|p| std::cmp::Reverse(p.len()));
        patterns.dedup();
        if patterns.is_empty() {
            return text.to_string();
        }
        let Ok(regex) = Regex::new(&patterns.join("|")) else {
            return text.to_string();
        };
        regex
            .replace_all(text, |caps: &regex::Captures<'_>| {
                lookup
                    .get(&normalize_placeholder(&caps[0]))
                    .map_or_else(|| caps[0].to_string(), |value| (*value).to_string())
            })
            .into_owned()
    }
}

fn normalize_placeholder(value: &str) -> String {
    for (open, close) in [('[', ']'), ('{', '}')] {
        if let Some(inner) = value.strip_prefix(open).and_then(|s| s.strip_suffix(close)) {
            return format!("{open}{}{close}", inner.trim().to_ascii_uppercase());
        }
    }
    value.to_string()
}

/// Split at the last underscore so multi-word prefixes are supported.
fn parse_placeholder(placeholder: &str, open: char, close: char) -> Option<(String, String)> {
    let inner = placeholder.strip_prefix(open)?.strip_suffix(close)?;
    let (prefix, index) = inner.rsplit_once('_')?;
    if index.is_empty() || !index.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some((prefix.to_string(), index.to_string()))
}

/// One placeholder-to-original-value mapping.
///
/// `Debug` output redacts [`original_value`](Self::original_value); it shows only the
/// placeholder, entity type, and confidence. Serde serialization still includes the real
/// value — see [`PromptMapping`].
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct PromptMappingEntry {
    /// Placeholder inserted into the sanitized prompt, such as `[EMAIL_1]`.
    pub placeholder: String,
    /// Entity type represented by this placeholder.
    pub entity_type: EntityType,
    /// Original sensitive value. Prefer [`original_value`](Self::original_value) for explicit access.
    pub original: String,
    /// Source prompt start byte offset of the first occurrence.
    pub span_start: usize,
    /// Source prompt end byte offset of the first occurrence.
    pub span_end: usize,
    /// Detection confidence.
    pub confidence: f64,
    /// Recognizer that produced the original finding.
    pub recognizer_id: String,
}

impl PromptMappingEntry {
    /// Constructs an entry directly. Mainly useful for tests and callers building mappings
    /// outside of [`PromptSanitizer::sanitize`].
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        placeholder: String,
        entity_type: EntityType,
        original: String,
        span_start: usize,
        span_end: usize,
        confidence: f64,
        recognizer_id: String,
    ) -> Self {
        Self {
            placeholder,
            entity_type,
            original,
            span_start,
            span_end,
            confidence,
            recognizer_id,
        }
    }

    /// Returns the original sensitive value this placeholder stands in for.
    ///
    /// Named explicitly so reads of sensitive data are
    /// greppable in downstream code.
    #[must_use]
    pub fn original_value(&self) -> &str {
        &self.original
    }
}

impl fmt::Debug for PromptMappingEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PromptMappingEntry")
            .field("placeholder", &self.placeholder)
            .field("entity_type", &self.entity_type)
            .field("original", &"<redacted>")
            .field("confidence", &self.confidence)
            .finish()
    }
}

impl fmt::Debug for PromptMapping {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PromptMapping")
            .field("entries", &self.entries)
            .field("style", &self.style())
            .finish()
    }
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
    use proptest::prelude::*;

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

    /// Recognizer that reports every occurrence of a fixed needle (used for dedup tests).
    struct RepeatingRecognizer {
        needle: &'static str,
        entity_type: EntityType,
    }

    impl Recognizer for RepeatingRecognizer {
        fn id(&self) -> &str {
            "repeating_test_v1"
        }

        fn entity_type(&self) -> EntityType {
            self.entity_type.clone()
        }

        fn supported_locales(&self) -> &[Locale] {
            &[]
        }

        fn scan(&self, text: &str) -> Vec<PiiEntity> {
            let mut findings = Vec::new();
            let mut start = 0;
            while let Some(offset) = text[start..].find(self.needle) {
                let match_start = start + offset;
                let match_end = match_start + self.needle.len();
                findings.push(PiiEntity {
                    entity_type: self.entity_type.clone(),
                    span: Span::new(match_start, match_end),
                    text: self.needle.to_string(),
                    confidence: Confidence::new(0.9).unwrap(),
                    recognizer_id: self.id().to_string(),
                });
                start = match_end;
            }
            findings
        }
    }

    /// Reports every occurrence of "shared-value" in the text, alternating entity types
    /// across occurrences (first is `Url`, second is `Email`, ...). Spans never overlap, so
    /// this exercises the sanitizer's own (entity_type, text) dedup key rather than the
    /// scanner's span-overlap merging.
    struct DualTypeRecognizer;

    impl Recognizer for DualTypeRecognizer {
        fn id(&self) -> &str {
            "dual_type_test_v1"
        }

        fn entity_type(&self) -> EntityType {
            EntityType::Url
        }

        fn supported_locales(&self) -> &[Locale] {
            &[]
        }

        fn scan(&self, text: &str) -> Vec<PiiEntity> {
            let needle = "shared-value";
            let types = [EntityType::Url, EntityType::Email];
            let mut findings = Vec::new();
            let mut start = 0;
            let mut occurrence = 0;
            while let Some(offset) = text[start..].find(needle) {
                let match_start = start + offset;
                let match_end = match_start + needle.len();
                findings.push(PiiEntity {
                    entity_type: types[occurrence % types.len()].clone(),
                    span: Span::new(match_start, match_end),
                    text: needle.to_string(),
                    confidence: Confidence::new(0.9).unwrap(),
                    recognizer_id: self.id().to_string(),
                });
                start = match_end;
                occurrence += 1;
            }
            findings
        }
    }

    fn sanitizer_with<R: Recognizer + 'static>(recognizer: R) -> PromptSanitizer {
        let scanner = Scanner::builder().recognizer(recognizer).build().unwrap();
        PromptSanitizer::new(scanner)
    }

    #[test]
    fn test_prompt_sanitizer_replaces_with_numbered_placeholders() {
        let sanitizer = sanitizer_with(MultiRecognizer);
        let (clean, mapping) = sanitizer
            .sanitize("Email jane@example.com and john@example.com")
            .unwrap();
        assert_eq!(clean, "Email [EMAIL_1] and [EMAIL_2]");
        let entries: Vec<_> = mapping.entries().collect();
        assert_eq!(entries[0].original_value(), "jane@example.com");
        assert_eq!(entries[1].placeholder, "[EMAIL_2]");
    }

    #[test]
    fn test_prompt_sanitizer_restore_reinjects_original_values() {
        let sanitizer = sanitizer_with(MultiRecognizer);
        let (_, mapping) = sanitizer
            .sanitize("Call +1 555 010 1234 or email jane@example.com")
            .unwrap();
        let restored = sanitizer.restore("Use [PHONE_1] and [EMAIL_1]", &mapping);
        assert_eq!(restored, "Use +1 555 010 1234 and jane@example.com");
    }

    #[test]
    fn test_prompt_mapping_restore_replaces_repeated_placeholders() {
        let mapping = PromptMapping::new(vec![PromptMappingEntry::new(
            "[EMAIL_1]".to_string(),
            EntityType::Email,
            "jane@example.com".to_string(),
            0,
            16,
            0.95,
            "test".to_string(),
        )]);
        assert_eq!(
            mapping.restore("[EMAIL_1] replied to [EMAIL_1]"),
            "jane@example.com replied to jane@example.com"
        );
    }

    // --- A1: dedup ---

    #[test]
    fn test_dedup_same_email_three_times_uses_one_placeholder_and_one_entry() {
        let sanitizer = sanitizer_with(RepeatingRecognizer {
            needle: "jane@example.com",
            entity_type: EntityType::Email,
        });
        let (clean, mapping) = sanitizer
            .sanitize("jane@example.com, jane@example.com, jane@example.com")
            .unwrap();
        assert_eq!(clean, "[EMAIL_1], [EMAIL_1], [EMAIL_1]");
        assert_eq!(mapping.entries().count(), 1);
    }

    #[test]
    fn test_dedup_two_different_emails_get_distinct_placeholders() {
        let sanitizer = sanitizer_with(MultiRecognizer);
        let (clean, mapping) = sanitizer
            .sanitize("jane@example.com and john@example.com")
            .unwrap();
        assert_eq!(clean, "[EMAIL_1] and [EMAIL_2]");
        assert_eq!(mapping.entries().count(), 2);
    }

    #[test]
    fn test_dedup_same_text_two_entity_types_keeps_two_placeholders() {
        let sanitizer = sanitizer_with(DualTypeRecognizer);
        let (clean, mapping) = sanitizer
            .sanitize("first: shared-value, second: shared-value")
            .unwrap();
        assert_eq!(clean, "first: [URL_1], second: [EMAIL_1]");
        assert_eq!(mapping.entries().count(), 2);
        let placeholders: Vec<_> = mapping.entries().map(|e| e.placeholder.clone()).collect();
        assert!(placeholders.contains(&"[URL_1]".to_string()));
        assert!(placeholders.contains(&"[EMAIL_1]".to_string()));
    }

    #[test]
    fn test_dedup_round_trip_restores_original_exactly() {
        let sanitizer = sanitizer_with(RepeatingRecognizer {
            needle: "jane@example.com",
            entity_type: EntityType::Email,
        });
        let original = "jane@example.com, jane@example.com, jane@example.com";
        let (clean, mapping) = sanitizer.sanitize(original).unwrap();
        assert_eq!(sanitizer.restore(&clean, &mapping), original);
    }

    // --- A2: Debug redaction ---

    #[test]
    fn test_debug_format_never_contains_original_values() {
        let sanitizer = sanitizer_with(MultiRecognizer);
        let (_, mapping) = sanitizer
            .sanitize("Call +1 555 010 1234 or email jane@example.com")
            .unwrap();
        let debug_output = format!("{mapping:?}");
        assert!(!debug_output.contains("jane@example.com"));
        assert!(!debug_output.contains("+1 555 010 1234"));
        assert!(debug_output.contains("[EMAIL_1]"));
        assert!(debug_output.contains("[PHONE_1]"));
    }

    #[test]
    fn test_debug_format_entry_redacts_original_value() {
        let entry = PromptMappingEntry::new(
            "[EMAIL_1]".to_string(),
            EntityType::Email,
            "jane@example.com".to_string(),
            0,
            16,
            0.95,
            "test".to_string(),
        );
        let debug_output = format!("{entry:?}");
        assert!(!debug_output.contains("jane@example.com"));
        assert!(debug_output.contains("<redacted>"));
    }

    #[test]
    fn test_serde_json_round_trip_still_restores_correctly() {
        let sanitizer = sanitizer_with(MultiRecognizer);
        let (clean, mapping) = sanitizer
            .sanitize("Call +1 555 010 1234 or email jane@example.com")
            .unwrap();
        let json = serde_json::to_string(&mapping).unwrap();
        assert!(json.contains("jane@example.com"));
        let restored_mapping: PromptMapping = serde_json::from_str(&json).unwrap();
        assert_eq!(
            sanitizer.restore(&clean, &restored_mapping),
            "Call +1 555 010 1234 or email jane@example.com"
        );
    }

    // --- A4: tolerant/strict matching ---

    #[test]
    fn test_tolerant_restore_accepts_case_and_whitespace_variants() {
        let mapping = PromptMapping::new(vec![PromptMappingEntry::new(
            "[EMAIL_1]".to_string(),
            EntityType::Email,
            "jane@example.com".to_string(),
            0,
            0,
            0.9,
            "test".to_string(),
        )]);
        for variant in ["[ EMAIL_1 ]", "[email_1]", "[Email_1]", "[EMAIL_1]"] {
            assert_eq!(mapping.restore(variant), "jane@example.com", "{variant}");
        }
    }

    #[test]
    fn test_strict_restore_rejects_variants_but_accepts_exact() {
        let mapping = PromptMapping::new(vec![PromptMappingEntry::new(
            "[EMAIL_1]".to_string(),
            EntityType::Email,
            "jane@example.com".to_string(),
            0,
            0,
            0.9,
            "test".to_string(),
        )]);
        for variant in ["[ EMAIL_1 ]", "[email_1]", "[Email_1]"] {
            assert_eq!(mapping.restore_strict(variant), variant, "{variant}");
        }
        assert_eq!(mapping.restore_strict("[EMAIL_1]"), "jane@example.com");
    }

    #[test]
    fn test_tolerant_restore_does_not_match_longer_index() {
        let mapping = PromptMapping::new(vec![PromptMappingEntry::new(
            "[EMAIL_1]".to_string(),
            EntityType::Email,
            "jane@example.com".to_string(),
            0,
            0,
            0.9,
            "test".to_string(),
        )]);
        assert_eq!(mapping.restore("[EMAIL_10]"), "[EMAIL_10]");
    }

    #[test]
    fn test_unknown_index_left_as_is_no_panic() {
        let mapping = PromptMapping::new(vec![PromptMappingEntry::new(
            "[EMAIL_1]".to_string(),
            EntityType::Email,
            "jane@example.com".to_string(),
            0,
            0,
            0.9,
            "test".to_string(),
        )]);
        assert_eq!(mapping.restore("[EMAIL_999]"), "[EMAIL_999]");
    }

    #[test]
    fn test_unknown_prefix_left_untouched_in_both_modes() {
        let mapping = PromptMapping::new(vec![PromptMappingEntry::new(
            "[EMAIL_1]".to_string(),
            EntityType::Email,
            "jane@example.com".to_string(),
            0,
            0,
            0.9,
            "test".to_string(),
        )]);
        assert_eq!(mapping.restore("[PERSON_1]"), "[PERSON_1]");
        assert_eq!(mapping.restore_strict("[PERSON_1]"), "[PERSON_1]");
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        /// `restore(sanitize(text))` reproduces the original text exactly, for random ASCII
        /// text with a known email value injected at a random position.
        #[test]
        fn test_property_sanitize_restore_round_trips_injected_pii(
            prefix_text in "[a-zA-Z0-9 .,!?]{0,40}",
            suffix_text in "[a-zA-Z0-9 .,!?]{0,40}",
        ) {
            let email = "jane@example.com";
            let original = format!("{prefix_text} {email} {suffix_text}");
            let sanitizer = sanitizer_with(RepeatingRecognizer {
                needle: email,
                entity_type: EntityType::Email,
            });
            let (clean, mapping) = sanitizer.sanitize(&original).unwrap();
            let restored = sanitizer.restore(&clean, &mapping);
            prop_assert_eq!(restored, original);
        }

        #[test]
        fn test_property_tolerant_and_strict_agree_on_exact_placeholders(
            prefix in "[A-Z]{3,8}",
            index in 1u64..500,
            value in "[a-zA-Z0-9]{1,20}",
            before in "[a-zA-Z0-9 ]{0,10}",
            after in "[a-zA-Z0-9 ]{0,10}",
        ) {
            let placeholder = format!("[{prefix}_{index}]");
            let mapping = PromptMapping::new(vec![PromptMappingEntry::new(
                placeholder.clone(),
                EntityType::Custom(prefix.clone()),
                value,
                0,
                0,
                0.9,
                "test".to_string(),
            )]);
            let text = format!("{before}{placeholder}{after}");
            prop_assert_eq!(mapping.restore(&text), mapping.restore_strict(&text));
        }
    }

    // --- A5: additional edge cases ---

    #[test]
    fn test_sanitize_empty_input_returns_empty_output_and_no_findings() {
        let sanitizer = sanitizer_with(MultiRecognizer);
        let (clean, mapping) = sanitizer.sanitize("").unwrap();
        assert_eq!(clean, "");
        assert_eq!(mapping.entries().count(), 0);
    }

    #[test]
    fn test_sanitize_input_with_zero_findings_is_unchanged() {
        let sanitizer = sanitizer_with(MultiRecognizer);
        let (clean, mapping) = sanitizer.sanitize("nothing sensitive here").unwrap();
        assert_eq!(clean, "nothing sensitive here");
        assert_eq!(mapping.entries().count(), 0);
    }

    #[test]
    fn test_sanitize_input_that_is_only_a_pii_value() {
        let sanitizer = sanitizer_with(RepeatingRecognizer {
            needle: "jane@example.com",
            entity_type: EntityType::Email,
        });
        let (clean, mapping) = sanitizer.sanitize("jane@example.com").unwrap();
        assert_eq!(clean, "[EMAIL_1]");
        assert_eq!(sanitizer.restore(&clean, &mapping), "jane@example.com");
    }

    #[test]
    fn test_sanitize_restore_round_trip_with_emoji_and_cjk_adjacent_to_pii() {
        let sanitizer = sanitizer_with(RepeatingRecognizer {
            needle: "jane@example.com",
            entity_type: EntityType::Email,
        });
        let original = "😀你好 jane@example.com 再见🎉";
        let (clean, mapping) = sanitizer.sanitize(original).unwrap();
        assert!(clean.contains("[EMAIL_1]"));
        assert_eq!(sanitizer.restore(&clean, &mapping), original);
    }

    #[test]
    fn test_sanitize_restore_round_trip_overlapping_style_findings() {
        // Two recognizers reporting overlapping spans (email inside a longer URL-ish
        // string): sanitize should still produce a well-formed, restorable output.
        struct OverlappingRecognizer;
        impl Recognizer for OverlappingRecognizer {
            fn id(&self) -> &str {
                "overlap_test_v1"
            }
            fn entity_type(&self) -> EntityType {
                EntityType::Url
            }
            fn supported_locales(&self) -> &[Locale] {
                &[]
            }
            fn scan(&self, text: &str) -> Vec<PiiEntity> {
                let needle = "https://jane@example.com/path";
                let Some(start) = text.find(needle) else {
                    return Vec::new();
                };
                vec![PiiEntity {
                    entity_type: EntityType::Url,
                    span: Span::new(start, start + needle.len()),
                    text: needle.to_string(),
                    confidence: Confidence::new(0.9).unwrap(),
                    recognizer_id: self.id().to_string(),
                }]
            }
        }

        let sanitizer = sanitizer_with(OverlappingRecognizer);
        let original = "link: https://jane@example.com/path end";
        let (clean, mapping) = sanitizer.sanitize(original).unwrap();
        assert_eq!(clean, "link: [URL_1] end");
        assert_eq!(sanitizer.restore(&clean, &mapping), original);
    }

    #[test]
    fn test_placeholder_style_braces_round_trips() {
        let sanitizer = sanitizer_with(MultiRecognizer);
        let (clean, mapping) = sanitizer
            .sanitize_with_style("email jane@example.com", PlaceholderStyle::Braces)
            .unwrap();
        assert_eq!(clean, "email {EMAIL_1}");
        assert_eq!(
            sanitizer.restore(&clean, &mapping),
            "email jane@example.com"
        );
    }
    #[test]
    fn test_existing_placeholder_text_round_trips_without_collision() {
        let sanitizer = sanitizer_with(MultiRecognizer);
        for original in [
            "[EMAIL_1] [ email_2 ] jane@example.com",
            "{email_1} jane@example.com",
        ] {
            for style in [PlaceholderStyle::Brackets, PlaceholderStyle::Braces] {
                let (clean, mapping) = sanitizer.sanitize_with_style(original, style).unwrap();
                assert_eq!(mapping.restore(&clean), original);
            }
        }
    }

    #[test]
    fn test_public_mapping_literals_and_custom_placeholders_remain_compatible() {
        let mapping = PromptMapping {
            entries: vec![PromptMappingEntry {
                placeholder: "TOKEN".into(),
                entity_type: EntityType::Email,
                original: "jane@example.com".into(),
                span_start: 0,
                span_end: 16,
                confidence: 0.95,
                recognizer_id: "test".into(),
            }],
        };
        assert_eq!(mapping.entries[0].original, "jane@example.com");
        assert_eq!(mapping.restore("TOKEN"), "jane@example.com");
    }

    #[test]
    fn test_restore_preserves_index_spelling_and_is_not_recursive() {
        let mapping = PromptMapping::new(vec![
            PromptMappingEntry::new(
                "[EMAIL_1]".into(),
                EntityType::Email,
                "[EMAIL_2]".into(),
                0,
                0,
                0.9,
                "test".into(),
            ),
            PromptMappingEntry::new(
                "[EMAIL_2]".into(),
                EntityType::Email,
                "secret".into(),
                0,
                0,
                0.9,
                "test".into(),
            ),
        ]);
        for text in ["[EMAIL_01]", "[EMAIL_10]"] {
            assert_eq!(mapping.restore(text), text);
            assert_eq!(mapping.restore_strict(text), text);
        }
        assert_eq!(mapping.restore("[EMAIL_1]"), "[EMAIL_2]");
        assert_eq!(mapping.restore_strict("[EMAIL_1]"), "[EMAIL_2]");
    }
}
