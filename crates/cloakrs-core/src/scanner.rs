//! Scanner orchestration.

use crate::masker::deduplicate;
use crate::{
    apply_mask, CloakError, Confidence, EntityType, Locale, MaskStrategy, PiiEntity, Recognizer,
    RecognizerRegistry, Result,
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::time::Instant;

/// Builder for configuring a [`Scanner`].
///
/// # Examples
///
/// ```
/// use cloakrs_core::{Locale, Scanner};
///
/// let scanner = Scanner::builder().locale(Locale::US).build();
/// assert!(scanner.is_err());
/// ```
pub struct ScannerBuilder {
    registry: RecognizerRegistry,
    locale: Locale,
    strategy: Option<MaskStrategy>,
    min_confidence: Confidence,
    allow_list: Vec<String>,
    deny_list: Vec<String>,
    excluded_entities: HashSet<EntityType>,
}

impl Default for ScannerBuilder {
    fn default() -> Self {
        Self {
            registry: RecognizerRegistry::new(),
            locale: Locale::Universal,
            strategy: Some(MaskStrategy::default()),
            min_confidence: Confidence::ZERO,
            allow_list: Vec::new(),
            deny_list: Vec::new(),
            excluded_entities: HashSet::new(),
        }
    }
}

impl ScannerBuilder {
    /// Creates a scanner builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a scanner builder from an existing recognizer registry.
    #[must_use]
    pub fn from_registry(registry: RecognizerRegistry) -> Self {
        Self {
            registry,
            ..Self::default()
        }
    }

    /// Sets the scanner locale.
    #[must_use]
    pub fn locale(mut self, locale: Locale) -> Self {
        self.locale = locale;
        self
    }

    /// Sets the masking strategy.
    #[must_use]
    pub fn strategy(mut self, strategy: MaskStrategy) -> Self {
        self.strategy = Some(strategy);
        self
    }

    /// Disables masked text generation.
    #[must_use]
    pub fn without_masking(mut self) -> Self {
        self.strategy = None;
        self
    }

    /// Adds a recognizer.
    #[must_use]
    pub fn recognizer<R>(mut self, recognizer: R) -> Self
    where
        R: Recognizer + 'static,
    {
        self.registry.register(recognizer);
        self
    }

    /// Adds a boxed recognizer.
    #[must_use]
    pub fn boxed_recognizer(mut self, recognizer: Box<dyn Recognizer>) -> Self {
        self.registry.register_boxed(recognizer);
        self
    }

    /// Sets the minimum confidence threshold.
    pub fn min_confidence(mut self, confidence: f64) -> Result<Self> {
        self.min_confidence = Confidence::new(confidence)?;
        Ok(self)
    }

    /// Adds literal values that should never be reported or masked.
    #[must_use]
    pub fn allow_list<I, S>(mut self, values: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.allow_list.extend(
            values
                .into_iter()
                .map(Into::into)
                .filter(|value| !value.is_empty()),
        );
        self
    }

    /// Adds literal values that should always be reported and masked.
    #[must_use]
    pub fn deny_list<I, S>(mut self, values: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.deny_list.extend(
            values
                .into_iter()
                .map(Into::into)
                .filter(|value| !value.is_empty()),
        );
        self
    }

    /// Excludes findings for selected entity types.
    #[must_use]
    pub fn exclude_entities<I>(mut self, entity_types: I) -> Self
    where
        I: IntoIterator<Item = EntityType>,
    {
        self.excluded_entities.extend(entity_types);
        self
    }

    /// Builds a scanner.
    pub fn build(self) -> Result<Scanner> {
        if self.registry.is_empty() {
            return Err(CloakError::NoRecognizers);
        }

        Ok(Scanner {
            registry: self.registry,
            locale: self.locale,
            strategy: self.strategy,
            min_confidence: self.min_confidence,
            allow_list: self.allow_list,
            deny_list: self.deny_list,
            excluded_entities: self.excluded_entities,
        })
    }
}

/// The main scanner that ties detection and masking together.
pub struct Scanner {
    registry: RecognizerRegistry,
    locale: Locale,
    strategy: Option<MaskStrategy>,
    min_confidence: Confidence,
    allow_list: Vec<String>,
    deny_list: Vec<String>,
    excluded_entities: HashSet<EntityType>,
}

impl Scanner {
    /// Creates a scanner builder.
    #[must_use]
    pub fn builder() -> ScannerBuilder {
        ScannerBuilder::new()
    }

    /// Scans text and returns findings, optional masked text, and stats.
    pub fn scan(&self, text: &str) -> Result<ScanResult> {
        let started = Instant::now();
        let mut findings = self.registry.scan_locale(text, &self.locale);
        findings.retain(|finding| !self.excluded_entities.contains(&finding.entity_type));
        findings.extend(deny_list_findings(text, &self.deny_list));
        let allow_spans = literal_spans(text, &self.allow_list);
        findings.retain(|finding| !allow_spans.iter().any(|span| span.overlaps(finding.span)));
        findings.retain(|finding| finding.confidence >= self.min_confidence);
        findings = deduplicate_for_reporting(&findings);
        findings.sort_by_key(|finding| finding.span.start);

        let masked_text = self
            .strategy
            .as_ref()
            .map(|strategy| apply_mask(text, &findings, strategy))
            .transpose()?;

        let stats = ScanStats::from_findings(&findings, started.elapsed().as_millis(), text.len());

        Ok(ScanResult {
            findings,
            masked_text,
            stats,
        })
    }
}

fn deny_list_findings(text: &str, deny_list: &[String]) -> Vec<PiiEntity> {
    literal_spans(text, deny_list)
        .into_iter()
        .map(|span| PiiEntity {
            entity_type: EntityType::Custom("DenyList".to_string()),
            span,
            text: text[span.start..span.end].to_string(),
            confidence: Confidence::ONE,
            recognizer_id: "deny_list_v1".to_string(),
        })
        .collect()
}

fn literal_spans(text: &str, values: &[String]) -> Vec<crate::Span> {
    let mut spans = Vec::new();
    for value in values {
        if value.is_empty() {
            continue;
        }
        let mut search_start = 0;
        while let Some(offset) = text[search_start..].find(value) {
            let start = search_start + offset;
            let end = start + value.len();
            spans.push(crate::Span::new(start, end));
            search_start = end;
        }
    }
    spans
}

fn deduplicate_for_reporting(findings: &[PiiEntity]) -> Vec<PiiEntity> {
    let mut sorted = findings.to_vec();
    sorted.sort_by_key(|finding| (finding.span.start, std::cmp::Reverse(finding.span.end)));

    let mut keep: Vec<PiiEntity> = Vec::with_capacity(sorted.len());
    for finding in sorted {
        if keep
            .iter()
            .any(|kept| should_preserve_nested_url_query(kept, &finding))
        {
            keep.push(finding);
            continue;
        }

        if let Some(overlap_index) = keep
            .iter()
            .rposition(|kept| finding.span.overlaps(kept.span))
        {
            if should_keep_existing_url_query(&keep[overlap_index], &finding) {
                continue;
            }
            if should_replace_with_url_query(&keep[overlap_index], &finding) {
                keep[overlap_index] = finding;
                continue;
            }

            let merged = deduplicate(&[keep[overlap_index].clone(), finding])
                .into_iter()
                .next()
                .unwrap_or_else(|| keep[overlap_index].clone());
            keep[overlap_index] = merged;
            continue;
        }
        keep.push(finding);
    }

    keep
}

fn should_preserve_nested_url_query(outer: &PiiEntity, inner: &PiiEntity) -> bool {
    outer.entity_type == EntityType::Url
        && inner.recognizer_id.starts_with("url_query_")
        && inner.span.start >= outer.span.start
        && inner.span.end <= outer.span.end
}

fn should_keep_existing_url_query(existing: &PiiEntity, incoming: &PiiEntity) -> bool {
    existing.span == incoming.span
        && existing.entity_type == incoming.entity_type
        && existing.recognizer_id.starts_with("url_query_")
        && !incoming.recognizer_id.starts_with("url_query_")
}

fn should_replace_with_url_query(existing: &PiiEntity, incoming: &PiiEntity) -> bool {
    existing.span == incoming.span
        && existing.entity_type == incoming.entity_type
        && !existing.recognizer_id.starts_with("url_query_")
        && incoming.recognizer_id.starts_with("url_query_")
}

/// Result of scanning text.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScanResult {
    /// All PII entities found.
    pub findings: Vec<PiiEntity>,
    /// Text with PII masked, when masking is enabled.
    pub masked_text: Option<String>,
    /// Statistics about the scan.
    pub stats: ScanStats,
}

/// Statistics about a scan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanStats {
    /// Total number of findings.
    pub total_findings: usize,
    /// Count of findings per entity type.
    pub findings_by_type: HashMap<EntityType, usize>,
    /// Wall-clock scan duration in milliseconds.
    pub scan_duration_ms: u64,
    /// Number of input bytes scanned.
    pub bytes_scanned: usize,
}

impl ScanStats {
    fn from_findings(findings: &[PiiEntity], duration_ms: u128, bytes_scanned: usize) -> Self {
        let mut findings_by_type = HashMap::new();
        for finding in findings {
            *findings_by_type
                .entry(finding.entity_type.clone())
                .or_insert(0) += 1;
        }

        Self {
            total_findings: findings.len(),
            findings_by_type,
            scan_duration_ms: duration_ms.try_into().unwrap_or(u64::MAX),
            bytes_scanned,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Span;

    struct EmailRecognizer;

    impl Recognizer for EmailRecognizer {
        fn id(&self) -> &str {
            "email_test_v1"
        }

        fn entity_type(&self) -> EntityType {
            EntityType::Email
        }

        fn supported_locales(&self) -> &[Locale] {
            &[]
        }

        fn scan(&self, text: &str) -> Vec<PiiEntity> {
            let Some(start) = text
                .find('@')
                .and_then(|at| text[..at].rfind(' ').map(|space| space + 1).or(Some(0)))
            else {
                return Vec::new();
            };
            let end = text[start..]
                .find(' ')
                .map_or(text.len(), |offset| start + offset);
            vec![PiiEntity {
                entity_type: EntityType::Email,
                span: Span::new(start, end),
                text: text[start..end].to_string(),
                confidence: Confidence::new(0.95).unwrap(),
                recognizer_id: self.id().to_string(),
            }]
        }
    }

    #[test]
    fn test_scanner_builder_without_recognizers_errors() {
        assert!(Scanner::builder().build().is_err());
    }

    #[test]
    fn test_scanner_scan_returns_findings_and_masked_text() {
        let scanner = Scanner::builder()
            .recognizer(EmailRecognizer)
            .build()
            .unwrap();
        let result = scanner.scan("Contact user@example.com").unwrap();
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.masked_text.as_deref(), Some("Contact [EMAIL]"));
    }

    #[test]
    fn test_scanner_without_masking_returns_no_masked_text() {
        let scanner = Scanner::builder()
            .recognizer(EmailRecognizer)
            .without_masking()
            .build()
            .unwrap();
        let result = scanner.scan("Contact user@example.com").unwrap();
        assert!(result.masked_text.is_none());
    }

    #[test]
    fn test_scanner_min_confidence_filters_low_confidence_findings() {
        let scanner = Scanner::builder()
            .recognizer(EmailRecognizer)
            .min_confidence(1.0)
            .unwrap()
            .build()
            .unwrap();
        let result = scanner.scan("Contact user@example.com").unwrap();
        assert!(result.findings.is_empty());
    }

    #[test]
    fn test_scanner_allow_list_suppresses_overlapping_findings() {
        let scanner = Scanner::builder()
            .recognizer(EmailRecognizer)
            .allow_list(["user@example.com"])
            .build()
            .unwrap();
        let result = scanner.scan("Contact user@example.com").unwrap();
        assert!(result.findings.is_empty());
        assert_eq!(
            result.masked_text.as_deref(),
            Some("Contact user@example.com")
        );
    }

    #[test]
    fn test_scanner_excludes_selected_entity_types() {
        let scanner = Scanner::builder()
            .recognizer(EmailRecognizer)
            .exclude_entities([EntityType::Email])
            .build()
            .unwrap();
        let result = scanner.scan("Contact user@example.com").unwrap();
        assert!(result.findings.is_empty());
        assert_eq!(
            result.masked_text.as_deref(),
            Some("Contact user@example.com")
        );
    }

    #[test]
    fn test_scanner_deny_list_adds_custom_finding() {
        let scanner = Scanner::builder()
            .recognizer(EmailRecognizer)
            .deny_list(["PRJ-12345"])
            .build()
            .unwrap();
        let result = scanner.scan("ticket PRJ-12345").unwrap();
        assert_eq!(result.findings.len(), 1);
        assert_eq!(
            result.findings[0].entity_type,
            EntityType::Custom("DenyList".to_string())
        );
        assert_eq!(result.masked_text.as_deref(), Some("ticket [DENYLIST]"));
    }
}
