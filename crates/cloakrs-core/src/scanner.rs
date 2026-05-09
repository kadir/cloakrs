//! Scanner orchestration.

use crate::masker::deduplicate;
use crate::{
    apply_mask, CloakError, Confidence, EntityType, Locale, MaskStrategy, PiiEntity, Recognizer,
    RecognizerRegistry, Result,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
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
}

impl Default for ScannerBuilder {
    fn default() -> Self {
        Self {
            registry: RecognizerRegistry::new(),
            locale: Locale::Universal,
            strategy: Some(MaskStrategy::default()),
            min_confidence: Confidence::ZERO,
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
        })
    }
}

/// The main scanner that ties detection and masking together.
pub struct Scanner {
    registry: RecognizerRegistry,
    locale: Locale,
    strategy: Option<MaskStrategy>,
    min_confidence: Confidence,
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
}
