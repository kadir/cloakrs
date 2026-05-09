//! Plaintext scanning adapter.

use cloakrs_core::{PiiEntity, Result, Scanner};
use serde::{Deserialize, Serialize};
use std::io::BufRead;

/// PII findings for one line of plaintext.
///
/// Spans are byte offsets relative to the line content.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LineScanResult {
    /// One-based line number.
    pub line_number: usize,
    /// Findings detected on this line.
    pub findings: Vec<PiiEntity>,
    /// Masked line when the scanner has masking enabled.
    pub masked_line: Option<String>,
}

/// Scans a string as plaintext, line by line.
///
/// # Examples
///
/// ```
/// use cloakrs_core::{Confidence, EntityType, Locale, PiiEntity, Recognizer, Scanner, Span};
/// use cloakrs_adapters::scan_text;
///
/// struct Email;
/// impl Recognizer for Email {
///     fn id(&self) -> &str { "email_test" }
///     fn entity_type(&self) -> EntityType { EntityType::Email }
///     fn supported_locales(&self) -> &[Locale] { &[] }
///     fn scan(&self, text: &str) -> Vec<PiiEntity> {
///         text.find('@').map(|_| PiiEntity {
///             entity_type: EntityType::Email,
///             span: Span::new(0, text.len()),
///             text: text.to_string(),
///             confidence: Confidence::new(0.9).unwrap(),
///             recognizer_id: self.id().to_string(),
///         }).into_iter().collect()
///     }
/// }
///
/// let scanner = Scanner::builder().recognizer(Email).build().unwrap();
/// let results = scan_text("a@b.test\nplain", &scanner).unwrap();
/// assert_eq!(results.len(), 2);
/// ```
pub fn scan_text(text: &str, scanner: &Scanner) -> Result<Vec<LineScanResult>> {
    scan_lines(std::io::Cursor::new(text), scanner)
}

/// Scans a buffered reader as plaintext without loading the whole input.
pub fn scan_lines<R>(reader: R, scanner: &Scanner) -> Result<Vec<LineScanResult>>
where
    R: BufRead,
{
    let mut results = Vec::new();
    for (index, line) in reader.lines().enumerate() {
        let line = line?;
        let scan = scanner.scan(&line)?;
        results.push(LineScanResult {
            line_number: index + 1,
            findings: scan.findings,
            masked_line: scan.masked_text,
        });
    }
    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cloakrs_core::Locale;
    use cloakrs_patterns::default_registry;

    fn scanner() -> Scanner {
        default_registry()
            .into_scanner_builder()
            .locale(Locale::US)
            .build()
            .unwrap()
    }

    #[test]
    fn test_scan_text_multiline_reports_line_numbers() {
        let results =
            scan_text("email jane@example.com\nplain\nssn 123-45-6789", &scanner()).unwrap();
        assert_eq!(results[0].line_number, 1);
        assert_eq!(results[1].line_number, 2);
        assert_eq!(results[2].line_number, 3);
        assert_eq!(results[0].findings.len(), 1);
        assert_eq!(results[2].findings.len(), 1);
    }

    #[test]
    fn test_scan_text_empty_lines_are_preserved() {
        let results = scan_text("\nemail jane@example.com", &scanner()).unwrap();
        assert_eq!(results.len(), 2);
        assert!(results[0].findings.is_empty());
    }

    #[test]
    fn test_scan_text_long_line_detects_finding() {
        let mut line = "a".repeat(12_000);
        line.push_str(" email jane@example.com");
        let results = scan_text(&line, &scanner()).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].findings.len(), 1);
    }
}
