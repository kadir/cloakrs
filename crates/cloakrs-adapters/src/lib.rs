//! Format adapters for scanning files and streams.
//!
//! JSON, CSV, plaintext, log stream, and SQL dump adapters live here.

pub mod csv;
pub mod json;
pub mod logstream;
pub mod plaintext;
pub mod sql;

pub use csv::{mask_csv_reader, scan_csv_str, CsvCellScanResult, CsvScanOptions, CsvScanResult};
pub use json::{
    scan_json_str, scan_json_value, JsonScanOptions, JsonScanResult, JsonStringScanResult,
};
pub use logstream::{
    mask_log_reader, scan_log_str, LogLineFormat, LogLineScanResult, LogStreamScanResult,
};
pub use plaintext::{scan_lines, scan_text, LineScanResult};
pub use sql::{mask_sql_reader, scan_sql_str, SqlScanResult, SqlValueScanResult};

use cloakrs_core::{PiiEntity, Result, Scanner};
use serde::{Deserialize, Serialize};

/// Supported adapter kinds for common report output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdapterKind {
    /// Plain text adapter.
    Plaintext,
    /// JSON adapter.
    Json,
    /// CSV adapter.
    Csv,
    /// Log stream adapter.
    LogStream,
    /// SQL dump adapter.
    Sql,
}

/// A grouped finding location exposed through the common adapter report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AdapterFinding {
    /// Human-readable location such as `line:1`, `$.user.email`, or `row:1,column:2`.
    pub location: String,
    /// Findings detected at this location.
    pub findings: Vec<PiiEntity>,
    /// Masked value for this location, when available.
    pub masked_value: Option<String>,
}

/// Common report shape returned by simple adapter wrappers.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AdapterReport {
    /// Adapter that produced this report.
    pub kind: AdapterKind,
    /// Findings grouped by adapter-specific location.
    pub findings: Vec<AdapterFinding>,
    /// Masked output for the whole input.
    pub masked_output: String,
}

/// A simple string-to-string adapter interface for library and CLI callers.
///
/// # Examples
///
/// ```
/// use cloakrs_adapters::{Adapter, PlaintextAdapter};
/// use cloakrs_core::{Confidence, EntityType, Locale, PiiEntity, Recognizer, Scanner, Span};
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
/// let report = PlaintextAdapter.scan_str("a@test", &scanner).unwrap();
/// assert_eq!(report.findings.len(), 1);
/// ```
pub trait Adapter {
    /// Scans input text and returns a common report.
    fn scan_str(&self, input: &str, scanner: &Scanner) -> Result<AdapterReport>;
}

/// Plaintext adapter wrapper.
#[derive(Debug, Default, Clone, Copy)]
pub struct PlaintextAdapter;

/// JSON adapter wrapper.
#[derive(Debug, Default, Clone)]
pub struct JsonAdapter {
    /// JSON path scanning options.
    pub options: JsonScanOptions,
}

/// CSV adapter wrapper.
#[derive(Debug, Default, Clone)]
pub struct CsvAdapter {
    /// CSV scanning options.
    pub options: CsvScanOptions,
}

/// Log stream adapter wrapper.
#[derive(Debug, Default, Clone, Copy)]
pub struct LogStreamAdapter;

/// SQL dump adapter wrapper.
#[derive(Debug, Default, Clone, Copy)]
pub struct SqlAdapter;

impl Adapter for PlaintextAdapter {
    fn scan_str(&self, input: &str, scanner: &Scanner) -> Result<AdapterReport> {
        let lines = scan_text(input, scanner)?;
        let findings = lines
            .iter()
            .filter(|line| !line.findings.is_empty())
            .map(|line| AdapterFinding {
                location: format!("line:{}", line.line_number),
                findings: line.findings.clone(),
                masked_value: line.masked_line.clone(),
            })
            .collect();
        let masked_output = masked_plaintext_output(input, &lines);
        Ok(AdapterReport {
            kind: AdapterKind::Plaintext,
            findings,
            masked_output,
        })
    }
}

fn masked_plaintext_output(input: &str, lines: &[LineScanResult]) -> String {
    let mut output = String::with_capacity(input.len());
    for (index, segment) in input.split_inclusive('\n').enumerate() {
        let line = segment.strip_suffix('\n').unwrap_or(segment);
        let line = line.strip_suffix('\r').unwrap_or(line);
        let masked = lines
            .get(index)
            .and_then(|result| result.masked_line.as_deref())
            .unwrap_or(line);
        output.push_str(masked);
        if segment.ends_with('\n') {
            if segment.ends_with("\r\n") {
                output.push('\r');
            }
            output.push('\n');
        }
    }
    if !input.contains('\n') {
        return lines
            .first()
            .and_then(|result| result.masked_line.clone())
            .unwrap_or_else(|| input.to_string());
    }
    output
}

impl Adapter for JsonAdapter {
    fn scan_str(&self, input: &str, scanner: &Scanner) -> Result<AdapterReport> {
        let result = scan_json_str(input, scanner, &self.options)?;
        let findings = result
            .strings
            .into_iter()
            .map(|string| AdapterFinding {
                location: string.path,
                findings: string.findings,
                masked_value: string.masked_value,
            })
            .collect();
        Ok(AdapterReport {
            kind: AdapterKind::Json,
            findings,
            masked_output: serde_json::to_string(&result.masked_json)?,
        })
    }
}

impl Adapter for CsvAdapter {
    fn scan_str(&self, input: &str, scanner: &Scanner) -> Result<AdapterReport> {
        let result = scan_csv_str(input, scanner, &self.options)?;
        let findings = result
            .cells
            .into_iter()
            .map(|cell| AdapterFinding {
                location: format!("row:{},column:{}", cell.row_number, cell.column_index),
                findings: cell.findings,
                masked_value: cell.masked_value,
            })
            .collect();
        Ok(AdapterReport {
            kind: AdapterKind::Csv,
            findings,
            masked_output: result.masked_csv,
        })
    }
}

impl Adapter for LogStreamAdapter {
    fn scan_str(&self, input: &str, scanner: &Scanner) -> Result<AdapterReport> {
        let result = scan_log_str(input, scanner)?;
        let findings = result
            .lines
            .into_iter()
            .filter(|line| !line.findings.is_empty())
            .map(|line| AdapterFinding {
                location: format!("line:{}", line.line_number),
                findings: line.findings,
                masked_value: line.masked_line,
            })
            .collect();
        Ok(AdapterReport {
            kind: AdapterKind::LogStream,
            findings,
            masked_output: result.masked_log,
        })
    }
}

impl Adapter for SqlAdapter {
    fn scan_str(&self, input: &str, scanner: &Scanner) -> Result<AdapterReport> {
        let result = scan_sql_str(input, scanner)?;
        let findings = result
            .values
            .into_iter()
            .map(|value| AdapterFinding {
                location: format!(
                    "statement:{},value:{}",
                    value.statement_number, value.value_index
                ),
                findings: value.findings,
                masked_value: value.masked_value,
            })
            .collect();
        Ok(AdapterReport {
            kind: AdapterKind::Sql,
            findings,
            masked_output: result.masked_sql,
        })
    }
}

/// Returns the crate version.
#[must_use]
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
