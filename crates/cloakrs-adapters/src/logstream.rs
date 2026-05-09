//! Log stream adapter for line-by-line scanning.

use crate::{scan_json_str, JsonScanOptions};
use cloakrs_core::{PiiEntity, Result, Scanner};
use serde::{Deserialize, Serialize};
use std::io::{BufRead, Write};

/// The practical shape detected for one log line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LogLineFormat {
    /// Plain text or an unrecognized log format.
    Plaintext,
    /// A valid JSON log line.
    Json,
    /// A log line containing `key=value` fields.
    KeyValue,
}

/// PII findings for one streamed log line.
///
/// Spans are byte offsets relative to the original line content.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LogLineScanResult {
    /// One-based line number.
    pub line_number: usize,
    /// Detected practical log format for the line.
    pub format: LogLineFormat,
    /// Findings detected on this line.
    pub findings: Vec<PiiEntity>,
    /// Masked line when the scanner has masking enabled.
    pub masked_line: Option<String>,
}

/// Scans log text line by line.
///
/// # Examples
///
/// ```
/// use cloakrs_adapters::scan_log_str;
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
/// let result = scan_log_str("user=a@test\n", &scanner).unwrap();
/// assert_eq!(result.lines.len(), 1);
/// ```
pub fn scan_log_str(input: &str, scanner: &Scanner) -> Result<LogStreamScanResult> {
    let mut output = Vec::new();
    let lines = mask_log_reader(input.as_bytes(), &mut output, scanner)?;
    let masked_log = String::from_utf8(output)
        .map_err(|error| cloakrs_core::CloakError::ConfigError(error.to_string()))?;
    Ok(LogStreamScanResult { lines, masked_log })
}

/// Result of scanning a log stream.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LogStreamScanResult {
    /// Findings grouped by log line.
    pub lines: Vec<LogLineScanResult>,
    /// Masked log text.
    pub masked_log: String,
}

/// Streams logs from a reader to a writer, masking each line immediately.
///
/// This function processes exactly one input line at a time.
pub fn mask_log_reader<R, W>(
    reader: R,
    mut writer: W,
    scanner: &Scanner,
) -> Result<Vec<LogLineScanResult>>
where
    R: BufRead,
    W: Write,
{
    let mut results = Vec::new();
    for (index, line) in reader.lines().enumerate() {
        let line = line?;
        let result = scan_log_line(index + 1, &line, scanner)?;
        writer.write_all(result.masked_line.as_deref().unwrap_or(&line).as_bytes())?;
        writer.write_all(b"\n")?;
        results.push(result);
    }
    Ok(results)
}

fn scan_log_line(line_number: usize, line: &str, scanner: &Scanner) -> Result<LogLineScanResult> {
    if let Some(result) = scan_json_log_line(line_number, line, scanner)? {
        return Ok(result);
    }
    if let Some(result) = scan_key_value_log_line(line_number, line, scanner)? {
        return Ok(result);
    }

    let scan = scanner.scan(line)?;
    Ok(LogLineScanResult {
        line_number,
        format: LogLineFormat::Plaintext,
        findings: scan.findings,
        masked_line: scan.masked_text,
    })
}

fn scan_json_log_line(
    line_number: usize,
    line: &str,
    scanner: &Scanner,
) -> Result<Option<LogLineScanResult>> {
    let trimmed = line.trim_start();
    if !trimmed.starts_with('{') && !trimmed.starts_with('[') {
        return Ok(None);
    }

    let Ok(result) = scan_json_str(line, scanner, &JsonScanOptions::default()) else {
        return Ok(None);
    };
    let findings = result
        .strings
        .into_iter()
        .flat_map(|string| string.findings)
        .collect();
    let masked_line = Some(serde_json::to_string(&result.masked_json)?);
    Ok(Some(LogLineScanResult {
        line_number,
        format: LogLineFormat::Json,
        findings,
        masked_line,
    }))
}

fn scan_key_value_log_line(
    line_number: usize,
    line: &str,
    scanner: &Scanner,
) -> Result<Option<LogLineScanResult>> {
    let mut findings = Vec::new();
    let mut replacements = Vec::new();
    let mut saw_key_value = false;

    for (value_start, value_end) in key_value_spans(line) {
        saw_key_value = true;
        let value = &line[value_start..value_end];
        let scan = scanner.scan(value)?;
        if scan.findings.is_empty() {
            continue;
        }

        findings.extend(scan.findings.into_iter().map(|mut finding| {
            finding.span.start += value_start;
            finding.span.end += value_start;
            finding
        }));
        if let Some(masked_value) = scan.masked_text {
            replacements.push((value_start, value_end, masked_value));
        }
    }

    if !saw_key_value {
        return Ok(None);
    }

    let mut masked_line = line.to_string();
    for (start, end, replacement) in replacements.into_iter().rev() {
        masked_line.replace_range(start..end, &replacement);
    }

    Ok(Some(LogLineScanResult {
        line_number,
        format: LogLineFormat::KeyValue,
        findings,
        masked_line: Some(masked_line),
    }))
}

fn key_value_spans(line: &str) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    let mut index = 0;
    while index < line.len() {
        index = skip_whitespace(line, index);
        if index >= line.len() {
            break;
        }

        let token_start = index;
        while index < line.len() {
            let ch = line[index..].chars().next().unwrap_or_default();
            if ch == '=' || ch.is_whitespace() {
                break;
            }
            index += ch.len_utf8();
        }

        if index >= line.len() || !line[index..].starts_with('=') || index == token_start {
            index = skip_token(line, index);
            continue;
        }

        index += 1;
        if index >= line.len() {
            continue;
        }

        let quote = line[index..]
            .chars()
            .next()
            .filter(|ch| *ch == '"' || *ch == '\'');
        let value_start = if let Some(quote) = quote {
            index += quote.len_utf8();
            index
        } else {
            index
        };

        while index < line.len() {
            let ch = line[index..].chars().next().unwrap_or_default();
            if quote.is_some_and(|quote| ch == quote) || quote.is_none() && ch.is_whitespace() {
                break;
            }
            if ch == '\\' {
                index += ch.len_utf8();
                if index < line.len() {
                    let escaped = line[index..].chars().next().unwrap_or_default();
                    index += escaped.len_utf8();
                }
                continue;
            }
            index += ch.len_utf8();
        }

        if value_start < index {
            spans.push((value_start, index));
        }
        index = skip_token(line, index);
    }
    spans
}

fn skip_whitespace(line: &str, mut index: usize) -> usize {
    while index < line.len() {
        let ch = line[index..].chars().next().unwrap_or_default();
        if !ch.is_whitespace() {
            break;
        }
        index += ch.len_utf8();
    }
    index
}

fn skip_token(line: &str, mut index: usize) -> usize {
    while index < line.len() {
        let ch = line[index..].chars().next().unwrap_or_default();
        index += ch.len_utf8();
        if ch.is_whitespace() {
            break;
        }
    }
    index
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
    fn test_scan_log_str_plaintext_masks_line() {
        let result = scan_log_str("login jane@example.com\n", &scanner()).unwrap();
        assert_eq!(result.lines[0].format, LogLineFormat::Plaintext);
        assert!(result.masked_log.contains("[EMAIL]"));
    }

    #[test]
    fn test_scan_log_str_json_line_masks_string_value() {
        let result =
            scan_log_str(r#"{"level":"info","email":"jane@example.com"}"#, &scanner()).unwrap();
        assert_eq!(result.lines[0].format, LogLineFormat::Json);
        assert_eq!(result.lines[0].findings.len(), 1);
        assert!(result.masked_log.contains(r#""email":"[EMAIL]""#));
    }

    #[test]
    fn test_scan_log_str_key_value_line_detects_format() {
        let result = scan_log_str("level=info email=jane@example.com", &scanner()).unwrap();
        assert_eq!(result.lines[0].format, LogLineFormat::KeyValue);
        assert!(result.masked_log.contains("email=[EMAIL]"));
    }

    #[test]
    fn test_mask_log_reader_writes_each_line() {
        let input = "a jane@example.com\nb ops@example.com\n";
        let mut output = Vec::new();
        let results = mask_log_reader(input.as_bytes(), &mut output, &scanner()).unwrap();
        let output = String::from_utf8(output).unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(output.matches("[EMAIL]").count(), 2);
    }
}
