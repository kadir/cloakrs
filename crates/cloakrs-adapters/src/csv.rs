//! CSV adapter for column-aware scanning.

use cloakrs_core::{PiiEntity, Result, Scanner};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::io::{Read, Write};

/// Options controlling which CSV columns are scanned.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CsvScanOptions {
    /// Whether the first record contains headers.
    pub has_headers: bool,
    /// Column names to scan when headers are present.
    pub columns: Vec<String>,
    /// Zero-based column indexes to scan.
    pub column_indexes: Vec<usize>,
    /// CSV delimiter byte.
    pub delimiter: u8,
}

impl CsvScanOptions {
    fn delimiter(&self) -> u8 {
        if self.delimiter == 0 {
            b','
        } else {
            self.delimiter
        }
    }
}

/// PII findings for one CSV cell.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CsvCellScanResult {
    /// One-based data row number. Header row is not counted.
    pub row_number: usize,
    /// Zero-based column index.
    pub column_index: usize,
    /// Header name when available.
    pub column_name: Option<String>,
    /// Findings detected in this cell.
    pub findings: Vec<PiiEntity>,
    /// Masked cell value when masking is enabled.
    pub masked_value: Option<String>,
}

/// Result of scanning CSV data.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CsvScanResult {
    /// Findings grouped by CSV cell.
    pub cells: Vec<CsvCellScanResult>,
    /// Masked CSV data.
    pub masked_csv: String,
}

/// Scans CSV text and returns column-aware findings.
pub fn scan_csv_str(
    input: &str,
    scanner: &Scanner,
    options: &CsvScanOptions,
) -> Result<CsvScanResult> {
    let mut output = Vec::new();
    let cells = mask_csv_reader(input.as_bytes(), &mut output, scanner, options)?;
    let masked_csv = String::from_utf8(output)
        .map_err(|error| cloakrs_core::CloakError::ConfigError(error.to_string()))?;
    Ok(CsvScanResult { cells, masked_csv })
}

/// Streams CSV from a reader to a writer while masking selected cells.
pub fn mask_csv_reader<R, W>(
    reader: R,
    writer: W,
    scanner: &Scanner,
    options: &CsvScanOptions,
) -> Result<Vec<CsvCellScanResult>>
where
    R: Read,
    W: Write,
{
    let mut csv_reader = csv::ReaderBuilder::new()
        .has_headers(options.has_headers)
        .delimiter(options.delimiter())
        .from_reader(reader);
    let mut csv_writer = csv::WriterBuilder::new()
        .has_headers(false)
        .delimiter(options.delimiter())
        .from_writer(writer);

    let headers = if options.has_headers {
        let headers = csv_reader.headers()?.clone();
        csv_writer.write_record(&headers)?;
        Some(headers)
    } else {
        None
    };
    let selected = selected_indexes(headers.as_ref(), options);
    let mut cells = Vec::new();

    for (row_index, record) in csv_reader.records().enumerate() {
        let record = record?;
        let mut masked_record: Vec<String> = record.iter().map(str::to_string).collect();
        for (column_index, value) in record.iter().enumerate() {
            if !selected.is_empty() && !selected.contains(&column_index) {
                continue;
            }
            let scan = scanner.scan(value)?;
            if scan.findings.is_empty() {
                continue;
            }
            let masked_value = scan.masked_text.clone();
            if let Some(masked_value) = &masked_value {
                masked_record[column_index] = masked_value.clone();
            }
            cells.push(CsvCellScanResult {
                row_number: row_index + 1,
                column_index,
                column_name: headers
                    .as_ref()
                    .and_then(|headers| headers.get(column_index))
                    .map(str::to_string),
                findings: scan.findings,
                masked_value,
            });
        }
        csv_writer.write_record(masked_record)?;
    }
    csv_writer.flush()?;
    Ok(cells)
}

fn selected_indexes(
    headers: Option<&csv::StringRecord>,
    options: &CsvScanOptions,
) -> HashSet<usize> {
    let mut selected: HashSet<usize> = options.column_indexes.iter().copied().collect();
    if let Some(headers) = headers {
        for column in &options.columns {
            if let Some(index) = headers.iter().position(|header| header == column) {
                selected.insert(index);
            }
        }
    }
    selected
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
    fn test_scan_csv_str_with_headers_scans_named_column() {
        let input = "name,email\nJane,jane@example.com\n";
        let options = CsvScanOptions {
            has_headers: true,
            columns: vec!["email".to_string()],
            column_indexes: Vec::new(),
            delimiter: b',',
        };
        let result = scan_csv_str(input, &scanner(), &options).unwrap();
        assert_eq!(result.cells.len(), 1);
        assert_eq!(result.cells[0].column_name.as_deref(), Some("email"));
        assert!(result.masked_csv.contains("[EMAIL]"));
    }

    #[test]
    fn test_scan_csv_str_without_headers_scans_index() {
        let input = "Jane,jane@example.com\n";
        let options = CsvScanOptions {
            has_headers: false,
            columns: Vec::new(),
            column_indexes: vec![1],
            delimiter: b',',
        };
        let result = scan_csv_str(input, &scanner(), &options).unwrap();
        assert_eq!(result.cells[0].row_number, 1);
        assert_eq!(result.cells[0].column_index, 1);
    }

    #[test]
    fn test_scan_csv_str_empty_selection_scans_all_columns() {
        let input = "name,email,phone\nJane,jane@example.com,+1 (555) 123-4567\n";
        let options = CsvScanOptions {
            has_headers: true,
            columns: Vec::new(),
            column_indexes: Vec::new(),
            delimiter: b',',
        };
        let result = scan_csv_str(input, &scanner(), &options).unwrap();
        assert_eq!(result.cells.len(), 2);
    }

    #[test]
    fn test_scan_csv_str_semicolon_delimiter() {
        let input = "name;email\nJane;jane@example.com\n";
        let options = CsvScanOptions {
            has_headers: true,
            columns: vec!["email".to_string()],
            column_indexes: Vec::new(),
            delimiter: b';',
        };
        let result = scan_csv_str(input, &scanner(), &options).unwrap();
        assert!(result.masked_csv.contains("[EMAIL]"));
    }

    #[test]
    fn test_scan_csv_str_quoted_multiline_field() {
        let input = "notes\n\"hello\nemail jane@example.com\"\n";
        let options = CsvScanOptions {
            has_headers: true,
            columns: vec!["notes".to_string()],
            column_indexes: Vec::new(),
            delimiter: b',',
        };
        let result = scan_csv_str(input, &scanner(), &options).unwrap();
        assert_eq!(result.cells.len(), 1);
    }
}
