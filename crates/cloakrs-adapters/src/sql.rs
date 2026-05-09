//! SQL dump adapter for masking quoted values in `INSERT` statements.

use cloakrs_core::{PiiEntity, Result, Scanner};
use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader, Read, Write};

/// PII findings for one quoted SQL string value.
///
/// Spans are byte offsets relative to the unescaped SQL string value.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SqlValueScanResult {
    /// One-based `INSERT` statement number.
    pub statement_number: usize,
    /// Zero-based quoted string value index within that statement.
    pub value_index: usize,
    /// Findings detected in this string value.
    pub findings: Vec<PiiEntity>,
    /// Masked value when the scanner has masking enabled.
    pub masked_value: Option<String>,
}

/// Result of scanning a SQL dump.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SqlScanResult {
    /// Findings grouped by SQL quoted string value.
    pub values: Vec<SqlValueScanResult>,
    /// SQL output with quoted value contents masked.
    pub masked_sql: String,
}

/// Scans SQL dump text and masks PII inside quoted `INSERT ... VALUES` strings.
///
/// # Examples
///
/// ```
/// use cloakrs_adapters::scan_sql_str;
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
/// let result = scan_sql_str("INSERT INTO users VALUES ('a@test');", &scanner).unwrap();
/// assert!(result.masked_sql.contains("[EMAIL]"));
/// ```
pub fn scan_sql_str(input: &str, scanner: &Scanner) -> Result<SqlScanResult> {
    let mut output = Vec::new();
    let values = mask_sql_reader(input.as_bytes(), &mut output, scanner)?;
    let masked_sql = String::from_utf8(output)
        .map_err(|error| cloakrs_core::CloakError::ConfigError(error.to_string()))?;
    Ok(SqlScanResult { values, masked_sql })
}

/// Streams SQL dump text from a reader to a writer while masking quoted
/// strings in `INSERT ... VALUES` statements.
pub fn mask_sql_reader<R, W>(
    reader: R,
    mut writer: W,
    scanner: &Scanner,
) -> Result<Vec<SqlValueScanResult>>
where
    R: Read,
    W: Write,
{
    let mut reader = BufReader::new(reader);
    let mut state = SqlStreamState::default();
    let mut values = Vec::new();
    let mut line = String::new();

    loop {
        line.clear();
        let bytes = reader.read_line(&mut line)?;
        if bytes == 0 {
            break;
        }
        state.process_line(&line, &mut writer, scanner, &mut values)?;
    }
    state.finish(&mut writer)?;
    Ok(values)
}

#[derive(Default)]
struct SqlStreamState {
    in_insert_values: bool,
    in_string: bool,
    statement_number: usize,
    value_index: usize,
    token: String,
    raw_string: String,
}

impl SqlStreamState {
    fn process_line<W>(
        &mut self,
        line: &str,
        writer: &mut W,
        scanner: &Scanner,
        values: &mut Vec<SqlValueScanResult>,
    ) -> Result<()>
    where
        W: Write,
    {
        let mut chars = line.chars().peekable();
        while let Some(ch) = chars.next() {
            if self.in_string {
                self.process_string_char(ch, &mut chars, writer, scanner, values)?;
            } else {
                self.process_sql_char(ch, writer)?;
            }
        }
        Ok(())
    }

    fn process_sql_char<W>(&mut self, ch: char, writer: &mut W) -> Result<()>
    where
        W: Write,
    {
        if ch == '\'' && self.in_insert_values {
            self.in_string = true;
            self.raw_string.clear();
            return Ok(());
        }

        write_char(writer, ch)?;
        if ch == ';' {
            self.in_insert_values = false;
            self.token.clear();
            return Ok(());
        }
        self.update_sql_state(ch);
        Ok(())
    }

    fn process_string_char<I, W>(
        &mut self,
        ch: char,
        chars: &mut std::iter::Peekable<I>,
        writer: &mut W,
        scanner: &Scanner,
        values: &mut Vec<SqlValueScanResult>,
    ) -> Result<()>
    where
        I: Iterator<Item = char>,
        W: Write,
    {
        if ch == '\'' {
            if matches!(chars.peek(), Some('\'')) {
                self.raw_string.push('\'');
                self.raw_string.push('\'');
                let _ = chars.next();
                return Ok(());
            }
            self.write_masked_string(writer, scanner, values)?;
            return Ok(());
        }

        if ch == '\\' {
            self.raw_string.push(ch);
            if let Some(escaped) = chars.next() {
                self.raw_string.push(escaped);
            }
            return Ok(());
        }

        self.raw_string.push(ch);
        Ok(())
    }

    fn write_masked_string<W>(
        &mut self,
        writer: &mut W,
        scanner: &Scanner,
        values: &mut Vec<SqlValueScanResult>,
    ) -> Result<()>
    where
        W: Write,
    {
        let unescaped = unescape_sql_string(&self.raw_string);
        let scan = scanner.scan(&unescaped)?;
        let masked_value = if scan.findings.is_empty() {
            None
        } else {
            scan.masked_text.clone()
        };
        let value_to_write = masked_value
            .as_deref()
            .map(escape_sql_string)
            .unwrap_or_else(|| self.raw_string.clone());

        writer.write_all(b"'")?;
        writer.write_all(value_to_write.as_bytes())?;
        writer.write_all(b"'")?;

        if !scan.findings.is_empty() {
            values.push(SqlValueScanResult {
                statement_number: self.statement_number,
                value_index: self.value_index,
                findings: scan.findings,
                masked_value,
            });
        }
        self.value_index += 1;
        self.in_string = false;
        self.raw_string.clear();
        self.token.clear();
        Ok(())
    }

    fn update_sql_state(&mut self, ch: char) {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            self.token.push(ch.to_ascii_uppercase());
            return;
        }

        if self.token == "INSERT" {
            self.statement_number += 1;
            self.value_index = 0;
            self.in_insert_values = false;
        } else if self.token == "VALUES" && self.statement_number > 0 {
            self.in_insert_values = true;
        }
        self.token.clear();
    }

    fn finish<W>(&mut self, writer: &mut W) -> Result<()>
    where
        W: Write,
    {
        if self.in_string {
            writer.write_all(b"'")?;
            writer.write_all(self.raw_string.as_bytes())?;
            self.in_string = false;
            self.raw_string.clear();
        }
        Ok(())
    }
}

fn write_char<W>(writer: &mut W, ch: char) -> Result<()>
where
    W: Write,
{
    let mut buffer = [0; 4];
    writer.write_all(ch.encode_utf8(&mut buffer).as_bytes())?;
    Ok(())
}

fn unescape_sql_string(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    let mut chars = value.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\'' && matches!(chars.peek(), Some('\'')) {
            output.push('\'');
            let _ = chars.next();
        } else if ch == '\\' {
            if let Some(next) = chars.next() {
                output.push(next);
            } else {
                output.push(ch);
            }
        } else {
            output.push(ch);
        }
    }
    output
}

fn escape_sql_string(value: &str) -> String {
    value.replace('\'', "''")
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
    fn test_scan_sql_str_insert_masks_quoted_string() {
        let sql = "INSERT INTO users (email) VALUES ('jane@example.com');";
        let result = scan_sql_str(sql, &scanner()).unwrap();
        assert!(result.masked_sql.contains("'[EMAIL]'"));
        assert_eq!(result.values.len(), 1);
    }

    #[test]
    fn test_scan_sql_str_multi_row_insert_masks_each_row() {
        let sql = "INSERT INTO users VALUES (1,'jane@example.com'),(2,'ops@example.com');";
        let result = scan_sql_str(sql, &scanner()).unwrap();
        assert_eq!(result.values.len(), 2);
        assert_eq!(result.masked_sql.matches("'[EMAIL]'").count(), 2);
    }

    #[test]
    fn test_scan_sql_str_escaped_quote_preserves_valid_sql() {
        let sql = "INSERT INTO users VALUES ('Jane O''Neil <jane@example.com>');";
        let result = scan_sql_str(sql, &scanner()).unwrap();
        assert!(result.masked_sql.contains("'Jane O''Neil <[EMAIL]>'"));
    }

    #[test]
    fn test_scan_sql_str_non_insert_is_not_masked() {
        let sql = "UPDATE users SET email='jane@example.com';";
        let result = scan_sql_str(sql, &scanner()).unwrap();
        assert_eq!(result.values.len(), 0);
        assert_eq!(result.masked_sql, sql);
    }
}
