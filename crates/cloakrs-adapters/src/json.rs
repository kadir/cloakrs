//! JSON adapter for scanning string values with path metadata.

use cloakrs_core::{PiiEntity, Result, Scanner};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// Options controlling which JSON paths are scanned.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsonScanOptions {
    /// JSONPath-like paths to include. Empty means include every string.
    pub include_paths: Vec<String>,
    /// JSONPath-like paths to skip.
    pub exclude_paths: Vec<String>,
}

/// PII findings from one JSON string value.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JsonStringScanResult {
    /// JSON path where the string was found.
    pub path: String,
    /// Findings detected in this string.
    pub findings: Vec<PiiEntity>,
    /// Masked value when scanner masking is enabled.
    pub masked_value: Option<String>,
}

/// Result of scanning a JSON document.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JsonScanResult {
    /// Findings grouped by JSON string path.
    pub strings: Vec<JsonStringScanResult>,
    /// JSON value with masked strings in place.
    pub masked_json: Value,
}

/// Scans JSON text and returns path-aware findings.
///
/// # Examples
///
/// ```
/// use cloakrs_adapters::{scan_json_str, JsonScanOptions};
/// use cloakrs_core::{Confidence, EntityType, Locale, PiiEntity, Recognizer, Scanner, Span};
///
/// struct Email;
/// impl Recognizer for Email {
///     fn id(&self) -> &str { "email_test" }
///     fn entity_type(&self) -> EntityType { EntityType::Email }
///     fn supported_locales(&self) -> &[Locale] { &[] }
///     fn scan(&self, text: &str) -> Vec<PiiEntity> {
///         text.find('@').map(|at| PiiEntity {
///             entity_type: EntityType::Email,
///             span: Span::new(0, at + 4),
///             text: text[..at + 4].to_string(),
///             confidence: Confidence::new(0.9).unwrap(),
///             recognizer_id: self.id().to_string(),
///         }).into_iter().collect()
///     }
/// }
///
/// let scanner = Scanner::builder().recognizer(Email).build().unwrap();
/// let result = scan_json_str(r#"{"email":"a@b.test"}"#, &scanner, &JsonScanOptions::default()).unwrap();
/// assert_eq!(result.strings[0].path, "$.email");
/// ```
pub fn scan_json_str(
    input: &str,
    scanner: &Scanner,
    options: &JsonScanOptions,
) -> Result<JsonScanResult> {
    let value: Value = serde_json::from_str(input)?;
    scan_json_value(&value, scanner, options)
}

/// Scans an already parsed JSON value.
pub fn scan_json_value(
    value: &Value,
    scanner: &Scanner,
    options: &JsonScanOptions,
) -> Result<JsonScanResult> {
    let mut strings = Vec::new();
    let masked_json = scan_value(value, "$", scanner, options, &mut strings)?;
    Ok(JsonScanResult {
        strings,
        masked_json,
    })
}

fn scan_value(
    value: &Value,
    path: &str,
    scanner: &Scanner,
    options: &JsonScanOptions,
    strings: &mut Vec<JsonStringScanResult>,
) -> Result<Value> {
    match value {
        Value::String(text) => scan_string(text, path, scanner, options, strings),
        Value::Array(items) => {
            let mut masked = Vec::with_capacity(items.len());
            for (index, item) in items.iter().enumerate() {
                masked.push(scan_value(
                    item,
                    &format!("{path}[{index}]"),
                    scanner,
                    options,
                    strings,
                )?);
            }
            Ok(Value::Array(masked))
        }
        Value::Object(map) => {
            let mut masked = Map::with_capacity(map.len());
            for (key, item) in map {
                masked.insert(
                    key.clone(),
                    scan_value(item, &format!("{path}.{key}"), scanner, options, strings)?,
                );
            }
            Ok(Value::Object(masked))
        }
        _ => Ok(value.clone()),
    }
}

fn scan_string(
    text: &str,
    path: &str,
    scanner: &Scanner,
    options: &JsonScanOptions,
    strings: &mut Vec<JsonStringScanResult>,
) -> Result<Value> {
    if !path_allowed(path, options) {
        return Ok(Value::String(text.to_string()));
    }

    let scan = scanner.scan(text)?;
    let masked_value = scan.masked_text.clone();
    if !scan.findings.is_empty() {
        strings.push(JsonStringScanResult {
            path: path.to_string(),
            findings: scan.findings,
            masked_value: masked_value.clone(),
        });
    }
    Ok(Value::String(
        masked_value.unwrap_or_else(|| text.to_string()),
    ))
}

fn path_allowed(path: &str, options: &JsonScanOptions) -> bool {
    let included = options.include_paths.is_empty()
        || options
            .include_paths
            .iter()
            .any(|pattern| path_matches(pattern, path));
    let excluded = options
        .exclude_paths
        .iter()
        .any(|pattern| path_matches(pattern, path));
    included && !excluded
}

fn path_matches(pattern: &str, path: &str) -> bool {
    if pattern == path {
        return true;
    }
    if !pattern.contains("[*]") {
        return false;
    }
    let mut rest = path;
    for part in pattern.split("[*]") {
        if part.is_empty() {
            continue;
        }
        let Some(index) = rest.find(part) else {
            return false;
        };
        rest = &rest[index + part.len()..];
    }
    true
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
    fn test_scan_json_str_nested_object_detects_path() {
        let input = r#"{"user":{"email":"jane@example.com"}}"#;
        let result = scan_json_str(input, &scanner(), &JsonScanOptions::default()).unwrap();
        assert_eq!(result.strings[0].path, "$.user.email");
        assert_eq!(result.masked_json["user"]["email"], "[EMAIL]");
    }

    #[test]
    fn test_scan_json_str_arrays_use_indexed_paths() {
        let input = r#"{"records":[{"email":"jane@example.com"}]}"#;
        let result = scan_json_str(input, &scanner(), &JsonScanOptions::default()).unwrap();
        assert_eq!(result.strings[0].path, "$.records[0].email");
    }

    #[test]
    fn test_scan_json_str_include_paths_filters() {
        let input =
            r#"{"user":{"email":"jane@example.com"},"metadata":{"email":"ops@example.com"}}"#;
        let options = JsonScanOptions {
            include_paths: vec!["$.user.email".to_string()],
            exclude_paths: Vec::new(),
        };
        let result = scan_json_str(input, &scanner(), &options).unwrap();
        assert_eq!(result.strings.len(), 1);
        assert_eq!(result.strings[0].path, "$.user.email");
    }

    #[test]
    fn test_scan_json_str_exclude_paths_filters() {
        let input =
            r#"{"user":{"email":"jane@example.com"},"metadata":{"email":"ops@example.com"}}"#;
        let options = JsonScanOptions {
            include_paths: Vec::new(),
            exclude_paths: vec!["$.metadata.email".to_string()],
        };
        let result = scan_json_str(input, &scanner(), &options).unwrap();
        assert_eq!(result.strings.len(), 1);
        assert_eq!(result.strings[0].path, "$.user.email");
    }

    #[test]
    fn test_scan_json_str_wildcard_path_matches_array_items() {
        let input = r#"{"records":[{"email":"jane@example.com"},{"email":"ops@example.com"}]}"#;
        let options = JsonScanOptions {
            include_paths: vec!["$.records[*].email".to_string()],
            exclude_paths: Vec::new(),
        };
        let result = scan_json_str(input, &scanner(), &options).unwrap();
        assert_eq!(result.strings.len(), 2);
    }
}
