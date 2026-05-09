use cloakrs_core::{EntityType, PiiEntity, Span};
use serde_json::{json, Value};
use std::collections::BTreeMap;

const SARIF_SCHEMA: &str =
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json";

#[derive(Debug, Clone)]
pub struct SarifFinding {
    pub uri: String,
    pub location: String,
    pub entity_type: EntityType,
    pub span: Span,
    pub confidence: f64,
    pub recognizer_id: String,
}

impl SarifFinding {
    pub fn from_pii(
        uri: impl Into<String>,
        location: impl Into<String>,
        finding: &PiiEntity,
    ) -> Self {
        Self {
            uri: uri.into(),
            location: location.into(),
            entity_type: finding.entity_type.clone(),
            span: finding.span,
            confidence: finding.confidence.value(),
            recognizer_id: finding.recognizer_id.clone(),
        }
    }
}

pub fn sarif_log(findings: &[SarifFinding]) -> Value {
    let rules = rules_for_findings(findings);
    let rule_indexes: BTreeMap<String, usize> = rules
        .iter()
        .enumerate()
        .filter_map(|(index, rule)| {
            rule.get("id")
                .and_then(Value::as_str)
                .map(|id| (id.to_string(), index))
        })
        .collect();

    let results: Vec<_> = findings
        .iter()
        .map(|finding| result_for_finding(finding, &rule_indexes))
        .collect();

    json!({
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "cloakrs",
                    "informationUri": "https://github.com/kadir/cloakrs",
                    "semanticVersion": env!("CARGO_PKG_VERSION"),
                    "rules": rules
                }
            },
            "results": results
        }]
    })
}

pub fn validate_sarif_shape(value: &Value) -> Result<(), String> {
    if value.get("version").and_then(Value::as_str) != Some("2.1.0") {
        return Err("SARIF log must use version 2.1.0".to_string());
    }
    if value.get("$schema").and_then(Value::as_str).is_none() {
        return Err("SARIF log must include $schema".to_string());
    }
    let runs = value
        .get("runs")
        .and_then(Value::as_array)
        .filter(|runs| !runs.is_empty())
        .ok_or_else(|| "SARIF log must include at least one run".to_string())?;
    let run = &runs[0];
    if run
        .pointer("/tool/driver/name")
        .and_then(Value::as_str)
        .is_none()
    {
        return Err("SARIF run must include tool.driver.name".to_string());
    }
    if run
        .pointer("/tool/driver/rules")
        .and_then(Value::as_array)
        .is_none()
    {
        return Err("SARIF run must include tool.driver.rules".to_string());
    }
    let results = run
        .get("results")
        .and_then(Value::as_array)
        .ok_or_else(|| "SARIF run must include results".to_string())?;
    for result in results {
        validate_result_shape(result)?;
    }
    Ok(())
}

pub fn rule_id(entity_type: &EntityType) -> String {
    let tag = entity_type.redaction_tag();
    let name = tag.trim_start_matches('[').trim_end_matches(']');
    format!("{name}_DETECTED")
}

pub fn level(entity_type: &EntityType) -> &'static str {
    match entity_type {
        EntityType::CreditCard | EntityType::Ssn => "error",
        EntityType::Email | EntityType::PhoneNumber | EntityType::Iban => "warning",
        _ => "note",
    }
}

fn validate_result_shape(result: &Value) -> Result<(), String> {
    if result.get("ruleId").and_then(Value::as_str).is_none() {
        return Err("SARIF result must include ruleId".to_string());
    }
    if result.get("level").and_then(Value::as_str).is_none() {
        return Err("SARIF result must include level".to_string());
    }
    if result
        .pointer("/message/text")
        .and_then(Value::as_str)
        .is_none()
    {
        return Err("SARIF result must include message.text".to_string());
    }
    if result
        .pointer("/locations/0/physicalLocation/artifactLocation/uri")
        .and_then(Value::as_str)
        .is_none()
    {
        return Err("SARIF result must include artifactLocation.uri".to_string());
    }
    if result
        .pointer("/locations/0/physicalLocation/region/startLine")
        .and_then(Value::as_u64)
        .is_none()
    {
        return Err("SARIF result must include region.startLine".to_string());
    }
    Ok(())
}

fn rules_for_findings(findings: &[SarifFinding]) -> Vec<Value> {
    let mut rules = BTreeMap::new();
    for finding in findings {
        let id = rule_id(&finding.entity_type);
        rules
            .entry(id)
            .or_insert_with(|| rule_for_entity(&finding.entity_type));
    }
    rules.into_values().collect()
}

fn rule_for_entity(entity_type: &EntityType) -> Value {
    let id = rule_id(entity_type);
    let name = format!("{entity_type:?}");
    json!({
        "id": id,
        "name": name,
        "shortDescription": {
            "text": format!("{name} detected")
        },
        "fullDescription": {
            "text": format!("cloakrs detected a possible {name} value.")
        },
        "defaultConfiguration": {
            "level": level(entity_type)
        },
        "properties": {
            "precision": "high",
            "tags": ["pii", "privacy", "security"]
        }
    })
}

fn result_for_finding(finding: &SarifFinding, rule_indexes: &BTreeMap<String, usize>) -> Value {
    let rule_id = rule_id(&finding.entity_type);
    json!({
        "ruleId": rule_id,
        "ruleIndex": rule_indexes.get(&rule_id).copied().unwrap_or(0),
        "level": level(&finding.entity_type),
        "kind": "fail",
        "message": {
            "text": format!("{:?} detected at {}", finding.entity_type, finding.location)
        },
        "locations": [{
            "physicalLocation": {
                "artifactLocation": { "uri": finding.uri },
                "region": region(&finding.location, finding.span)
            }
        }],
        "partialFingerprints": {
            "primaryLocationLineHash": fingerprint(finding)
        },
        "properties": {
            "entityType": format!("{:?}", finding.entity_type),
            "confidence": finding.confidence,
            "recognizerId": finding.recognizer_id,
            "adapterLocation": finding.location
        }
    })
}

fn region(location: &str, span: Span) -> Value {
    let start_line = location_line(location).unwrap_or(1);
    json!({
        "startLine": start_line,
        "startColumn": span.start + 1,
        "endLine": start_line,
        "endColumn": span.end + 1
    })
}

fn location_line(location: &str) -> Option<usize> {
    if let Some(line) = location
        .strip_prefix("line:")
        .and_then(|value| value.parse::<usize>().ok())
    {
        return Some(line);
    }
    if let Some(row) = location
        .strip_prefix("row:")
        .and_then(|value| value.split(',').next())
        .and_then(|value| value.parse::<usize>().ok())
    {
        return Some(row + 1);
    }
    None
}

fn fingerprint(finding: &SarifFinding) -> String {
    format!(
        "{}:{}:{}:{}",
        finding.uri,
        rule_id(&finding.entity_type),
        finding.location,
        finding.span.start
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use cloakrs_core::{Confidence, PiiEntity};

    fn finding(entity_type: EntityType) -> PiiEntity {
        PiiEntity {
            entity_type,
            span: Span::new(3, 19),
            text: "jane@example.com".to_string(),
            confidence: Confidence::new(0.95).unwrap(),
            recognizer_id: "test".to_string(),
        }
    }

    #[test]
    fn test_sarif_log_includes_required_shape() {
        let finding = SarifFinding::from_pii("sample.txt", "line:2", &finding(EntityType::Email));
        let log = sarif_log(&[finding]);
        validate_sarif_shape(&log).unwrap();
        assert_eq!(log["version"], "2.1.0");
        assert_eq!(log["runs"][0]["results"][0]["ruleId"], "EMAIL_DETECTED");
    }

    #[test]
    fn test_rule_id_uses_redaction_tag_shape() {
        assert_eq!(rule_id(&EntityType::CreditCard), "CREDIT_CARD_DETECTED");
        assert_eq!(rule_id(&EntityType::PhoneNumber), "PHONE_DETECTED");
    }

    #[test]
    fn test_level_maps_high_risk_entities_to_error() {
        assert_eq!(level(&EntityType::CreditCard), "error");
        assert_eq!(level(&EntityType::Email), "warning");
    }

    #[test]
    fn test_region_uses_line_or_csv_row() {
        assert_eq!(region("line:7", Span::new(0, 4))["startLine"], 7);
        assert_eq!(region("row:2,column:1", Span::new(0, 4))["startLine"], 3);
    }
}
