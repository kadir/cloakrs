use crate::common::{compile_regex, confidence, context_boost};
use cloakrs_core::{Confidence, EntityType, Locale, PiiEntity, Recognizer, Span};
use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashSet;

static DOMAIN_HOSTNAME_REGEX: Lazy<Regex> = Lazy::new(|| {
    compile_regex(
        r"(?i)\b[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?){1,}\b",
    )
});

static WINDOWS_HOSTNAME_REGEX: Lazy<Regex> =
    Lazy::new(|| compile_regex(r"\b(?:DESKTOP|LAPTOP|WIN|PC|WORKSTATION)-[A-Z0-9]{6,10}\b"));

const CONTEXT_WORDS: &[&str] = &[
    "host",
    "hostname",
    "server",
    "node",
    "instance",
    "machine",
    "connecting to",
    "connected to",
    "resolved",
    "dns",
    "nslookup",
    "ping",
    "ssh",
    "host:",
    "server_name",
    "server_addr",
    "remote_host",
    "upstream",
];

const INTERNAL_LABELS: &[&str] = &[
    "internal", "local", "lan", "corp", "private", "intranet", "k8s", "svc", "cluster",
];

const INFRA_LABEL_PREFIXES: &[&str] = &[
    "server", "node", "worker", "db", "redis", "cache", "web", "app", "api", "proxy", "lb",
    "queue", "staging", "prod", "dev", "test", "ip",
];

const CLOUD_SUFFIXES: &[&[&str]] = &[
    &["ec2", "internal"],
    &["compute", "internal"],
    &["k8s", "local"],
    &["svc", "cluster", "local"],
    &["rds", "amazonaws", "com"],
    &["cloudfront", "net"],
    &["elasticbeanstalk", "com"],
];

const PUBLIC_FIRST_LABELS: &[&str] = &["com", "org", "net", "io", "edu", "gov"];

/// Recognizes internal hostnames and machine names that can leak infrastructure.
///
/// # Examples
///
/// ```
/// use cloakrs_core::{EntityType, Recognizer};
/// use cloakrs_patterns::HostnameRecognizer;
///
/// let findings = HostnameRecognizer.scan("connecting to db-prod-01.internal.company.com");
/// assert_eq!(findings[0].entity_type, EntityType::Hostname);
/// assert_eq!(findings[0].text, "db-prod-01.internal.company.com");
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct HostnameRecognizer;

impl Recognizer for HostnameRecognizer {
    fn id(&self) -> &str {
        "hostname_infra_v1"
    }

    fn entity_type(&self) -> EntityType {
        EntityType::Hostname
    }

    fn supported_locales(&self) -> &[Locale] {
        &[]
    }

    fn scan(&self, text: &str) -> Vec<PiiEntity> {
        let mut seen = HashSet::new();
        let mut findings = Vec::new();

        for matched in DOMAIN_HOSTNAME_REGEX.find_iter(text) {
            let start = matched.start();
            let end = matched.end();
            if seen.insert((start, end)) && self.is_valid_domain_match(text, start, end) {
                findings.push(self.finding(text, Span::new(start, end)));
            }
        }

        for matched in WINDOWS_HOSTNAME_REGEX.find_iter(text) {
            let start = matched.start();
            let end = matched.end();
            if seen.insert((start, end)) && is_boundary(text, start, end) {
                findings.push(self.finding(text, Span::new(start, end)));
            }
        }

        findings.sort_by_key(|finding| finding.span.start);
        findings
    }

    fn validate(&self, candidate: &str) -> bool {
        is_windows_hostname(candidate) || validate_domain_hostname(candidate)
    }
}

impl HostnameRecognizer {
    fn finding(&self, text: &str, span: Span) -> PiiEntity {
        let candidate = &text[span.start..span.end];
        PiiEntity {
            entity_type: self.entity_type(),
            span,
            text: candidate.to_string(),
            confidence: self.compute_confidence(text, span.start, candidate),
            recognizer_id: self.id().to_string(),
        }
    }

    fn is_valid_domain_match(&self, text: &str, start: usize, end: usize) -> bool {
        let candidate = &text[start..end];
        validate_domain_hostname(candidate)
            && is_boundary(text, start, end)
            && !is_email_domain(text, start)
            && !is_url_host(text, start, candidate)
    }

    fn compute_confidence(&self, text: &str, start: usize, candidate: &str) -> Confidence {
        let base = if is_windows_hostname(candidate) || has_internal_marker(candidate) {
            0.85
        } else if has_cloud_suffix(candidate) || has_infra_label(candidate) {
            0.80
        } else {
            0.50
        };
        confidence(base + context_boost(text, start, CONTEXT_WORDS))
    }
}

fn validate_domain_hostname(candidate: &str) -> bool {
    let labels: Vec<&str> = candidate.split('.').collect();
    labels.len() >= 2
        && labels.iter().all(|label| validate_label(label))
        && !is_reversed_domain(&labels)
        && (has_internal_marker(candidate)
            || has_cloud_suffix(candidate)
            || has_infra_label(candidate))
}

fn validate_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 63
        && !label.starts_with('-')
        && !label.ends_with('-')
        && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
}

fn is_windows_hostname(candidate: &str) -> bool {
    WINDOWS_HOSTNAME_REGEX
        .find(candidate)
        .is_some_and(|matched| matched.start() == 0 && matched.end() == candidate.len())
}

fn has_internal_marker(candidate: &str) -> bool {
    candidate
        .split('.')
        .any(|label| INTERNAL_LABELS.contains(&label.to_ascii_lowercase().as_str()))
}

fn has_cloud_suffix(candidate: &str) -> bool {
    let labels: Vec<String> = candidate.split('.').map(str::to_ascii_lowercase).collect();
    CLOUD_SUFFIXES.iter().any(|suffix| {
        labels.len() >= suffix.len()
            && labels[labels.len() - suffix.len()..]
                .iter()
                .zip(suffix.iter())
                .all(|(left, right)| left == right)
    })
}

fn has_infra_label(candidate: &str) -> bool {
    candidate.split('.').any(|label| {
        let lower = label.to_ascii_lowercase();
        INFRA_LABEL_PREFIXES.iter().any(|prefix| {
            lower == *prefix
                || lower.strip_prefix(prefix).is_some_and(|rest| {
                    rest.starts_with('-') || rest.chars().next().is_some_and(|c| c.is_ascii_digit())
                })
        })
    })
}

fn is_reversed_domain(labels: &[&str]) -> bool {
    labels
        .first()
        .is_some_and(|label| PUBLIC_FIRST_LABELS.contains(&label.to_ascii_lowercase().as_str()))
}

fn is_email_domain(text: &str, start: usize) -> bool {
    text[..start].ends_with('@')
}

fn is_url_host(text: &str, start: usize, candidate: &str) -> bool {
    candidate
        .get(..4)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("www."))
        || text[..start].ends_with("://")
}

fn is_boundary(text: &str, start: usize, end: usize) -> bool {
    let before = text[..start].chars().next_back();
    let after = text[end..].chars().next();
    !before.is_some_and(is_hostname_continuation) && !after.is_some_and(is_hostname_continuation)
}

fn is_hostname_continuation(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.')
}

#[cfg(test)]
mod tests {
    use super::*;
    use cloakrs_core::RecognizerRegistry;

    fn texts(input: &str) -> Vec<String> {
        HostnameRecognizer
            .scan(input)
            .into_iter()
            .map(|finding| finding.text)
            .collect()
    }

    #[test]
    fn test_hostname_internal_company_host_detected() {
        assert_eq!(
            texts("ssh server-prod-01.internal.company.com"),
            ["server-prod-01.internal.company.com"]
        );
    }

    #[test]
    fn test_hostname_rds_cloud_host_detected() {
        assert_eq!(
            texts("server db-replica-3.eu-west-1.rds.amazonaws.com"),
            ["db-replica-3.eu-west-1.rds.amazonaws.com"]
        );
    }

    #[test]
    fn test_hostname_ec2_internal_host_detected() {
        assert_eq!(
            texts("resolved ip-172-31-16-58.ec2.internal"),
            ["ip-172-31-16-58.ec2.internal"]
        );
    }

    #[test]
    fn test_hostname_k8s_local_host_detected() {
        assert_eq!(
            texts("node worker-node-7.k8s.local"),
            ["worker-node-7.k8s.local"]
        );
    }

    #[test]
    fn test_hostname_infra_context_public_tld_detected() {
        assert_eq!(
            texts("host redis-cache-01.staging.myapp.io"),
            ["redis-cache-01.staging.myapp.io"]
        );
    }

    #[test]
    fn test_hostname_windows_machine_detected() {
        assert_eq!(texts("machine DESKTOP-A1B2C3D"), ["DESKTOP-A1B2C3D"]);
    }

    #[test]
    fn test_hostname_mdns_machine_detected() {
        assert_eq!(
            texts("ping macbook-pro-kadir.local"),
            ["macbook-pro-kadir.local"]
        );
    }

    #[test]
    fn test_hostname_corp_short_host_detected() {
        assert_eq!(texts("upstream api-gateway.corp"), ["api-gateway.corp"]);
    }

    #[test]
    fn test_hostname_public_google_domain_rejected() {
        assert!(texts("open google.com").is_empty());
    }

    #[test]
    fn test_hostname_public_github_domain_rejected() {
        assert!(texts("host github.com").is_empty());
    }

    #[test]
    fn test_hostname_email_domain_rejected() {
        assert!(texts("mail user@company.com").is_empty());
    }

    #[test]
    fn test_hostname_url_host_rejected() {
        assert!(texts("url https://example.com/path").is_empty());
    }

    #[test]
    fn test_hostname_localhost_rejected() {
        assert!(texts("host localhost").is_empty());
    }

    #[test]
    fn test_hostname_reversed_domain_rejected() {
        assert!(texts("package com.google.android.app").is_empty());
    }

    #[test]
    fn test_hostname_single_project_name_rejected() {
        assert!(texts("repo my-cool-project").is_empty());
    }

    #[test]
    fn test_hostname_connecting_context_boosts_confidence() {
        let with_context = HostnameRecognizer.scan("connecting to db-prod.internal.myco.com");
        let without_context = HostnameRecognizer.scan("value db-prod.internal.myco.com");
        assert!(with_context[0].confidence > without_context[0].confidence);
    }

    #[test]
    fn test_hostname_host_prefix_context_boosts_confidence() {
        let with_context = HostnameRecognizer.scan("host: web-01.corp");
        let without_context = HostnameRecognizer.scan("value web-01.corp");
        assert!(with_context[0].confidence > without_context[0].confidence);
    }

    #[test]
    fn test_hostname_supported_locales_are_universal() {
        assert!(HostnameRecognizer.supported_locales().is_empty());
    }

    #[test]
    fn test_hostname_registry_integration_detects_default_recognizer() {
        let mut registry = RecognizerRegistry::new();
        crate::register_default_recognizers(&mut registry);

        let findings = registry.scan_all("remote_host=db-prod.internal.myco.com");

        assert!(findings
            .iter()
            .any(|finding| finding.entity_type == EntityType::Hostname));
    }
}
