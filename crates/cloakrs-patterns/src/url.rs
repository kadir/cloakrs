use crate::common::{compile_regex, confidence, context_boost};
use crate::{EmailRecognizer, SsnRecognizer};
use cloakrs_core::{Confidence, EntityType, Locale, PiiEntity, Recognizer, Span};
use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashSet;
use std::net::IpAddr;

static URL_REGEX: Lazy<Regex> =
    Lazy::new(|| compile_regex(r##"(?i)\b(?:https?://|ftp://|www\.)[^\s<>"'`{}|\\^\[\]]+"##));

static US_LOCALES: &[Locale] = &[Locale::US];

const CONTEXT_WORDS: &[&str] = &[
    "url", "uri", "link", "website", "endpoint", "callback", "redirect",
];

/// Recognizes HTTP, HTTPS, FTP, and `www.` URLs.
///
/// # Examples
///
/// ```
/// use cloakrs_core::{EntityType, Recognizer};
/// use cloakrs_patterns::UrlRecognizer;
///
/// let findings = UrlRecognizer.scan("link: https://example.com/path");
/// assert_eq!(findings[0].entity_type, EntityType::Url);
/// assert_eq!(findings[0].text, "https://example.com/path");
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct UrlRecognizer;

impl Recognizer for UrlRecognizer {
    fn id(&self) -> &str {
        "url_regex_v1"
    }

    fn entity_type(&self) -> EntityType {
        EntityType::Url
    }

    fn supported_locales(&self) -> &[Locale] {
        &[]
    }

    fn scan(&self, text: &str) -> Vec<PiiEntity> {
        find_url_spans(text)
            .into_iter()
            .map(|span| {
                let candidate = &text[span.start..span.end];
                PiiEntity {
                    entity_type: self.entity_type(),
                    span,
                    text: candidate.to_string(),
                    confidence: self.compute_confidence(text, span.start, candidate),
                    recognizer_id: self.id().to_string(),
                }
            })
            .collect()
    }

    fn validate(&self, candidate: &str) -> bool {
        validate_url(candidate)
    }
}

impl UrlRecognizer {
    fn compute_confidence(&self, text: &str, start: usize, candidate: &str) -> Confidence {
        let base = if has_explicit_scheme(candidate) {
            0.90
        } else {
            0.80
        };
        confidence(base + context_boost(text, start, CONTEXT_WORDS))
    }
}

pub(crate) struct UrlQueryEmailRecognizer;

impl Recognizer for UrlQueryEmailRecognizer {
    fn id(&self) -> &str {
        "url_query_email_v1"
    }

    fn entity_type(&self) -> EntityType {
        EntityType::Email
    }

    fn supported_locales(&self) -> &[Locale] {
        &[]
    }

    fn scan(&self, text: &str) -> Vec<PiiEntity> {
        scan_query_values(text, &EmailRecognizer, self.id())
    }
}

pub(crate) struct UrlQuerySsnRecognizer;

impl Recognizer for UrlQuerySsnRecognizer {
    fn id(&self) -> &str {
        "url_query_ssn_v1"
    }

    fn entity_type(&self) -> EntityType {
        EntityType::Ssn
    }

    fn supported_locales(&self) -> &[Locale] {
        US_LOCALES
    }

    fn scan(&self, text: &str) -> Vec<PiiEntity> {
        scan_query_values(text, &SsnRecognizer, self.id())
    }
}

fn find_url_spans(text: &str) -> Vec<Span> {
    URL_REGEX
        .find_iter(text)
        .filter_map(|matched| {
            let end = trim_url_end(matched.as_str(), matched.start());
            (matched.start() < end && validate_url(&text[matched.start()..end]))
                .then(|| Span::new(matched.start(), end))
        })
        .filter(|span| is_url_boundary(text, span.start, span.end))
        .collect()
}

fn trim_url_end(candidate: &str, start: usize) -> usize {
    let mut end = start + candidate.len();
    let mut value = candidate;
    while let Some(c) = value.chars().next_back() {
        let should_trim = matches!(c, '.' | ',' | ';' | ':' | '!' | '?')
            || (matches!(c, ')' | ']' | '}') && !has_matching_opener(value, c));
        if !should_trim {
            break;
        }
        end -= c.len_utf8();
        value = &candidate[..end - start];
    }
    end
}

fn has_matching_opener(value: &str, closer: char) -> bool {
    let opener = match closer {
        ')' => '(',
        ']' => '[',
        '}' => '{',
        _ => return true,
    };
    value.chars().filter(|c| *c == opener).count() >= value.chars().filter(|c| *c == closer).count()
}

fn validate_url(candidate: &str) -> bool {
    let Some(authority) = authority(candidate) else {
        return false;
    };
    let host = host_from_authority(authority);
    validate_host(host)
}

fn has_explicit_scheme(candidate: &str) -> bool {
    candidate
        .get(..7)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("http://"))
        || candidate
            .get(..8)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("https://"))
        || candidate
            .get(..6)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("ftp://"))
}

fn authority(candidate: &str) -> Option<&str> {
    let after_prefix = if let Some((_, rest)) = candidate.split_once("://") {
        rest
    } else {
        candidate
            .get(..4)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("www."))
            .then_some(candidate)?
    };
    let end = after_prefix
        .find(['/', '?', '#'])
        .unwrap_or(after_prefix.len());
    let authority = &after_prefix[..end];
    (!authority.is_empty()).then_some(authority)
}

fn host_from_authority(authority: &str) -> &str {
    let without_userinfo = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    if let Some(rest) = without_userinfo.strip_prefix('[') {
        return rest
            .split_once(']')
            .map_or(without_userinfo, |(host, _)| host);
    }
    without_userinfo
        .split_once(':')
        .map_or(without_userinfo, |(host, _)| host)
}

fn validate_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") || host.parse::<IpAddr>().is_ok() {
        return true;
    }
    if host.is_empty() || !host.contains('.') {
        return false;
    }
    host.split('.').all(validate_host_label)
}

fn validate_host_label(label: &str) -> bool {
    !label.is_empty()
        && !label.starts_with('-')
        && !label.ends_with('-')
        && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
}

fn is_url_boundary(text: &str, start: usize, end: usize) -> bool {
    let before = text[..start].chars().next_back();
    let after = text[end..].chars().next();
    !before.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        && !after.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

fn scan_query_values<R>(text: &str, recognizer: &R, recognizer_id: &str) -> Vec<PiiEntity>
where
    R: Recognizer,
{
    let mut findings = Vec::new();
    let mut seen = HashSet::new();

    for url_span in find_url_spans(text) {
        let Some(query_span) = query_span(text, url_span) else {
            continue;
        };
        for value_span in query_value_spans(text, query_span) {
            scan_query_value(
                text,
                value_span,
                recognizer,
                recognizer_id,
                &mut seen,
                &mut findings,
            );
        }
    }

    findings.sort_by_key(|finding| finding.span.start);
    findings
}

fn scan_query_value<R>(
    text: &str,
    value_span: Span,
    recognizer: &R,
    recognizer_id: &str,
    seen: &mut HashSet<(EntityType, usize, usize)>,
    findings: &mut Vec<PiiEntity>,
) where
    R: Recognizer,
{
    add_query_findings(
        text,
        value_span,
        recognizer.scan(&text[value_span.start..value_span.end]),
        recognizer_id,
        seen,
        findings,
    );

    let Some(decoded) = percent_decode_with_mapping(&text[value_span.start..value_span.end]) else {
        return;
    };
    if decoded.value == text[value_span.start..value_span.end] {
        return;
    }

    let decoded_findings = recognizer.scan(&decoded.value);
    for finding in decoded_findings {
        if finding.span.is_empty() || finding.span.end > decoded.mapping.len() {
            continue;
        }
        let original_start = value_span.start + decoded.mapping[finding.span.start].0;
        let original_end = value_span.start + decoded.mapping[finding.span.end - 1].1;
        add_query_findings(
            text,
            Span::new(original_start, original_end),
            vec![PiiEntity {
                entity_type: finding.entity_type,
                span: Span::new(0, original_end - original_start),
                text: text[original_start..original_end].to_string(),
                confidence: finding.confidence,
                recognizer_id: finding.recognizer_id,
            }],
            recognizer_id,
            seen,
            findings,
        );
    }
}

fn add_query_findings(
    text: &str,
    offset: Span,
    local_findings: Vec<PiiEntity>,
    recognizer_id: &str,
    seen: &mut HashSet<(EntityType, usize, usize)>,
    findings: &mut Vec<PiiEntity>,
) {
    for finding in local_findings {
        let span = Span::new(
            offset.start + finding.span.start,
            offset.start + finding.span.end,
        );
        if span.end > text.len()
            || !seen.insert((finding.entity_type.clone(), span.start, span.end))
        {
            continue;
        }
        findings.push(PiiEntity {
            entity_type: finding.entity_type,
            span,
            text: text[span.start..span.end].to_string(),
            confidence: finding.confidence,
            recognizer_id: recognizer_id.to_string(),
        });
    }
}

fn query_span(text: &str, url_span: Span) -> Option<Span> {
    let url = &text[url_span.start..url_span.end];
    let query_start = url.find('?')? + 1;
    let query_end = url[query_start..]
        .find('#')
        .map_or(url.len(), |fragment| query_start + fragment);
    (query_start < query_end)
        .then(|| Span::new(url_span.start + query_start, url_span.start + query_end))
}

fn query_value_spans(text: &str, query_span: Span) -> Vec<Span> {
    let mut spans = Vec::new();
    let mut parameter_start = query_span.start;
    let query = &text[query_span.start..query_span.end];

    for (offset, c) in query.char_indices() {
        if matches!(c, '&' | ';') {
            push_query_value_span(text, parameter_start, query_span.start + offset, &mut spans);
            parameter_start = query_span.start + offset + c.len_utf8();
        }
    }
    push_query_value_span(text, parameter_start, query_span.end, &mut spans);

    spans
}

fn push_query_value_span(text: &str, start: usize, end: usize, spans: &mut Vec<Span>) {
    if start >= end {
        return;
    }
    let parameter = &text[start..end];
    if let Some(eq) = parameter.find('=') {
        let value_start = start + eq + 1;
        if value_start < end {
            spans.push(Span::new(value_start, end));
        }
    }
}

struct DecodedValue {
    value: String,
    mapping: Vec<(usize, usize)>,
}

fn percent_decode_with_mapping(value: &str) -> Option<DecodedValue> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut mapping = Vec::with_capacity(bytes.len());
    let mut index = 0;

    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            if let (Some(high), Some(low)) =
                (hex_value(bytes[index + 1]), hex_value(bytes[index + 2]))
            {
                decoded.push(high * 16 + low);
                mapping.push((index, index + 3));
                index += 3;
                continue;
            }
        }

        decoded.push(if bytes[index] == b'+' {
            b' '
        } else {
            bytes[index]
        });
        mapping.push((index, index + 1));
        index += 1;
    }

    String::from_utf8(decoded)
        .ok()
        .map(|value| DecodedValue { value, mapping })
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::default_registry;
    use cloakrs_core::MaskStrategy;

    fn url_texts(input: &str) -> Vec<String> {
        UrlRecognizer
            .scan(input)
            .into_iter()
            .map(|finding| finding.text)
            .collect()
    }

    fn query_email_texts(input: &str) -> Vec<String> {
        UrlQueryEmailRecognizer
            .scan(input)
            .into_iter()
            .map(|finding| finding.text)
            .collect()
    }

    fn query_ssn_texts(input: &str) -> Vec<String> {
        UrlQuerySsnRecognizer
            .scan(input)
            .into_iter()
            .map(|finding| finding.text)
            .collect()
    }

    #[test]
    fn test_url_http_detected() {
        assert_eq!(url_texts("link http://example.com"), ["http://example.com"]);
    }

    #[test]
    fn test_url_https_path_query_fragment_detected() {
        assert_eq!(
            url_texts("visit https://example.com/a/b?x=1#top"),
            ["https://example.com/a/b?x=1#top"]
        );
    }

    #[test]
    fn test_url_www_detected() {
        assert_eq!(
            url_texts("open www.example.com/docs"),
            ["www.example.com/docs"]
        );
    }

    #[test]
    fn test_url_localhost_port_detected() {
        assert_eq!(
            url_texts("endpoint http://localhost:8080/health"),
            ["http://localhost:8080/health"]
        );
    }

    #[test]
    fn test_url_ip_host_detected() {
        assert_eq!(
            url_texts("endpoint http://203.0.113.42/api"),
            ["http://203.0.113.42/api"]
        );
    }

    #[test]
    fn test_url_trailing_punctuation_excluded() {
        assert_eq!(
            url_texts("see https://example.com/path."),
            ["https://example.com/path"]
        );
    }

    #[test]
    fn test_url_balanced_parentheses_preserved() {
        assert_eq!(
            url_texts("see https://example.com/a_(b)"),
            ["https://example.com/a_(b)"]
        );
    }

    #[test]
    fn test_url_invalid_host_without_dot_rejected() {
        assert!(url_texts("go https://example/path").is_empty());
    }

    #[test]
    fn test_url_embedded_in_word_rejected() {
        assert!(url_texts("abchttps://example.com").is_empty());
    }

    #[test]
    fn test_url_multiple_values_detected() {
        assert_eq!(
            url_texts("a https://example.com b www.example.org"),
            ["https://example.com", "www.example.org"]
        );
    }

    #[test]
    fn test_url_context_boosts_confidence() {
        let with_context = UrlRecognizer.scan("url https://example.com");
        let without_context = UrlRecognizer.scan("value https://example.com");
        assert!(with_context[0].confidence > without_context[0].confidence);
    }

    #[test]
    fn test_url_www_confidence_lower_than_scheme() {
        let scheme = UrlRecognizer.scan("https://example.com");
        let www = UrlRecognizer.scan("www.example.com");
        assert!(www[0].confidence < scheme[0].confidence);
    }

    #[test]
    fn test_url_query_email_unencoded_detected() {
        assert_eq!(
            query_email_texts("https://example.com/callback?email=jane@example.com"),
            ["jane@example.com"]
        );
    }

    #[test]
    fn test_url_query_email_percent_encoded_detected() {
        assert_eq!(
            query_email_texts("https://example.com/callback?email=jane%40example.com"),
            ["jane%40example.com"]
        );
    }

    #[test]
    fn test_url_query_ssn_detected() {
        assert_eq!(
            query_ssn_texts("https://example.com/callback?ssn=123-45-6789"),
            ["123-45-6789"]
        );
    }

    #[test]
    fn test_url_query_ssn_supported_locale_is_us() {
        assert_eq!(UrlQuerySsnRecognizer.supported_locales(), &[Locale::US]);
    }

    #[test]
    fn test_url_default_registry_preserves_url_and_query_email() {
        let scanner = default_registry()
            .into_scanner_builder()
            .without_masking()
            .build()
            .unwrap();

        let result = scanner
            .scan("go https://example.com/callback?email=jane@example.com")
            .unwrap();

        assert!(result
            .findings
            .iter()
            .any(|finding| finding.entity_type == EntityType::Url));
        assert!(result
            .findings
            .iter()
            .any(|finding| finding.entity_type == EntityType::Email
                && finding.recognizer_id == "url_query_email_v1"));
    }

    #[test]
    fn test_url_us_scanner_preserves_url_and_query_ssn() {
        let scanner = default_registry()
            .into_scanner_builder()
            .locale(Locale::US)
            .without_masking()
            .build()
            .unwrap();

        let result = scanner
            .scan("go https://example.com/callback?ssn=123-45-6789")
            .unwrap();

        assert!(result
            .findings
            .iter()
            .any(|finding| finding.entity_type == EntityType::Url));
        assert!(result
            .findings
            .iter()
            .any(|finding| finding.entity_type == EntityType::Ssn
                && finding.recognizer_id == "url_query_ssn_v1"));
    }

    #[test]
    fn test_url_universal_scanner_excludes_query_ssn() {
        let scanner = default_registry()
            .into_scanner_builder()
            .locale(Locale::Universal)
            .without_masking()
            .build()
            .unwrap();

        let result = scanner
            .scan("go https://example.com/callback?ssn=123-45-6789")
            .unwrap();

        assert!(result
            .findings
            .iter()
            .all(|finding| finding.entity_type != EntityType::Ssn));
    }

    #[test]
    fn test_url_masking_redacts_outer_url_once() {
        let scanner = default_registry()
            .into_scanner_builder()
            .strategy(MaskStrategy::Redact)
            .build()
            .unwrap();

        let result = scanner
            .scan("go https://example.com/callback?email=jane@example.com")
            .unwrap();

        assert_eq!(result.masked_text.as_deref(), Some("go [URL]"));
    }
}
