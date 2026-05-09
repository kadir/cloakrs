use crate::common::{compile_regex, confidence};
use cloakrs_core::{Confidence, EntityType, Locale, PiiEntity, Recognizer, Span};
use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashSet;

static ISO_DATE_REGEX: Lazy<Regex> = Lazy::new(|| compile_regex(r"\b\d{4}-\d{1,2}-\d{1,2}\b"));
static SLASH_DASH_DATE_REGEX: Lazy<Regex> =
    Lazy::new(|| compile_regex(r"\b\d{1,2}[/-]\d{1,2}[/-]\d{4}\b"));
static MONTH_NAME_DATE_REGEX: Lazy<Regex> = Lazy::new(|| {
    compile_regex(
        r"(?i)\b(?:jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|jun(?:e)?|jul(?:y)?|aug(?:ust)?|sep(?:t(?:ember)?)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)\.?\s+\d{1,2},?\s+\d{4}\b",
    )
});
static DAY_MONTH_NAME_DATE_REGEX: Lazy<Regex> = Lazy::new(|| {
    compile_regex(
        r"(?i)\b\d{1,2}\s+(?:jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|jun(?:e)?|jul(?:y)?|aug(?:ust)?|sep(?:t(?:ember)?)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)\.?\s+\d{4}\b",
    )
});

const CONTEXT_TERMS: &[&str] = &[
    "dob",
    "d.o.b",
    "date of birth",
    "birth date",
    "born",
    "born on",
    "birthday",
    "geboortedatum",
];

/// Recognizes dates that are likely dates of birth from nearby birth context.
///
/// # Examples
///
/// ```
/// use cloakrs_core::{EntityType, Recognizer};
/// use cloakrs_patterns::DateOfBirthRecognizer;
///
/// let findings = DateOfBirthRecognizer.scan("DOB: 1980-04-23");
/// assert_eq!(findings[0].entity_type, EntityType::DateOfBirth);
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct DateOfBirthRecognizer;

impl Recognizer for DateOfBirthRecognizer {
    fn id(&self) -> &str {
        "date_of_birth_context_v1"
    }

    fn entity_type(&self) -> EntityType {
        EntityType::DateOfBirth
    }

    fn supported_locales(&self) -> &[Locale] {
        &[]
    }

    fn scan(&self, text: &str) -> Vec<PiiEntity> {
        let mut seen = HashSet::new();
        let mut findings = Vec::new();

        for regex in [
            &*ISO_DATE_REGEX,
            &*SLASH_DASH_DATE_REGEX,
            &*MONTH_NAME_DATE_REGEX,
            &*DAY_MONTH_NAME_DATE_REGEX,
        ] {
            for matched in regex.find_iter(text) {
                if seen.insert((matched.start(), matched.end()))
                    && self.is_valid_match(text, matched.start(), matched.end())
                {
                    findings.push(PiiEntity {
                        entity_type: self.entity_type(),
                        span: Span::new(matched.start(), matched.end()),
                        text: matched.as_str().to_string(),
                        confidence: self.compute_confidence(text, matched.start()),
                        recognizer_id: self.id().to_string(),
                    });
                }
            }
        }

        findings.sort_by_key(|finding| finding.span.start);
        findings
    }

    fn validate(&self, candidate: &str) -> bool {
        parse_date(candidate).is_some()
    }
}

impl DateOfBirthRecognizer {
    fn is_valid_match(&self, text: &str, start: usize, end: usize) -> bool {
        self.validate(&text[start..end])
            && has_birth_context_before(text, start)
            && is_date_boundary(text, start, end)
    }

    fn compute_confidence(&self, text: &str, start: usize) -> Confidence {
        let boost = if has_strong_birth_context_before(text, start) {
            0.15
        } else {
            0.08
        };
        confidence(0.76 + boost)
    }
}

#[derive(Debug, Clone, Copy)]
struct DateParts {
    year: u16,
    month: u8,
    day: u8,
}

fn parse_date(candidate: &str) -> Option<DateParts> {
    parse_iso_date(candidate)
        .or_else(|| parse_numeric_date(candidate))
        .or_else(|| parse_month_name_date(candidate))
        .filter(|date| is_valid_date(*date))
}

fn parse_iso_date(candidate: &str) -> Option<DateParts> {
    let mut parts = candidate.split('-');
    let year = parts.next()?.parse().ok()?;
    let month = parts.next()?.parse().ok()?;
    let day = parts.next()?.parse().ok()?;
    parts
        .next()
        .is_none()
        .then_some(DateParts { year, month, day })
}

fn parse_numeric_date(candidate: &str) -> Option<DateParts> {
    let separator = if candidate.contains('/') { '/' } else { '-' };
    let values: Vec<u16> = candidate
        .split(separator)
        .filter_map(|part| part.parse().ok())
        .collect();
    if values.len() != 3 {
        return None;
    }

    let first = values[0].try_into().ok()?;
    let second = values[1].try_into().ok()?;
    let year = values[2];

    [
        DateParts {
            year,
            month: first,
            day: second,
        },
        DateParts {
            year,
            month: second,
            day: first,
        },
    ]
    .into_iter()
    .find(|date| is_valid_date(*date))
}

fn parse_month_name_date(candidate: &str) -> Option<DateParts> {
    let cleaned = candidate.replace(',', "");
    let parts: Vec<&str> = cleaned.split_whitespace().collect();
    let [first, second, year] = parts.as_slice() else {
        return None;
    };

    if let Some(month) = month_number(first) {
        Some(DateParts {
            year: year.parse().ok()?,
            month,
            day: second.parse().ok()?,
        })
    } else {
        Some(DateParts {
            year: year.parse().ok()?,
            month: month_number(second)?,
            day: first.parse().ok()?,
        })
    }
}

fn month_number(value: &str) -> Option<u8> {
    let lower = value.trim_end_matches('.').to_ascii_lowercase();
    match lower.as_str() {
        "jan" | "january" => Some(1),
        "feb" | "february" => Some(2),
        "mar" | "march" => Some(3),
        "apr" | "april" => Some(4),
        "may" => Some(5),
        "jun" | "june" => Some(6),
        "jul" | "july" => Some(7),
        "aug" | "august" => Some(8),
        "sep" | "sept" | "september" => Some(9),
        "oct" | "october" => Some(10),
        "nov" | "november" => Some(11),
        "dec" | "december" => Some(12),
        _ => None,
    }
}

fn is_valid_date(date: DateParts) -> bool {
    (1900..=2100).contains(&date.year)
        && (1..=12).contains(&date.month)
        && (1..=days_in_month(date.year, date.month)).contains(&date.day)
}

fn days_in_month(year: u16, month: u8) -> u8 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

fn is_leap_year(year: u16) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

fn has_birth_context_before(text: &str, start: usize) -> bool {
    let window = context_window_before(text, start);
    CONTEXT_TERMS.iter().any(|term| window.contains(term))
}

fn has_strong_birth_context_before(text: &str, start: usize) -> bool {
    let window = context_window_before(text, start);
    ["dob", "date of birth", "d.o.b", "geboortedatum"]
        .iter()
        .any(|term| window.contains(term))
}

fn context_window_before(text: &str, start: usize) -> String {
    text[..start]
        .chars()
        .rev()
        .take(80)
        .collect::<String>()
        .chars()
        .rev()
        .collect::<String>()
        .to_ascii_lowercase()
}

fn is_date_boundary(text: &str, start: usize, end: usize) -> bool {
    let before = text[..start].chars().next_back();
    let after = text[end..].chars().next();
    !before.is_some_and(is_date_continuation) && !after.is_some_and(is_date_continuation)
}

fn is_date_continuation(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '/' | '-' | '.')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::default_registry;

    fn texts(input: &str) -> Vec<String> {
        DateOfBirthRecognizer
            .scan(input)
            .into_iter()
            .map(|finding| finding.text)
            .collect()
    }

    #[test]
    fn test_date_of_birth_iso_with_dob_context_detected() {
        assert_eq!(texts("DOB: 1980-04-23"), ["1980-04-23"]);
    }

    #[test]
    fn test_date_of_birth_slash_mdy_with_context_detected() {
        assert_eq!(texts("date of birth 04/23/1980"), ["04/23/1980"]);
    }

    #[test]
    fn test_date_of_birth_slash_dmy_with_context_detected() {
        assert_eq!(texts("born 23/04/1980"), ["23/04/1980"]);
    }

    #[test]
    fn test_date_of_birth_dash_numeric_with_context_detected() {
        assert_eq!(texts("birthday 23-04-1980"), ["23-04-1980"]);
    }

    #[test]
    fn test_date_of_birth_month_name_with_context_detected() {
        assert_eq!(texts("DOB Apr 23, 1980"), ["Apr 23, 1980"]);
    }

    #[test]
    fn test_date_of_birth_day_month_name_with_context_detected() {
        assert_eq!(texts("born 23 April 1980"), ["23 April 1980"]);
    }

    #[test]
    fn test_date_of_birth_geboortedatum_context_detected() {
        assert_eq!(texts("geboortedatum 1980-04-23"), ["1980-04-23"]);
    }

    #[test]
    fn test_date_of_birth_without_birth_context_rejected() {
        assert!(texts("invoice date 1980-04-23").is_empty());
    }

    #[test]
    fn test_date_of_birth_context_after_date_rejected() {
        assert!(texts("1980-04-23 date of birth").is_empty());
    }

    #[test]
    fn test_date_of_birth_invalid_day_rejected() {
        assert!(texts("DOB 1980-04-31").is_empty());
    }

    #[test]
    fn test_date_of_birth_invalid_month_rejected() {
        assert!(texts("DOB 1980-13-23").is_empty());
    }

    #[test]
    fn test_date_of_birth_invalid_february_rejected() {
        assert!(texts("DOB 1981-02-29").is_empty());
    }

    #[test]
    fn test_date_of_birth_leap_day_detected() {
        assert_eq!(texts("DOB 1980-02-29"), ["1980-02-29"]);
    }

    #[test]
    fn test_date_of_birth_embedded_in_word_rejected() {
        assert!(texts("DOB x1980-04-23").is_empty());
    }

    #[test]
    fn test_date_of_birth_embedded_in_longer_date_rejected() {
        assert!(texts("DOB 1980-04-23-01").is_empty());
    }

    #[test]
    fn test_date_of_birth_multiple_values_detected() {
        assert_eq!(
            texts("DOB 1980-04-23 and birthday May 5, 1991"),
            ["1980-04-23", "May 5, 1991"]
        );
    }

    #[test]
    fn test_date_of_birth_strong_context_has_higher_confidence() {
        let strong = DateOfBirthRecognizer.scan("date of birth 1980-04-23");
        let weaker = DateOfBirthRecognizer.scan("born 1980-04-23");
        assert!(strong[0].confidence > weaker[0].confidence);
    }

    #[test]
    fn test_date_of_birth_supported_locales_are_universal() {
        assert!(DateOfBirthRecognizer.supported_locales().is_empty());
    }

    #[test]
    fn test_date_of_birth_default_registry_detects_date_of_birth() {
        let findings = default_registry().scan_all("DOB 1980-04-23");

        assert!(findings
            .iter()
            .any(|finding| finding.entity_type == EntityType::DateOfBirth));
    }
}
