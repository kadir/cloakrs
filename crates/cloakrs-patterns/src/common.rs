use cloakrs_core::{context_score, Confidence, ContextConfig, Span};
use regex::Regex;

pub(crate) fn compile_regex(pattern: &str) -> Regex {
    match Regex::new(pattern) {
        Ok(regex) => regex,
        Err(_) => match Regex::new(r"\b\B") {
            Ok(fallback) => fallback,
            Err(_) => std::process::abort(),
        },
    }
}

pub(crate) fn confidence(value: f64) -> Confidence {
    match Confidence::new(value.clamp(0.0, 1.0)) {
        Ok(confidence) => confidence,
        Err(_) => Confidence::ZERO,
    }
}

pub(crate) fn context_boost(text: &str, start: usize, words: &[&str]) -> f64 {
    context_score(
        text,
        Span::new(start, start),
        words,
        &ContextConfig::default(),
    )
    .adjustment
}

pub(crate) fn is_boundary(text: &str, start: usize, end: usize) -> bool {
    let before = text[..start].chars().next_back();
    let after = text[end..].chars().next();
    !before.is_some_and(is_wordish) && !after.is_some_and(is_wordish)
}

fn is_wordish(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '-')
}

pub(crate) fn digits(value: &str) -> String {
    value.chars().filter(|c| c.is_ascii_digit()).collect()
}

pub(crate) fn alphanumeric_upper(value: &str) -> String {
    value
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .collect()
}
