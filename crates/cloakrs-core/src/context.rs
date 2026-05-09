//! Context-aware confidence scoring.

use crate::Span;
use serde::{Deserialize, Serialize};

/// Configuration for context-aware confidence scoring.
///
/// # Examples
///
/// ```
/// use cloakrs_core::ContextConfig;
///
/// let config = ContextConfig::default();
/// assert_eq!(config.words_before, 5);
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContextConfig {
    /// Number of words to inspect before the match.
    pub words_before: usize,
    /// Number of words to inspect after the match.
    pub words_after: usize,
    /// Boost for one positive context hit.
    pub single_hit_boost: f64,
    /// Boost for two or more positive context hits.
    pub multi_hit_boost: f64,
    /// Penalty when code-like context is detected.
    pub code_context_penalty: f64,
}

impl Default for ContextConfig {
    fn default() -> Self {
        Self {
            words_before: 5,
            words_after: 3,
            single_hit_boost: 0.10,
            multi_hit_boost: 0.15,
            code_context_penalty: 0.20,
        }
    }
}

/// Words surrounding a candidate match.
///
/// # Examples
///
/// ```
/// use cloakrs_core::{surrounding_context, ContextConfig, Span};
///
/// let window = surrounding_context(
///     "my email is jane@example.com today",
///     Span::new(12, 28),
///     &ContextConfig::default(),
/// );
/// assert!(window.before.contains(&"email".to_string()));
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextWindow {
    /// Lowercased words before the match.
    pub before: Vec<String>,
    /// Lowercased words after the match.
    pub after: Vec<String>,
}

/// Result of context scoring.
///
/// # Examples
///
/// ```
/// use cloakrs_core::{context_score, ContextConfig, Span};
///
/// let score = context_score(
///     "email jane@example.com",
///     Span::new(6, 22),
///     &["email"],
///     &ContextConfig::default(),
/// );
/// assert!(score.adjustment > 0.0);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct ContextScore {
    /// Adjustment to add to a recognizer's base confidence.
    pub adjustment: f64,
    /// Number of matching positive context terms.
    pub positive_hits: usize,
    /// Whether code-like context was detected.
    pub code_like: bool,
}

/// Extracts lowercased words before and after a candidate span.
#[must_use]
pub fn surrounding_context(text: &str, span: Span, config: &ContextConfig) -> ContextWindow {
    let start = span.start.min(text.len());
    let end = span.end.min(text.len());
    let before_text = text.get(..start).unwrap_or_default();
    let after_text = text.get(end..).unwrap_or_default();

    let mut before = words(before_text);
    let before_start = before.len().saturating_sub(config.words_before);
    before = before.split_off(before_start);

    let after = words(after_text)
        .into_iter()
        .take(config.words_after)
        .collect();

    ContextWindow { before, after }
}

/// Computes a bounded context confidence adjustment.
#[must_use]
pub fn context_score(
    text: &str,
    span: Span,
    positive_terms: &[&str],
    config: &ContextConfig,
) -> ContextScore {
    let window = surrounding_context(text, span, config);
    let haystack = window
        .before
        .iter()
        .chain(window.after.iter())
        .cloned()
        .collect::<Vec<_>>()
        .join(" ");

    let positive_hits = positive_terms
        .iter()
        .filter(|term| haystack.contains(&term.to_ascii_lowercase()))
        .count();

    let mut adjustment = match positive_hits {
        0 => 0.0,
        1 => config.single_hit_boost,
        _ => config.multi_hit_boost,
    };

    let code_like = is_code_like_context(&window);
    if code_like {
        adjustment -= config.code_context_penalty;
    }

    ContextScore {
        adjustment,
        positive_hits,
        code_like,
    }
}

fn is_code_like_context(window: &ContextWindow) -> bool {
    const CODE_TERMS: &[&str] = &["=", "var", "let", "const", "fn", "function"];
    window
        .before
        .iter()
        .rev()
        .take(3)
        .any(|word| CODE_TERMS.contains(&word.as_str()))
}

fn words(text: &str) -> Vec<String> {
    text.split(|c: char| !(c.is_alphanumeric() || matches!(c, '_' | '-' | ':' | '=')))
        .filter(|word| !word.is_empty())
        .map(|word| word.to_ascii_lowercase())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_surrounding_context_collects_before_and_after_words() {
        let window = surrounding_context(
            "my email is jane@example.com today please",
            Span::new(12, 28),
            &ContextConfig::default(),
        );
        assert!(window.before.contains(&"email".to_string()));
        assert!(window.after.contains(&"today".to_string()));
    }

    #[test]
    fn test_context_score_single_hit_boosts() {
        let score = context_score(
            "email jane@example.com",
            Span::new(6, 22),
            &["email"],
            &ContextConfig::default(),
        );
        assert_eq!(score.positive_hits, 1);
        assert_eq!(score.adjustment, 0.10);
    }

    #[test]
    fn test_context_score_multiple_hits_uses_larger_boost() {
        let score = context_score(
            "contact email jane@example.com",
            Span::new(14, 30),
            &["contact", "email"],
            &ContextConfig::default(),
        );
        assert_eq!(score.positive_hits, 2);
        assert_eq!(score.adjustment, 0.15);
    }

    #[test]
    fn test_context_score_code_context_penalizes() {
        let score = context_score(
            "let email = jane@example.com",
            Span::new(12, 28),
            &["email"],
            &ContextConfig::default(),
        );
        assert!(score.code_like);
        assert!(score.adjustment < 0.0);
    }

    #[test]
    fn test_context_score_no_terms_returns_zero() {
        let score = context_score(
            "value jane@example.com",
            Span::new(6, 22),
            &["email"],
            &ContextConfig::default(),
        );
        assert_eq!(score.adjustment, 0.0);
    }
}
