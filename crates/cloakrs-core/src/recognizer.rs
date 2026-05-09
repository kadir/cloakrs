//! Recognizer trait and registry.

use crate::ScannerBuilder;
use crate::{EntityType, Locale, PiiEntity};

/// A recognizer that can detect a specific type of PII.
///
/// # Examples
///
/// ```
/// use cloakrs_core::{EntityType, Locale, PiiEntity, Recognizer};
///
/// struct EmptyRecognizer;
///
/// impl Recognizer for EmptyRecognizer {
///     fn id(&self) -> &str { "empty_v1" }
///     fn entity_type(&self) -> EntityType { EntityType::Email }
///     fn supported_locales(&self) -> &[Locale] { &[] }
///     fn scan(&self, _text: &str) -> Vec<PiiEntity> { Vec::new() }
/// }
/// ```
pub trait Recognizer: Send + Sync {
    /// Unique, versioned identifier for this recognizer.
    fn id(&self) -> &str;

    /// The entity type this recognizer detects.
    fn entity_type(&self) -> EntityType;

    /// Locales this recognizer applies to. Empty means universal.
    fn supported_locales(&self) -> &[Locale];

    /// Scans the input text and returns all findings.
    fn scan(&self, text: &str) -> Vec<PiiEntity>;

    /// Validates a candidate match. Override for checksum-backed PII.
    fn validate(&self, _candidate: &str) -> bool {
        true
    }
}

/// Registry that holds active recognizers.
///
/// # Examples
///
/// ```
/// use cloakrs_core::RecognizerRegistry;
///
/// let registry = RecognizerRegistry::new();
/// assert!(registry.is_empty());
/// ```
#[derive(Default)]
pub struct RecognizerRegistry {
    recognizers: Vec<Box<dyn Recognizer>>,
}

impl RecognizerRegistry {
    /// Creates an empty recognizer registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a recognizer.
    pub fn register<R>(&mut self, recognizer: R)
    where
        R: Recognizer + 'static,
    {
        self.recognizers.push(Box::new(recognizer));
    }

    /// Registers an already boxed recognizer.
    pub fn register_boxed(&mut self, recognizer: Box<dyn Recognizer>) {
        self.recognizers.push(recognizer);
    }

    /// Returns the number of registered recognizers.
    #[must_use]
    pub fn len(&self) -> usize {
        self.recognizers.len()
    }

    /// Returns true when no recognizers are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.recognizers.is_empty()
    }

    /// Scans text using every registered recognizer.
    #[must_use]
    pub fn scan_all(&self, text: &str) -> Vec<PiiEntity> {
        self.recognizers
            .iter()
            .flat_map(|recognizer| recognizer.scan(text))
            .collect()
    }

    /// Scans text using recognizers that support the requested locale.
    #[must_use]
    pub fn scan_locale(&self, text: &str, locale: &Locale) -> Vec<PiiEntity> {
        self.recognizers
            .iter()
            .filter(|recognizer| supports_locale(recognizer.supported_locales(), locale))
            .flat_map(|recognizer| recognizer.scan(text))
            .collect()
    }

    /// Scans text using recognizers for one entity type.
    #[must_use]
    pub fn scan_entity_type(&self, text: &str, entity_type: &EntityType) -> Vec<PiiEntity> {
        self.recognizers
            .iter()
            .filter(|recognizer| &recognizer.entity_type() == entity_type)
            .flat_map(|recognizer| recognizer.scan(text))
            .collect()
    }

    /// Converts this registry into a scanner builder.
    #[must_use]
    pub fn into_scanner_builder(self) -> ScannerBuilder {
        ScannerBuilder::from_registry(self)
    }
}

fn supports_locale(supported: &[Locale], requested: &Locale) -> bool {
    supported.is_empty()
        || supported
            .iter()
            .any(|locale| locale == requested || locale == &Locale::Universal)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Confidence, Span};

    struct TestRecognizer {
        locale: Vec<Locale>,
    }

    impl Recognizer for TestRecognizer {
        fn id(&self) -> &str {
            "test_v1"
        }

        fn entity_type(&self) -> EntityType {
            EntityType::Email
        }

        fn supported_locales(&self) -> &[Locale] {
            &self.locale
        }

        fn scan(&self, text: &str) -> Vec<PiiEntity> {
            vec![PiiEntity {
                entity_type: EntityType::Email,
                span: Span::new(0, text.len()),
                text: text.to_string(),
                confidence: Confidence::new(0.9).unwrap(),
                recognizer_id: self.id().to_string(),
            }]
        }
    }

    #[test]
    fn test_registry_new_is_empty() {
        assert!(RecognizerRegistry::new().is_empty());
    }

    #[test]
    fn test_registry_register_increases_len() {
        let mut registry = RecognizerRegistry::new();
        registry.register(TestRecognizer { locale: vec![] });
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn test_registry_scan_all_returns_findings() {
        let mut registry = RecognizerRegistry::new();
        registry.register(TestRecognizer { locale: vec![] });
        assert_eq!(registry.scan_all("hello").len(), 1);
    }

    #[test]
    fn test_registry_scan_locale_filters_by_requested_locale() {
        let mut registry = RecognizerRegistry::new();
        registry.register(TestRecognizer {
            locale: vec![Locale::US],
        });
        assert_eq!(registry.scan_locale("hello", &Locale::NL).len(), 0);
    }

    #[test]
    fn test_registry_scan_universal_locale_excludes_specific_locale() {
        let mut registry = RecognizerRegistry::new();
        registry.register(TestRecognizer {
            locale: vec![Locale::US],
        });
        assert_eq!(registry.scan_locale("hello", &Locale::Universal).len(), 0);
    }
}
