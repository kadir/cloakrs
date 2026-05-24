//! `tracing` integration for emitting redacted events.
//!
//! `RedactLayer` scans string/debug field values with a `cloakrs_core::Scanner`
//! and writes sanitized events. It is intentionally a sanitizing output layer;
//! the `tracing` subscriber API does not let one layer mutate fields before
//! unrelated sibling layers observe them.
//!
//! # Examples
//!
//! ```
//! use cloakrs_core::{Confidence, EntityType, Locale, PiiEntity, Recognizer, Scanner, Span};
//! use tracing_subscriber::prelude::*;
//!
//! struct Email;
//! impl Recognizer for Email {
//!     fn id(&self) -> &str { "email_test" }
//!     fn entity_type(&self) -> EntityType { EntityType::Email }
//!     fn supported_locales(&self) -> &[Locale] { &[] }
//!     fn scan(&self, text: &str) -> Vec<PiiEntity> {
//!         text.find('@').map(|at| PiiEntity {
//!             entity_type: EntityType::Email,
//!             span: Span::new(0, text[at..].find(' ').map_or(text.len(), |offset| at + offset)),
//!             text: text[..text[at..].find(' ').map_or(text.len(), |offset| at + offset)].to_string(),
//!             confidence: Confidence::new(0.95).unwrap(),
//!             recognizer_id: self.id().to_string(),
//!         }).into_iter().collect()
//!     }
//! }
//!
//! let scanner = Scanner::builder().recognizer(Email).build().unwrap();
//! let _subscriber = tracing_subscriber::registry()
//!     .with(cloakrs_tracing::RedactLayer::new(scanner));
//! ```

use cloakrs_core::Scanner;
use std::fmt;
use std::io::{self, Write};
use std::sync::{Arc, Mutex};
use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::layer::Context;
use tracing_subscriber::Layer;

/// A tracing layer that writes sanitized events.
pub struct RedactLayer<W = io::Stderr> {
    scanner: Scanner,
    writer: Arc<Mutex<W>>,
}

impl RedactLayer<io::Stderr> {
    /// Creates a redacting layer that writes to stderr.
    #[must_use]
    pub fn new(scanner: Scanner) -> Self {
        Self {
            scanner,
            writer: Arc::new(Mutex::new(io::stderr())),
        }
    }
}

impl<W> RedactLayer<W>
where
    W: Write + Send + 'static,
{
    /// Creates a redacting layer that writes to a caller-provided writer.
    #[must_use]
    pub fn with_writer(scanner: Scanner, writer: W) -> Self {
        Self {
            scanner,
            writer: Arc::new(Mutex::new(writer)),
        }
    }

    /// Creates a redacting layer with a shared writer, useful in tests.
    #[must_use]
    pub fn with_shared_writer(scanner: Scanner, writer: Arc<Mutex<W>>) -> Self {
        Self { scanner, writer }
    }
}

impl<S, W> Layer<S> for RedactLayer<W>
where
    S: Subscriber,
    W: Write + Send + 'static,
{
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let mut visitor = SanitizingVisitor::new(&self.scanner);
        event.record(&mut visitor);
        let metadata = event.metadata();
        let line = render_event(metadata.level(), metadata.target(), &visitor.fields);
        if let Ok(mut writer) = self.writer.lock() {
            let _ = writeln!(writer, "{line}");
        }
    }
}

struct SanitizingVisitor<'a> {
    scanner: &'a Scanner,
    fields: Vec<(String, String)>,
}

impl<'a> SanitizingVisitor<'a> {
    fn new(scanner: &'a Scanner) -> Self {
        Self {
            scanner,
            fields: Vec::new(),
        }
    }

    fn record_value(&mut self, field: &Field, value: String) {
        self.fields
            .push((field.name().to_string(), sanitize(self.scanner, &value)));
    }
}

impl Visit for SanitizingVisitor<'_> {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.record_value(field, format!("{value:?}"));
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.record_value(field, value.to_string());
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.record_value(field, value.to_string());
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.record_value(field, value.to_string());
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.record_value(field, value.to_string());
    }
}

fn sanitize(scanner: &Scanner, value: &str) -> String {
    scanner
        .scan(value)
        .ok()
        .and_then(|result| result.masked_text)
        .unwrap_or_else(|| value.to_string())
}

fn render_event(level: &Level, target: &str, fields: &[(String, String)]) -> String {
    let mut line = format!("level={level} target={}", escape_value(target));
    for (name, value) in fields {
        line.push(' ');
        line.push_str(name);
        line.push('=');
        line.push_str(&escape_value(value));
    }
    line
}

fn escape_value(value: &str) -> String {
    let escaped = value
        .replace('\\', "\\\\")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('"', "\\\"");
    format!("\"{escaped}\"")
}

#[cfg(test)]
mod tests {
    use super::*;
    use cloakrs_core::{Confidence, EntityType, Locale, PiiEntity, Recognizer, Span};
    use std::sync::{Arc, Mutex};
    use tracing_subscriber::prelude::*;

    struct EmailRecognizer;

    impl Recognizer for EmailRecognizer {
        fn id(&self) -> &str {
            "email_test_v1"
        }

        fn entity_type(&self) -> EntityType {
            EntityType::Email
        }

        fn supported_locales(&self) -> &[Locale] {
            &[]
        }

        fn scan(&self, text: &str) -> Vec<PiiEntity> {
            let Some(start) = text.find("jane@example.com") else {
                return Vec::new();
            };
            vec![PiiEntity {
                entity_type: EntityType::Email,
                span: Span::new(start, start + "jane@example.com".len()),
                text: "jane@example.com".to_string(),
                confidence: Confidence::new(0.95).unwrap(),
                recognizer_id: self.id().to_string(),
            }]
        }
    }

    #[test]
    fn test_redact_layer_sanitizes_string_fields() {
        let scanner = Scanner::builder()
            .recognizer(EmailRecognizer)
            .build()
            .unwrap();
        let writer = Arc::new(Mutex::new(Vec::new()));
        let layer = RedactLayer::with_shared_writer(scanner, Arc::clone(&writer));
        let subscriber = tracing_subscriber::registry().with(layer);

        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(email = "jane@example.com", "sending message");
        });

        let output = String::from_utf8(writer.lock().unwrap().clone()).unwrap();
        assert!(output.contains("[EMAIL]"));
        assert!(!output.contains("jane@example.com"));
    }
}
