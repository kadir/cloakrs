//! Core types and scanning primitives for cloakrs.
//!
//! `cloakrs-core` contains the public data model, recognizer trait,
//! registry, scanner, and masking strategy implementations shared by the
//! rest of the workspace.
//!
//! # Examples
//!
//! ```
//! use cloakrs_core::{Confidence, EntityType, Locale, PiiEntity, Recognizer, Scanner, Span};
//!
//! struct Email;
//! impl Recognizer for Email {
//!     fn id(&self) -> &str { "email_example_v1" }
//!     fn entity_type(&self) -> EntityType { EntityType::Email }
//!     fn supported_locales(&self) -> &[Locale] { &[] }
//!     fn scan(&self, text: &str) -> Vec<PiiEntity> {
//!         text.find('@').map(|_| PiiEntity {
//!             entity_type: EntityType::Email,
//!             span: Span::new(0, text.len()),
//!             text: text.to_string(),
//!             confidence: Confidence::new(0.9).unwrap(),
//!             recognizer_id: self.id().to_string(),
//!         }).into_iter().collect()
//!     }
//! }
//!
//! let scanner = Scanner::builder().recognizer(Email).build().unwrap();
//! let result = scanner.scan("jane@example.com").unwrap();
//! assert_eq!(result.masked_text.as_deref(), Some("[EMAIL]"));
//! ```

mod context;
mod error;
mod finding;
mod masker;
mod prompt;
mod recognizer;
mod scanner;

pub use context::{context_score, surrounding_context, ContextConfig, ContextScore, ContextWindow};
pub use error::{CloakError, Result};
pub use finding::{Confidence, EntityType, Locale, PiiEntity, Span};
pub use masker::{apply_mask, decrypt_masked_value, MaskStrategy};
pub use prompt::{PromptMapping, PromptMappingEntry, PromptSanitizer};
pub use recognizer::{Recognizer, RecognizerRegistry};
pub use scanner::{ScanResult, ScanStats, Scanner, ScannerBuilder};
