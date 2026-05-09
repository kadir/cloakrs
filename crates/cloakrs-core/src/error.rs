//! Error types returned by cloakrs.

/// Convenient result alias for cloakrs operations.
pub type Result<T> = std::result::Result<T, CloakError>;

/// Errors produced by cloakrs core APIs.
#[derive(Debug, thiserror::Error)]
pub enum CloakError {
    /// A confidence score was outside the inclusive `0.0..=1.0` range.
    #[error("invalid confidence score: {0} (must be 0.0-1.0)")]
    InvalidConfidence(f64),

    /// A scanner was built or used without any recognizers.
    #[error("no recognizers registered")]
    NoRecognizers,

    /// A span does not point at valid UTF-8 character boundaries in the source text.
    #[error("invalid span {start}..{end} for text length {len}")]
    InvalidSpan {
        /// Start byte offset.
        start: usize,
        /// End byte offset.
        end: usize,
        /// Source text length in bytes.
        len: usize,
    },

    /// Regex compilation failed.
    #[error("regex compilation error: {0}")]
    RegexError(#[from] regex::Error),

    /// IO failed.
    #[error("io error: {0}")]
    IoError(#[from] std::io::Error),

    /// JSON parsing or serialization failed.
    #[error("json error: {0}")]
    JsonError(#[from] serde_json::Error),

    /// CSV parsing or serialization failed.
    #[error("csv error: {0}")]
    CsvError(#[from] csv::Error),

    /// Encryption failed.
    #[error("encryption error: {0}")]
    EncryptionError(String),

    /// Configuration is invalid.
    #[error("invalid configuration: {0}")]
    ConfigError(String),
}
