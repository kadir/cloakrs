# Adding Recognizers

This guide describes how to add a new universal recognizer to `cloakrs-patterns`.
Use `docs/locale-guide.md` for country-specific identifiers.

## 1. Choose The Entity Type

Prefer an existing `cloakrs_core::EntityType` variant. Add a new variant only when
the detected value needs its own redaction tag, risk level, or reporting identity.

## 2. Create The Module

Add a file under `crates/cloakrs-patterns/src/`, for example:

```text
crates/cloakrs-patterns/src/passport.rs
```

Regexes must be static and compiled with `once_cell::sync::Lazy` through the local
`compile_regex` helper.

## 3. Implement `Recognizer`

Every recognizer implements `cloakrs_core::Recognizer`:

```rust
use cloakrs_core::{EntityType, Locale, PiiEntity, Recognizer, Span};

pub struct ExampleRecognizer;

impl Recognizer for ExampleRecognizer {
    fn id(&self) -> &str {
        "example_regex_v1"
    }

    fn entity_type(&self) -> EntityType {
        EntityType::Custom("example".to_string())
    }

    fn supported_locales(&self) -> &[Locale] {
        &[]
    }

    fn scan(&self, _text: &str) -> Vec<PiiEntity> {
        Vec::new()
    }
}
```

Use an empty `supported_locales()` slice for universal recognizers. Use a stable,
versioned recognizer ID and do not change it once released.

## 4. Validate Beyond Regex

Regex should extract candidates, not be the whole validator. Use checksum,
range, parser, and boundary checks where possible. Prefer structured parsing
from the standard library or a small local validator over ad hoc string matching.

Examples already in the repo:

- Credit card: Luhn checksum.
- IBAN: country length plus MOD-97.
- IP address: `std::net::IpAddr`.
- Date of birth: calendar validation plus birth context.

## 5. Confidence And Context

Use conservative base confidence for noisy patterns, then boost when nearby
context is present. Avoid recognizing broad identifiers without context unless
the structure is strong enough on its own.

## 6. Register And Export

Update `crates/cloakrs-patterns/src/lib.rs`:

```rust
mod example;
pub use example::ExampleRecognizer;

pub fn register_default_recognizers(registry: &mut RecognizerRegistry) {
    registry.register(ExampleRecognizer);
}
```

## 7. Test Requirements

Use test names in `test_<what>_<condition>_<expected>` style. Cover:

- Valid examples.
- Multiple findings.
- Invalid examples.
- Boundary rejection.
- Context confidence behavior.
- Locale behavior if relevant.
- Default registry integration.

Run:

```bash
cargo fmt --all -- --check
cargo test -p cloakrs-patterns
cargo clippy -p cloakrs-patterns -- -D warnings
```

