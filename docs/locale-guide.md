# Locale Guide

Locale-specific recognizers live in `crates/cloakrs-locales`. They should be used
for identifiers that only make sense for one country or regional bundle, such as
Dutch BSN, UK NINO, German Steuer-ID, Indian Aadhaar, Brazilian CPF/CNPJ, and
French INSEE/NIR.

## Dependency Rule

Keep the one-way dependency flow:

```text
cloakrs-core -> cloakrs-patterns -> cloakrs-locales -> cloakrs-adapters -> cloakrs-cli
```

`cloakrs-core` must never depend on `cloakrs-patterns` or `cloakrs-locales`.

## Adding A Locale Recognizer

1. Add or update a locale module, for example `crates/cloakrs-locales/src/es_es.rs`.
2. Implement `cloakrs_core::Recognizer`.
3. Return the exact supported locale slice from `supported_locales()`.
4. Validate with official public algorithms where available.
5. Keep no-context confidence conservative for short numeric identifiers.
6. Register the recognizer in `register_locale_recognizers(...)`.
7. Export it from `crates/cloakrs-locales/src/lib.rs`.

## EU Meta-Locale

The current EU bundle is implemented by making EU-country recognizers support
both their country locale and `Locale::EU`. This avoids duplicate wrapper
recognizers and duplicate findings.

Only add a recognizer to `Locale::EU` when the identifier belongs to an EU member
country or is intentionally universal in the default registry.

## Test Checklist

Every locale recognizer should include:

- Valid official or synthetic examples.
- Invalid checksum examples.
- Invalid format examples.
- Boundary rejection.
- Context confidence tests.
- Locale filtering tests.
- Default locale registry integration.

Run:

```bash
cargo fmt --all -- --check
cargo test -p cloakrs-locales
cargo clippy -p cloakrs-locales -- -D warnings
```

