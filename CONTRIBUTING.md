# Contributing to cloakrs

Thanks for helping build `cloakrs`.

## Development Commands

```bash
cargo fmt --workspace
cargo clippy --workspace -- -D warnings
cargo test --workspace
cargo doc --workspace --no-deps
```

## Code Style

- Use Rust 2021 and keep compatibility with MSRV 1.75.0.
- Do not use `unwrap()` in library code. Use `Result`, `?`, or explicit handling.
- Compile regular expressions once with `std::sync::LazyLock`.
- Public APIs need rustdoc, preferably with short examples.
- Keep dependency direction one-way across crates.

## Adding a Recognizer

1. Add the recognizer to `cloakrs-patterns` for universal PII or `cloakrs-locales` for country-specific PII.
2. Implement `cloakrs_core::Recognizer`.
3. Add checksum validation when the PII type has a known checksum.
4. Add context words for confidence boosting.
5. Export the recognizer from the crate `lib.rs`.
6. Add focused tests, including positives, negatives, edge cases, and context confidence tests.
7. Register the recognizer in the default scanner loader once that loader exists.

## Pull Requests

- Keep PRs focused on one recognizer, adapter, strategy, or infrastructure change.
- Include tests for behavior changes.
- Run format, clippy, tests, and docs before opening a PR.
