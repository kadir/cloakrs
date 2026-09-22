# Implementation Status

cloakrs 0.3.1 is prepared as a Rust workspace with library crates and a CLI:

- `cloakrs-core`
- `cloakrs-patterns`
- `cloakrs-locales`
- `cloakrs-adapters`
- `cloakrs-tracing`
- `cloakrs-cli`

The current release includes universal PII and sensitive-data recognizers, including hostnames, user home paths, dictionary-backed person names, and US-style physical addresses; locale-specific identity recognizers; masking strategies; a hardened LLM prompt sanitizer (deduplicated placeholders, redacted `Debug` output, tolerant placeholder restore) with dedicated `sanitize`/`restore` CLI subcommands; format adapters for text/JSON/CSV/logs/SQL; CLI scan/stream/audit/pre-commit/sanitize/restore commands; SARIF output; structured JSONL audit logging; a tracing integration crate; release automation; and public contributor guides.

Python bindings and WASM packages are future work. The current package is a Rust library and native CLI.

See [supported entities](supported-entities.md) for the complete detection matrix.
