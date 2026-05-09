# Implementation Status

cloakrs 0.1.0 is published as a Rust workspace with library crates and a CLI:

- `cloakrs-core`
- `cloakrs-patterns`
- `cloakrs-locales`
- `cloakrs-adapters`
- `cloakrs-cli`

The current release includes universal PII recognizers, locale-specific identity recognizers, masking strategies, format adapters for text/JSON/CSV/logs/SQL, CLI scan/stream/audit commands, SARIF output, release automation, and public contributor guides.

Python bindings are future work. The current package is a Rust library and native CLI.

See [supported entities](supported-entities.md) for the complete detection matrix.
