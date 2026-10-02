# Implementation Status

The published Rust/CLI release is cloakrs 0.4.0. The workspace contains:

- `cloakrs-core`
- `cloakrs-patterns`
- `cloakrs-locales`
- `cloakrs-adapters`
- `cloakrs-tracing`
- `cloakrs-cli`

The current release includes universal PII and sensitive-data recognizers, including hostnames, user home paths, dictionary-backed person names, and US-style physical addresses; locale-specific identity recognizers; masking strategies; a hardened LLM prompt sanitizer (deduplicated placeholders, redacted `Debug` output, tolerant placeholder restore) with dedicated `sanitize`/`restore` CLI subcommands; format adapters for text/JSON/CSV/logs/SQL; CLI scan/stream/audit/pre-commit/sanitize/restore commands; SARIF output; structured JSONL audit logging; a tracing integration crate; release automation; and public contributor guides.

Version 0.4.0 adds opt-in entity exclusions through the Rust builder, CLI, and
TOML configuration. Default detection is unchanged. Excluding a URL can leave
embedded credentials visible; see [entity exclusions](entity-exclusions.md).

The [Python alpha package](../bindings/python/README.md) supports scanning,
redaction, and reversible prompt sanitization through the existing Rust engine,
with typed findings, Python string indices, and CLI-compatible mapping JSON.
Python [0.1.0a2](https://pypi.org/project/cloakrs/0.1.0a2/) is published with the
email quote-boundary fix from the 0.4.1 engine source. This does not publish
Rust crates or native CLI archives. The Python package is available on PyPI
with wheels for Linux x86_64/ARM64, macOS Intel/Apple Silicon, and Windows
x86_64, plus a source package. Release checks verify downloads and clean
installs on Python 3.11 and 3.14 for all five targets. See the
[Python bindings plan](python-bindings-plan.md) and
[release guide](python-releases.md). WASM packages remain future work.

See [supported entities](supported-entities.md) for the complete detection matrix.
