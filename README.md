# cloakrs

[![CI](https://github.com/kadir/cloakrs/actions/workflows/ci.yml/badge.svg)](https://github.com/kadir/cloakrs/actions/workflows/ci.yml)

`cloakrs` is a Rust library and CLI for detecting and masking personally identifiable information in text, logs, JSON, CSV, and database dumps.

It ships universal recognizers for emails, phone numbers, credit cards, IBANs, IP addresses, URLs, API keys, JWTs, AWS access keys, MAC addresses, hostnames, user home paths, person names, physical addresses, crypto wallet addresses, and context-dependent dates of birth. Locale bundles add identifiers such as US SSNs, Dutch BSNs, UK NINO/NHS numbers, German Steuer-IDs, Indian Aadhaar/PAN values, Brazilian CPF/CNPJ values, and French INSEE/NIR numbers.

See [supported entities](docs/supported-entities.md) for the full detection matrix, including validation algorithms, confidence ranges, and examples.

## Install

```bash
cargo install cloakrs-cli --locked
```

Prebuilt binaries are available for Linux, macOS, and Windows on the
[releases page](https://github.com/kadir/cloakrs/releases). The repository's
`install.sh` installs on Linux/macOS, verifies the release checksum and binary
version, and defaults to `~/.local/bin` without requiring root. See the
[installation guide](docs/installation.md) for platform requirements, pinned
versions, and Windows instructions.

For local development:

```bash
cargo build --workspace
cargo test --workspace
cargo run -p cloakrs-cli -- scan tests/fixtures/sample_text.txt
```

## Python (alpha)

The Python package uses the same Rust engine for local text scanning, masking,
and reversible prompt sanitization:

```sh
python -m pip install --only-binary=:all: 'cloakrs==0.1.0a2'
```

```python
from cloakrs import Scanner, Sanitizer

assert Scanner().mask("Email jane@example.com") == "Email [EMAIL]"
clean, mapping = Sanitizer().sanitize("Email jane@example.com")
assert mapping.restore(clean) == "Email jane@example.com"
```

Keep the mapping private: it contains original values. Python 3.11–3.14 is
supported with wheels for Linux x86_64/ARM64, macOS Intel/Apple Silicon, and
Windows x86_64. See the [Python documentation](bindings/python/README.md) for
platform requirements, configuration, examples, and prerelease limitations.

## Quick Start

```rust
use cloakrs_core::Locale;

let scanner = cloakrs_locales::default_registry()
    .into_scanner_builder()
    .locale(Locale::US)
    .build()?;

let result = scanner.scan("Contact jane@example.com or ssn 123-45-6789")?;
assert_eq!(result.masked_text.as_deref(), Some("Contact [EMAIL] or ssn [SSN]"));
# Ok::<(), cloakrs_core::CloakError>(())
```

## CLI Examples

```bash
# Scan a file and print a human-readable report.
cloakrs scan tests/fixtures/sample_text.txt --locale us --output-format text

# Produce SARIF for code scanning systems.
cloakrs audit . --output-format sarif --output cloakrs.sarif

# Run from the pre-commit framework against staged file paths.
cloakrs pre-commit src/lib.rs README.md --min-confidence 0.8

# Mask a CSV file, scanning selected columns only.
cloakrs scan users.csv --format csv --columns email,phone --output users.masked.csv

# Sanitize a prompt before sending it to an LLM, keeping the restore key in mapping.json.
# The mapping file contains the original sensitive values -- treat it like a secret.
cloakrs sanitize prompt.txt --mapping mapping.json --output clean.txt

# Restore placeholders in the model's response using that mapping (tolerant by default).
cloakrs restore response.txt --mapping mapping.json --output final.txt

# Keep URLs, hostnames, and user paths while masking other entities (0.4.0+).
cloakrs --exclude-entities url,hostname,user-path stream
```

The same exclusions can be configured in `.cloakrs.toml`:

```toml
exclude_entities = ["url", "hostname", "user-path"]
```

Entity exclusions are available starting with version 0.4.0.
They apply to `scan`, `stream`, `audit`, `pre-commit`, and `sanitize`; `restore`
uses its saved mapping. CLI and TOML exclusions are combined, and unknown names
are rejected. Excluding `url` preserves URLs while nested URL-query recognizers
can still mask supported PII such as email addresses and US SSNs.

**Warning:** Excluding `url` can expose URL-embedded credentials that no other recognizer catches. For example, `https://alice:supersecret@example.com/private` and percent-encoded API keys in query parameters can remain visible. Keep URL detection enabled when those values must be masked.

See [entity exclusions](docs/entity-exclusions.md) for configuration rules, Rust
usage, and a sanitization example. With no exclusions configured, all existing
entity types remain enabled for the selected locale.

## LLM Prompt Sanitization

```rust
use cloakrs_core::{Locale, PromptSanitizer, Result};

fn main() -> Result<()> {
    let scanner = cloakrs_locales::default_registry()
        .into_scanner_builder()
        .locale(Locale::US)
        .build()?;
    let sanitizer = PromptSanitizer::new(scanner);
    let (clean_prompt, mapping) =
        sanitizer.sanitize("Email jane@example.com about the invoice")?;
    assert_eq!(clean_prompt, "Email [EMAIL_1] about the invoice");
    let restored = sanitizer.restore("I emailed [EMAIL_1]", &mapping);
    assert_eq!(restored, "I emailed jane@example.com");
    Ok(())
}
```

Mapping JSON contains the original sensitive values. Keep it local and protect it like a
secret. Mapping and restored-output files are created with mode `0600` on Unix; on
Windows, access follows the destination directory's ACLs. Keep that directory private.
Detection is pattern-based and may miss unsupported or encoded values; sanitization is
not a guarantee that arbitrary text is free of sensitive information.

## Architecture

The workspace is split into six crates with one-way dependencies:

```text
cloakrs-core -> cloakrs-patterns -> cloakrs-locales -> cloakrs-adapters -> cloakrs-cli
cloakrs-core -> cloakrs-tracing
```

- `cloakrs-core`: scanner, recognizer trait, shared types, masking strategies
- `cloakrs-patterns`: universal recognizers such as email, phone, card, IBAN
- `cloakrs-locales`: country-specific recognizers such as US SSN and Dutch BSN
- `cloakrs-adapters`: streaming handlers for text, JSON, CSV, logs, and SQL dumps
- `cloakrs-tracing`: a `tracing_subscriber` layer for redacted event output
- `cloakrs-cli`: the `cloakrs` command-line interface

## Comparison

| Tool | Language | Runtime requirements | Primary fit | Benchmark status |
| --- | --- | --- | --- | --- |
| cloakrs | Rust | Single native binary | Fast local scanning and masking | Criterion suite included |
| Microsoft Presidio | Python | Python plus NLP dependencies | NLP-rich enterprise workflows | Run locally for same-hardware numbers |
| DataFog | Python | Python runtime | App-level PII detection | Run locally for same-hardware numbers |
| scrubadub | Python | Python runtime | Text scrubbing | Not benchmarked in-tree |
| piidetect | Go | Native binary | Lightweight PII detection | Not benchmarked in-tree |

Run the local benchmark suite with:

```bash
cargo bench -p cloakrs-cli --bench scan_benchmark
```

The benchmark harness covers 1KB through 10MB inputs for plain text, JSON, and CSV, each recognizer individually, and all masking strategies. See [docs/benchmarking.md](docs/benchmarking.md).

## Guides

- [Installation and checksum verification](docs/installation.md)
- [Security model and reporting](SECURITY.md)
- [Detection evaluation and known gaps](docs/evaluation.md)
- [Entity exclusions](docs/entity-exclusions.md)
- [Adding recognizers](docs/adding-recognizers.md)
- [Adding locale recognizers](docs/locale-guide.md)
- [Supported entities](docs/supported-entities.md)
- [CI/CD integration](docs/ci-cd-integration.md)
- [Benchmarking](docs/benchmarking.md)
- [Release checklist](docs/release-checklist.md)

## Status

The first Rust release is published on crates.io. See [implementation status](docs/implementation-status.md) for completed work and known gaps.

## License

MIT. See [LICENSE.md](LICENSE.md).
