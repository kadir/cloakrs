# cloakrs

[![CI](https://github.com/kadir/cloakrs/actions/workflows/ci.yml/badge.svg)](https://github.com/kadir/cloakrs/actions/workflows/ci.yml)

`cloakrs` is a Rust library and CLI for detecting and masking personally identifiable information in text, logs, JSON, CSV, and database dumps.

It ships universal recognizers for emails, phone numbers, credit cards, IBANs, IP addresses, URLs, API keys, JWTs, AWS access keys, MAC addresses, hostnames, user home paths, crypto wallet addresses, and context-dependent dates of birth. Locale bundles add identifiers such as US SSNs, Dutch BSNs, UK NINO/NHS numbers, German Steuer-IDs, Indian Aadhaar/PAN values, Brazilian CPF/CNPJ values, and French INSEE/NIR numbers.

See [supported entities](docs/supported-entities.md) for the full detection matrix, including validation algorithms, confidence ranges, and examples.

## Install

```bash
cargo install cloakrs-cli
```

For local development:

```bash
cargo build --workspace
cargo test --workspace
cargo run -p cloakrs-cli -- scan tests/fixtures/sample_text.txt
```

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

# Mask a CSV file, scanning selected columns only.
cloakrs scan users.csv --format csv --columns email,phone --output users.masked.csv
```

## Architecture

The workspace is split into five crates with one-way dependencies:

```text
cloakrs-core -> cloakrs-patterns -> cloakrs-locales -> cloakrs-adapters -> cloakrs-cli
```

- `cloakrs-core`: scanner, recognizer trait, shared types, masking strategies
- `cloakrs-patterns`: universal recognizers such as email, phone, card, IBAN
- `cloakrs-locales`: country-specific recognizers such as US SSN and Dutch BSN
- `cloakrs-adapters`: streaming handlers for text, JSON, CSV, logs, and SQL dumps
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
