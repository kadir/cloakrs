# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/).

## [0.3.0] - 2026-05-24

### Added
- Dictionary-backed person-name and US-style physical-address recognizers.
- Scanner literal allow and deny lists, with `.cloakrs.toml` support in the CLI.
- `PromptSanitizer` and prompt placeholder mapping helpers for LLM workflows.
- `cloakrs pre-commit`, pre-commit hook metadata, and structured JSONL audit logging.
- `cloakrs-tracing` with `RedactLayer` for sanitized tracing event output.
- A 10,000-line false-positive corpus test for default recognizers.

## [0.2.0] - 2026-05-16

### Added
- Hostname recognizer for internal DNS names, cloud infrastructure hostnames, mDNS names, and Windows machine names.
- User home path recognizer for Linux, macOS, Windows, and root paths that expose usernames.
- Redaction tags, partial masking, and username-only hash masking for the new entity types.
- Supported-entities documentation for `Hostname` and `UserPath`.

## [0.1.0] - 2026-05-09

### Added
- Core PII detection engine with confidence scoring and context-aware boosting
- Universal recognizers: Email, Phone, Credit Card (Luhn), IBAN (MOD-97), IP Address, URL, API Key, JWT, AWS Access Key, MAC Address, Crypto Wallet, Date of Birth
- Locale recognizers: US SSN, Dutch BSN (MOD-11), UK NINO, UK NHS Number, German Steuer-ID, Indian Aadhaar (Verhoeff), Indian PAN, Brazilian CPF, Brazilian CNPJ, French INSEE/NIR
- Five masking strategies: Redact, Partial Mask, Hash (SHA-256), Replace (fake data), Encrypt (AES-256-GCM)
- Format adapters: Plain text, JSON (path-aware), CSV (column-aware), Log stream (stdin), SQL dump
- CLI with three subcommands: `scan`, `stream`, `audit`
- Output formats: human-readable text, JSON report, SARIF for CI/CD
- Criterion benchmark suite
- Cross-platform install script
