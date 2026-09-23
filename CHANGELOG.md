# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/).

## [0.3.2] - 2026-09-23

### Security
- Encryption now uses a fresh OS-random nonce per value instead of deriving it
  from plaintext and finding metadata. `ENC[...]` output is nondeterministic;
  existing ciphertext remains decryptable. Stored ciphertext is not automatically
  upgraded; see [the security notes](SECURITY.md) for migration and key handling.
- `MaskStrategy` debug formatting redacts encryption keys and hash salts.
  Serialization still includes these values by design.

### Fixed
- The Linux/macOS installer now uses the actual published asset names and
  `SHA256SUMS.txt`, pins latest downloads to one release tag, validates the binary
  version, and stages installation before replacing an existing binary.
- Corrected invalid UK NINO, Indian Aadhaar/PAN, and German tax-ID examples in
  the supported-entities guide using values exercised by the labeled evaluation.

### Added
- Offline installer tests, installation instructions including Windows checksum
  verification, and documented security boundaries and reporting instructions.
- A 58-case labeled synthetic detection corpus with exact-span precision/recall,
  per-entity and per-category breakdowns, known misses, latency measurements, and
  peak process memory on Linux/macOS. This is a regression baseline, not a
  representative real-world accuracy claim.
- Installer and detection-baseline CI gates; dependency audits now also run
  during pull-request and release verification.
- Published release checks verify archive checksums, binary version, detection,
  and masking on all six targets, plus pinned/latest shell installation on
  Linux and macOS. GitHub release notes are taken from this changelog.

## [0.3.1] - 2026-09-22

### Fixed
- `PromptSanitizer::sanitize` now deduplicates identical `(entity_type, original_text)`
  values within a single call, so a repeated value reuses one placeholder instead of
  incrementing a new one each time (e.g. the same email no longer becomes `[EMAIL_1]` and
  `[EMAIL_2]`).
- `PromptMapping::restore` now tolerates
  placeholders that differ from the original only by ASCII case or interior whitespace
  (`[ email_1 ]`, `[Email_1]`), matching how LLMs actually echo placeholders back. Index
  matching is exact, so `[EMAIL_1]` never matches inside `[EMAIL_10]`, and unknown
  placeholders are left untouched.
- Sanitization handles nested URL findings without overlapping replacements and avoids
  collisions with placeholders already present in the input.
- Strict restoration preserves exact index spelling and replacements are non-recursive.
- Context scoring only tokenizes the requested neighboring words instead of the entire
  document for each finding, and overlap resolution skips completed spans. These changes
  avoid excessive work on large inputs while preserving detection results.
- Log streaming retains URL and API-key context and scans sensitive text outside log fields.
- Mapping files are created privately and saved atomically without following destination
  symlinks. Existing files cannot be overwritten without `--force`; input/output aliases
  of the mapping are rejected. Restored output files are also private on Unix.
- Sanitize/restore stdout preserves input newline boundaries exactly.
- Refreshed the lockfile for the supported Rust 1.75 toolchain; CI and release builds use
  `--locked` to keep dependency selection reproducible.

### Changed
- Preserved the public `PromptMapping::entries` and `PromptMappingEntry::original`
  fields and the existing JSON shape for compatibility with 0.3.0. Added `entries()`,
  `get()`, and `original_value()` accessors for explicit access to sensitive values.
- `Debug` for `PromptMapping` and `PromptMappingEntry` is now hand-written and redacts the
  original value, showing only the placeholder, entity type, and confidence. `Serialize`/`Deserialize` (the mapping JSON file)
  are unaffected and still contain the real values by design — treat mapping files as
  secrets.

### Added
- `cloakrs sanitize` and `cloakrs restore` CLI subcommands, so the sanitizer is usable
  outside of Rust. `sanitize` writes a mapping file (mode `0600` on Unix; refuses to
  overwrite an existing mapping without `--force`) alongside the sanitized text; `restore`
  reads it back with tolerant matching by default (`--strict` to disable). Both accept a
  file path or stdin, and `--help` calls out that the mapping file contains real sensitive
  values.
- `PlaceholderStyle` (`Brackets` / `Braces`) and `PromptSanitizer::sanitize_with_style`,
  for choosing the placeholder delimiter used when sanitizing; exposed on the CLI as
  `cloakrs sanitize --placeholder-style`.
- Expanded sanitizer test coverage: a 256-case property test asserting
  `restore(sanitize(text)) == text` for randomized input, dedup/Debug-redaction/tolerant-
  matching test matrices, and Unicode, empty-input, PII-only-input, and overlapping-finding
  edge cases.

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
