# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/).

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
