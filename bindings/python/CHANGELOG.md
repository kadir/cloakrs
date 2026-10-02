# Python changelog

## 0.1.0a2

Corrective prerelease, bundling the cloakrs 0.4.1 Rust engine source.

- Preserve paired surrounding single quotes when scanning, masking, or
  sanitizing an email, including encoded URL query values. For example,
  `VALUES ('jane@example.com')` now masks to `VALUES ('[EMAIL]')`.
- Preserve apostrophes inside email local parts and unpaired leading
  apostrophes. Raw-text paired outer quotes are treated as delimiters;
  this is a boundary heuristic, not SQL parsing.
- Add regression coverage for Unicode indices, mapping byte spans, both
  placeholder styles, and exact restoration. No public API changes.

## 0.1.0a1

First Python prerelease, powered by the cloakrs 0.4.0 Rust engine.

- Local scanning and masking with typed findings and Python string indices.
- Prompt sanitization with bracket/brace placeholders and tolerant or strict restoration.
- Explicit mapping JSON import/export interoperable with the Rust CLI.
- Locale, confidence, entity exclusion, and literal allow/deny options.
- Sensitive values omitted from mapping representations; automatic mapping pickling disabled.
- CPython 3.11–3.14 wheels for Linux x86_64/ARM64, macOS Intel/Apple Silicon,
  and Windows x86_64, plus a source distribution.
