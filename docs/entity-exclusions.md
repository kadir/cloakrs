# Entity exclusions

Available in the development version for the next release. Version 0.3.2 does
not have this option. Exclusions let an application preserve selected entity
types while continuing to detect other supported types. All recognizers remain
enabled by default for the selected locale.

## CLI and configuration

For an input where URLs, hostnames, and user paths should remain visible:

```sh
cloakrs --exclude-entities url,hostname,user-path stream
```

The option works with `scan`, `stream`, `audit`, `pre-commit`, and `sanitize`.
It accepts comma-separated names.
`restore` uses the saved mapping and does not rescan input or apply exclusions.

The same settings can be stored in `.cloakrs.toml`:

```toml
exclude_entities = ["url"]

[scanner]
exclude_entities = ["hostname", "user-path"]
```

Configuration rules:

- CLI, top-level TOML, and `[scanner]` exclusions are combined as a set.
- Duplicate names have no additional effect. A CLI list adds to the config;
  it does not replace it. An empty TOML list does not clear exclusions elsewhere.
- To re-enable a type, remove it from every active exclusion list. `--config`
  selects a specific file instead of automatic `.cloakrs.toml` discovery.
- Unknown entity names fail with exit code `2` before scanning. This also applies
  to empty audit directories and empty pre-commit input lists.
- Exclusions filter recognizer-produced findings before overlap resolution,
  reporting, and masking. They do not disable the recognizers themselves.
- Literal deny-list findings still apply even when the detected type is excluded.
  Existing allow-list precedence is preserved: an overlapping allowed literal
  suppresses findings, including deny-list findings.

Canonical names are listed in [supported entities](supported-entities.md#entity-selection).
The sample `.cloakrs.example.toml` leaves exclusions commented out, so copying
the file does not disable URL, hostname, or user-path detection.

## Sanitization and restoration

```sh
cloakrs sanitize prompt.txt --mapping mapping.json --output clean.txt \
  --locale us --exclude-entities url,hostname,user-path
cloakrs restore clean.txt --mapping mapping.json --output restored.txt
```

For this synthetic input:

```text
Open https://example.com?email=jane%40example.com&ssn=123-45-6789
```

The sanitized text is:

```text
Open https://example.com?email=[EMAIL_1]&ssn=[SSN_1]
```

Restoration recovers the exact original, including `%40`. Repeated identical
encoded values share a placeholder. Placeholders are text intended for model
input; sanitized URLs are not guaranteed to be valid request URLs. Keep the
mapping private because it contains original values.

## Rust

```rust
use cloakrs_core::{EntityType, Locale};

let scanner = cloakrs_locales::default_registry()
    .into_scanner_builder()
    .locale(Locale::US)
    .exclude_entities([EntityType::Url, EntityType::Hostname, EntityType::UserPath])
    .build()?;
let result = scanner.scan("https://example.com?email=jane%40example.com")?;
assert_eq!(result.masked_text.as_deref(), Some("https://example.com?email=[EMAIL]"));
# Ok::<(), cloakrs_core::CloakError>(())
```

Builder calls are additive and also accept `EntityType::Custom(name)`. Literal
deny-list findings are added after exclusions and remain active. Excluding one
type does not exclude independently detected types inside the same span.

## URL credential limits

Excluding `url` removes the protection of masking the whole URL. Current nested
query scanning recognizes email addresses and US SSNs (with the US locale),
including percent-encoded forms. Other recognizers may detect some credentials,
but URL contents are not comprehensively scanned after decoding.

For example, `https://alice:supersecret@example.com/private` and an API key whose
characters are all percent-encoded can remain visible with URLs excluded.
This behavior is documented and covered by regression tests. Keep URL detection
enabled when those values must be masked. This feature does not provide a safe
LLM-proxy preset or a guarantee that excluded containers contain no secrets.
