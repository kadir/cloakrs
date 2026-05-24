# CI/CD Integration

`cloakrs` can run as a local CLI, in pull-request checks, or in release gates.
The CLI exits with code `1` when findings are detected and `0` when no findings
are found.

## GitHub Actions

```yaml
name: PII scan

on:
  pull_request:

jobs:
  cloakrs:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo install cloakrs-cli
      - run: cloakrs audit . --output-format sarif --output cloakrs.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: cloakrs.sarif
```

## Local Pre-Commit Scan

```bash
cargo run -p cloakrs-cli -- audit . --severity medium --output-format text
```

Use `--quiet` when you want masked output without a human summary.

## pre-commit Framework

Add cloakrs as a pre-commit hook:

```yaml
repos:
  - repo: https://github.com/kadir/cloakrs
    rev: v0.3.0
    hooks:
      - id: cloakrs-scan
        args: ["--min-confidence", "0.8", "--locale", "eu"]
```

The hook expects the `cloakrs` binary on `PATH`, for example from
`cargo install cloakrs-cli --locked`. The repository is a Cargo workspace, so
the hook does not ask pre-commit to build from the workspace root.

Repository-level literal allow/deny lists can live in `.cloakrs.toml`:

```toml
allow_list = ["John Smith LLC"]
deny_list = ["PRJ-12345"]
```

Structured audit logs are JSON Lines:

```bash
cloakrs audit . --audit-log cloakrs-audit.jsonl
```

Audit log entries contain finding metadata, offsets, confidence, and recognizer
IDs; they intentionally do not include raw matched PII.

## File Scans

```bash
cloakrs scan ./fixtures/users.csv --format csv --columns email,phone
cloakrs scan ./app.log --format log --output masked.log
cloakrs scan ./dump.sql --format sql --output masked.sql
```

## SARIF Output

SARIF output is intended for CI systems and code scanning tools:

```bash
cloakrs audit . --output-format sarif --output cloakrs.sarif
```

## Exit Codes

- `0`: scan completed and no findings met the configured threshold.
- `1`: scan completed and one or more findings were reported.
- `2`: command-line or runtime error.
