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

