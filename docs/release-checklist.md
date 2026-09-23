# Release Checklist

Use this checklist before publishing a new `cloakrs` release.

## Verification

```bash
cargo fmt --all -- --check
cargo build --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo +1.75.0 test --workspace --locked
cargo doc --workspace --locked --no-deps
cargo bench --locked -p cloakrs-cli --bench scan_benchmark -- --test
python3 -m unittest discover -s tests/installer -v
python3 -m unittest discover -s tests/evaluation -v
cargo build --release --locked -p cloakrs-cli --example evaluate
python3 tests/evaluation/run.py --binary target/release/examples/evaluate
cargo audit
```

Review `target/evaluation-report.json`, including missed and extra findings.
If predictions change, review the detection change before explicitly updating
`tests/evaluation/baseline.json`; see [evaluation](evaluation.md). Inspect audit
warnings as well as failures. The current `number_prefix` maintenance warning is
documented in [SECURITY.md](../SECURITY.md).

After the release assets are published, smoke-test both latest and pinned
installation into a temporary directory on each supported platform. Confirm
`cloakrs --version`, a simple scan, checksum failure handling, and Windows ZIP
installation. Offline fixtures do not prove that real cross-built binaries run.
The release workflow runs these published-asset checks on native runners for
all six release targets; require every `Published install` job to succeed before
announcing the release.

## Publish Dry-Run

Run in dependency order:

```bash
cargo publish -p cloakrs-core --dry-run
cargo publish -p cloakrs-patterns --dry-run
cargo publish -p cloakrs-locales --dry-run
cargo publish -p cloakrs-adapters --dry-run
cargo publish -p cloakrs-tracing --dry-run
cargo publish -p cloakrs-cli --dry-run
```

Before publishing a new coordinated workspace version, only `cloakrs-core` can fully verify against
crates.io because the downstream crates depend on unpublished `cloakrs-*`
packages. After each crate is published, rerun the next dry-run in the order
above.

## Tag Release

```bash
git tag vX.Y.Z
git push origin vX.Y.Z
```

Replace `X.Y.Z` with the new workspace version; never move an existing release tag.

The release workflow builds binaries and publishes SHA256 checksums.

Before tagging, require green CI on Linux, macOS, and Windows, including Rust 1.75.
Set the changelog release date, commit the release changes, and verify that the tag
points to the exact tested commit. Do not infer cross-platform readiness from a
single local test run. Keep the contributor's entity-exclusions PR separate until
its review is resolved.
