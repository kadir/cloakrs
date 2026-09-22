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
```

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
git tag v0.3.1
git push origin v0.3.1
```

The release workflow builds binaries and publishes SHA256 checksums.

Before tagging, require green CI on Linux, macOS, and Windows, including Rust 1.75.
Set the changelog release date, commit the release changes, and verify that the tag
points to the exact tested commit. Do not infer cross-platform readiness from a
single local test run. Keep the contributor's entity-exclusions PR separate until
its review is resolved.
