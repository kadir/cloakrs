# Release Checklist

Use this checklist before publishing a new `cloakrs` release.

## Verification

```bash
cargo fmt --all -- --check
cargo build --workspace
cargo clippy --workspace -- -D warnings
cargo test --workspace
cargo test --doc --workspace
cargo doc --workspace --no-deps
cargo bench -p cloakrs-cli --bench scan_benchmark -- --sample-size 10
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

Before the first real release, only `cloakrs-core` can fully verify against
crates.io because the downstream crates depend on unpublished `cloakrs-*`
packages. After each crate is published, rerun the next dry-run in the order
above.

## Tag Release

```bash
git tag v0.3.0
git push origin v0.3.0
```

The release workflow builds binaries and publishes SHA256 checksums.
