# Benchmarking

Criterion benchmarks live in `benches/scan_benchmark.rs`; the publishable Cargo
bench target is mirrored under `crates/cloakrs-cli/benches/scan_benchmark.rs`.

Run the full benchmark suite:

```bash
cargo bench -p cloakrs-cli --bench scan_benchmark
```

Run a short CI-style smoke benchmark:

```bash
cargo bench -p cloakrs-cli --bench scan_benchmark -- --sample-size 10
```

The benchmark suite covers:

- Plain text, JSON, and CSV scans at 1KB, 10KB, 100KB, 1MB, and 10MB.
- Individual recognizers.
- Redact, partial mask, hash, replace, and encrypt masking strategies.

Before publishing performance claims, run equivalent Presidio and DataFog scans
on the same machine and update the README table with those local measurements.
