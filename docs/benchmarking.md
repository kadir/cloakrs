# Benchmarking

Criterion benchmarks live in `benches/scan_benchmark.rs`; the publishable Cargo
bench target is mirrored under `crates/cloakrs-cli/benches/scan_benchmark.rs`.

Run the full benchmark suite:

```bash
cargo bench -p cloakrs-cli --bench scan_benchmark
```

Run a short CI-style smoke benchmark (executes each case once without statistics):

```bash
cargo bench --locked -p cloakrs-cli --bench scan_benchmark -- --test
```

The benchmark suite covers:

- Plain text, JSON, and CSV scans at 1KB, 10KB, 100KB, 1MB, and 10MB.
- Individual recognizers.
- Redact, partial mask, hash, replace, and encrypt masking strategies.

Before publishing performance claims, run equivalent Presidio and DataFog scans
on the same machine and update the README table with those local measurements.

For labeled detection results, per-case warm latency, and peak process memory,
see [the evaluation guide](evaluation.md). The Criterion size benchmarks and the
small synthetic correctness corpus answer different questions; neither establishes
accuracy on customer data or a speed advantage over another tool.
