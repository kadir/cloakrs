# Python bindings plan

Status: scanning prototype implemented, 2026-09-29. The local alpha package
provides `Scanner`, `ScanResult`, and `Finding`; see the
[binding README](../bindings/python/README.md). Sanitization, mapping, and public
distribution remain planned. No Python package has been published to PyPI.

## Goal

Let Python applications call the existing Rust detection and sanitization engine
through `import cloakrs`. On supported platforms, installing a wheel should
require only Python and pip. All input processing stays inside the application
process. Detection rules and masking behavior continue to live in Rust.

This removes an integration step for Python services, notebooks, and LLM tools.
Adoption is a hypothesis to validate with working examples and user feedback.

## First public interface

Target interface: scanning is implemented; `Sanitizer` and `Mapping` are planned.

```python
from cloakrs import Scanner, Sanitizer

scanner = Scanner(locale="us")
result = scanner.scan("Email jane@example.com")
assert result.masked_text == "Email [EMAIL]"
assert scanner.mask("Email jane@example.com") == "Email [EMAIL]"

sanitizer = Sanitizer(locale="us")
clean, mapping = sanitizer.sanitize("Email jane@example.com")
assert clean == "Email [EMAIL_1]"
assert mapping.restore("Reply to [EMAIL_1]") == "Reply to jane@example.com"
```

- `Scanner.scan(text)` returns typed results and findings.
- `Scanner.mask(text)` returns redacted text using the same Rust scanner.
- `Sanitizer.sanitize(text, placeholder_style="brackets")` returns text and an
  opaque `Mapping`; support the existing braces style too.
- `Mapping.restore(text, strict=False)` preserves Rust restoration behavior.
- Both constructors accept locale selection, confidence, exclusions, and literal
  allow/deny lists. Defaults match the Rust library. Configuration is explicit;
  Python calls do not discover a `.cloakrs.toml` from the working directory.
- Exclusion names match the CLI. Exclusions remain empty by default, with the
  existing URL credential limitations documented in Python examples as well.
- Reusable instances avoid rebuilding recognizers for each call.

Findings expose entity type, confidence, recognizer ID, and half-open `start` and
`end` indices compatible with Python string slicing. Convert Rust UTF-8 byte
offsets to Python code-point indices in the binding. Test accented characters,
emoji, combining characters, and nested encoded findings. Raw finding text is
available through explicit access; result, finding, and mapping representations
must not print sensitive values or entire input/output strings.

Mapping JSON import/export should use the existing Rust schema for CLI
interoperability. Its stored spans remain explicitly documented UTF-8 byte
offsets. Exporting the mapping exposes original values; no automatic persistence,
logging, or pickling is part of the initial interface.

## Build and package design

- Use [PyO3](https://docs.rs/pyo3/0.29.2/pyo3/) for the native binding and
  [maturin](https://www.maturin.rs/tutorial) to build Python wheels.
- Keep the binding under `bindings/python/` with its own Cargo workspace,
  lockfile, Python metadata, and CI. Depend on the existing core/locales crates;
  include local Rust dependencies in source distributions and test those builds.
- Keep the existing Rust workspace and Rust 1.75 checks independent. PyO3 0.29.2
  requires Rust 1.83 or newer; validate the binding's declared toolchain minimum
  separately. Wheel users do not need Rust installed.
- Target regular CPython 3.11 through 3.14 initially, using `abi3-py311` where
  supported. Python 3.10 reaches end of life in October 2026 according to the
  [Python version schedule](https://devguide.python.org/versions/).
- Initial wheels: Linux x86_64/ARM64, macOS Intel/Apple Silicon, Windows x86_64.
  Build portable Linux wheels and import-test each wheel on its target platform.
  Alpine/musl, Windows ARM64, free-threaded Python, and alternative interpreters
  need their own validation before being advertised as supported.
- Ship type hints and `py.typed`. Release the interpreter lock during Rust work,
  using owned inputs and testing shared-instance concurrency.
- Proposed distribution/import name: `cloakrs`. Its PyPI metadata endpoint
  returned 404 during planning; first publication still needs to establish the
  project under the maintainer's PyPI account.

## Implementation order and acceptance checks

1. **Scanning prototype:** build and install a local wheel with `Scanner`, typed
   findings, redaction, options, Python exceptions, and Unicode-correct offsets.
   Compare results against the Rust engine on the existing synthetic corpus.
2. **Sanitize and restore:** wrap the existing Rust sanitizer and mapping; test
   exact round trips, repeated values, placeholder collisions, tolerant/strict
   restoration, encoded URL values, and CLI-compatible mapping JSON. Check that
   representations and errors do not reveal input values.
3. **Distribution:** build all five platform wheels, install them in clean
   environments without a Rust compiler, and run Python tests against the
   installed artifacts. Test supported Python versions, source distribution
   builds, type hints, and concurrency; retain all Rust CI checks.
4. **Public prerelease:** document installation and two small examples (ordinary
   masking and an LLM prompt/response round trip), configure PyPI publishing,
   and validate downloads before promoting a stable Python release. Keep Python
   publishing separate from the six-crate Rust release pipeline.

Initial scope is text scanning, redaction, and prompt sanitization. Batch APIs,
DataFrame helpers, async conveniences, framework integrations, file adapters,
additional masking strategies, and Python-defined recognizers can follow based
on usage. The first deliverable is an installable local wheel with scanning and
parity tests, before introducing public release automation.
