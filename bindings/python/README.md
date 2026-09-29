# cloakrs for Python

Local alpha prototype: a Python interface to the cloakrs 0.4.0 Rust engine.
The package is not published on PyPI yet. Scanning and redaction are implemented;
prompt sanitization/restoration and public wheel distribution are later steps.

## Use

```python
from cloakrs import Scanner

scanner = Scanner(locale="us")
result = scanner.scan("Email jane@example.com")
assert result.masked_text == "Email [EMAIL]"

finding = result.findings[0]
assert finding.entity_type == "email"
assert finding.text == "jane@example.com"
assert scanner.mask("Email jane@example.com") == "Email [EMAIL]"
```

`Scanner` accepts keyword-only options:

| Option | Default | Meaning |
| --- | --- | --- |
| `locale` | `"universal"` | One of `universal`, `us`, `uk`, `nl`, `de`, `fr`, `in`, `br`, `eu` |
| `min_confidence` | `0.0` | Finite threshold from 0 to 1, matching the Rust library default |
| `exclude_entities` | `()` | Sequence of canonical entity names; see `cloakrs.ENTITY_TYPES` |
| `allow_list` | `()` | Literal values whose overlapping findings are suppressed |
| `deny_list` | `()` | Literal values added as `deny-list` findings |

All options are explicit; no configuration files are discovered. Duplicate
exclusions have no additional effect. Deny-list rules survive entity exclusions;
allow-list precedence still applies to deny-list findings. `passport-number` and
`drivers-license` are reserved entity names without bundled recognizers.

```python
scanner = Scanner(locale="us", exclude_entities=["url"])
assert scanner.mask("https://example.com?email=jane%40example.com") == (
    "https://example.com?email=[EMAIL]"
)
```

Excluding URLs can leave embedded credentials visible, including userinfo
passwords and unsupported encoded query secrets. Default URL detection remains
enabled. Pattern-based detection does not guarantee that arbitrary text contains
no secrets; choose a locale and check representative input for your application.

## Results and errors

`ScanResult` and `Finding` are immutable typed dataclasses. Findings include
`entity_type`, `start`, `end`, `confidence`, `recognizer_id`, and `text`.
`source[finding.start:finding.end]` selects the matched original text. Indices
count Python Unicode code points, not Rust UTF-8 bytes or visual graphemes.
Nested URL findings can overlap; use `masked_text` for Rust's redaction policy.

Representations omit original and masked text. Accessing `.text`, `.masked_text`,
or explicitly serializing a result can expose sensitive values. Masked text may
still contain unsupported or intentionally excluded values.

Unknown options and invalid confidence values raise `ValueError`; wrong argument
types raise `TypeError`. Lone Unicode surrogates are rejected with `ValueError`.
Internal scanning failures raise a generic `RuntimeError` without source values.

Reuse a scanner for repeated calls. Scanning releases the Python interpreter
lock while Rust runs, and an instance can be shared between Python threads.
`mask()` avoids allocating Python finding objects when only redacted text is needed.

## Build and test from this repository

Requires regular CPython 3.11–3.14 and Rust 1.83 or newer for building this binding.
The Rust library and CLI retain their independent Rust 1.75 minimum. A built wheel
does not require a Rust compiler or additional Python runtime dependencies.
Free-threaded Python and alternative interpreters are not validated yet.

From the repository root:

```sh
python3 -m venv .venv-python
# Linux/macOS; on Windows activate .venv-python\Scripts\Activate.ps1 instead.
. .venv-python/bin/activate
python -m pip install 'maturin>=1.15,<2' 'pytest>=8,<10' 'mypy>=1.15,<3'
cd bindings/python
maturin build --release --locked --out dist
python -m pip install --no-deps --force-reinstall dist/*.whl
python -m pytest tests
python -m mypy python/cloakrs tests/typing_smoke.py
```

In PowerShell, install the wheel with
`python -m pip install --no-deps --force-reinstall (Get-ChildItem dist/*.whl)`.
The test suite runs against the installed wheel and compares all 58 existing
evaluation cases against the Rust detection snapshot. Its corpus tests require
the repository checkout. Python binding changes have a separate CI workflow.

## PyPI setup for the maintainer

Create a [PyPI account](https://pypi.org/account/register/), verify the email
address, and enable two-factor authentication. `pip` itself has no registration.
The intended distribution and import name is `cloakrs`.

Once release artifacts are ready, configure a
[pending Trusted Publisher](https://docs.pypi.org/trusted-publishers/creating-a-project-through-oidc/)
for the dedicated Python publishing workflow. The first successful upload creates
the PyPI project; configuring a pending publisher does not reserve its name.
The current prototype workflow only builds and tests artifacts, and does not upload
packages to PyPI. Public releases will follow platform wheel and source-package
validation and the sanitizer milestone.
