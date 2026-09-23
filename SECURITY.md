# Security

## Reporting a vulnerability

Email the maintainer at [kadircaneksi@gmail.com](mailto:kadircaneksi@gmail.com)
with the affected version, reproduction steps using synthetic data, and the
potential impact. Do not put live secrets or customer records in a public issue.
GitHub private vulnerability reporting is not currently enabled for this repository.

Fixes are developed against the latest release. Older releases do not have a
separate maintenance branch. This project has not undergone an independent
security audit; the tests and review described here are a maintained baseline.

## Detection and data handling

Bundled recognizers scan locally. Installation and dependency downloads require
network access. Detection is based on patterns, validators, context, and limited
name dictionaries. It can miss unsupported languages, obfuscated/encoded values,
unknown identifier formats, or values below the confidence threshold. False
positives can also change otherwise harmless text. See the
[labeled evaluation and known gaps](docs/evaluation.md).

A sanitized result is not a guarantee that arbitrary input contains no secrets.
Check representative data for your application, choose the correct locale, and
review output before sending high-impact information outside your trust boundary.
Partial masking deliberately reveals some characters. Hashing is deterministic,
uses SHA256 with an optional salt, and is not password hashing or protection
against guessing low-entropy identifiers.

`PiiEntity`, scan reports, and serialized prompt mappings can contain original
values. Mapping `Debug` output hides originals, and `MaskStrategy` debug output
hides encryption keys and hash salts, but serialization intentionally retains
them. Treat these objects and files as secrets. CLI mapping/restored-output files
use mode `0600` on Unix; Windows protection depends on the parent directory ACLs.
The library does not promise memory zeroization or protection against access to
the process, crash dumps, backups, or an already-compromised machine.

## Encryption

`MaskStrategy::Encrypt` uses AES-256-GCM with a 32-byte key supplied as 64 hex
characters. Generate keys with a cryptographically secure random generator;
do not use a password, example key, or a key committed to source control.
The CLI does not currently expose encryption key management.

Version 0.3.2 uses a fresh 96-bit OS-random nonce for every encrypted
finding. OS randomness failure returns an error through `try_replacement` and the
scanner. The convenience `replacement` method falls back to a redaction tag on
any error. Nonces are random, not a guarantee of uniqueness. Rotate keys well
before 2^32 encryptions across all processes sharing a key; the library does not
count usage or rotate keys. See [RustCrypto's AEAD nonce guidance](https://docs.rs/aead/0.5.2/aead/trait.AeadCore.html#method.generate_nonce).

The format remains `ENC[base64(nonce || ciphertext || authentication_tag)]`.
Existing values still decrypt, and authentication rejects tampered ciphertext.
There is no associated-data binding to the field, entity type, or source document:
the format does not prevent moving a valid encrypted value between records.
Applications needing that binding must provide it at a higher layer.

Version 0.3.1 and earlier derived a public deterministic nonce from the plaintext
and finding metadata. This leaks repeatability and can support offline guessing
of low-entropy values when that metadata is known. Updating the library only
changes newly encrypted values; re-encrypt stored values where this matters.
Older ciphertext and copies remain exposed to that earlier design. Earlier
`MaskStrategy` debug output also included keys and salts: if those were logged,
remove/restrict those logs and rotate affected keys.

## Dependencies and releases

CI and release verification run `cargo audit`, alongside the scheduled audit.
Checksums accompany release binaries, but releases do not yet have independent
signatures or provenance attestations. See [installation](docs/installation.md).

On 2026-09-23, `cargo audit` reported no known vulnerabilities in the checked-in
lockfile and one maintenance warning: `number_prefix` 0.4.0, pulled in by
`indicatif` 0.17.11 ([RUSTSEC-2025-0119](https://rustsec.org/advisories/RUSTSEC-2025-0119.html)).
This warning is not suppressed; replacing that dependency must preserve Rust 1.75
support and verify CLI progress output. Audit results are time-dependent and
do not establish that dependencies are free of vulnerabilities.
