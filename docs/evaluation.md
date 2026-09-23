# Detection evaluation

The versioned [corpus](../tests/evaluation/corpus.json) contains 58 manually
labeled synthetic snippets, with 44 expected findings across 26 entity types.
Sixteen snippets have no expected findings. Scenarios include prompts, logs,
URLs, JSON/CSV/SQL text, and locale identifiers, plus five deliberate coverage
challenges. Values are fictional or public test identifiers drawn from existing
tests/documentation; no customer records were collected.

This is a small regression corpus, not a held-out dataset or a representative
measure of production accuracy. Some values already appear in recognizer tests.
One positive example per type is especially weak evidence of general coverage.
The existing 10,000 generated clean-log test is a separate false-positive smoke
test; its line count does not make it an independent real-world evaluation.

## Reproduce

Use Rust and Python 3 from the repository root; Python needs no third-party packages:

```sh
python3 -m unittest discover -s tests/evaluation -v
cargo build --release --locked -p cloakrs-cli --example evaluate
python3 tests/evaluation/run.py --binary target/release/examples/evaluate
```

On Windows use `python` and `target/release/examples/evaluate.exe`. The command
writes `target/evaluation-report.json` with overall and per-entity/category
precision, recall, F1, counts, and every extra/missing typed span. It omits source
text and raw matched values from the report. The corpus itself contains the
synthetic inputs and labels.

The scanner uses the bundled locale registry, each case's specified locale, a
fixed minimum confidence of `0.5` (matching the CLI default), and no masking.
Expected labels describe desired detection, including unsupported challenge
cases. They were written before collecting the initial predictions and are not
replaced with scanner output to improve the score.

This measures the text scanner. JSON, CSV, and SQL snippets are passed as raw
text; adapter parsing, structure-preserving output, restoration, and CLI exit
codes have their own tests. In particular, an escaped JSON value missed here
does not imply that the JSON adapter misses the decoded value.

## Scoring and initial baseline

A true positive requires the same entity type and exact half-open UTF-8 byte
span. A wrong boundary/type counts as one false positive and one false negative.
Nested URL/email findings count separately because both appear in scan reports.
Duplicate predictions count as extra findings. Micro precision is
`TP / (TP + FP)` and recall is `TP / (TP + FN)`; undefined metrics are JSON `null`.
Negative-case false-positive rate is the fraction of clean snippets with any
finding, which is different from per-finding precision.

The initial baseline has **38 true positives, 1 false positive, and 6 false
negatives**: precision **97.44%**, recall **86.36%**, F1 **91.57%** on this corpus
only. None of the 16 negative cases was flagged. These are regression results,
not advertised product accuracy.

| Category | True positives | False positives | False negatives |
| --- | ---: | ---: | ---: |
| Prompt | 11 | 0 | 0 |
| Log | 10 | 0 | 0 |
| URL | 5 | 0 | 0 |
| Structured text | 2 | 1 | 1 |
| Locale | 10 | 0 | 0 |
| Negative | 0 | 0 | 0 |
| Challenge | 0 | 0 | 5 |

Known gaps retained in this baseline:

- `sql-email`: the raw-text email recognizer includes the opening SQL quote.
  This boundary error contributes both an extra and a missing finding.
- `challenge-obfuscated-email`: `[at]` / `[dot]` obfuscation is not detected.
- `challenge-unicode-name`: the limited dictionary misses the labeled Polish name.
- `challenge-dutch-address`: the address recognizer handles US-style addresses.
- `challenge-json-escaped-email`: the raw scanner does not decode JSON escapes.
- `challenge-unlabeled-bsn`: an ambiguous BSN without context falls below `0.5`.

## Reviewing detection changes

CI compares every case's predicted type/span multiset with
[baseline.json](../tests/evaluation/baseline.json) on all supported OS/toolchain
jobs. It also checks a SHA256 of canonical corpus JSON, independent of checkout
line endings. A changed corpus or changed detection result fails the gate, even
if aggregate scores happen to stay the same. Timing is excluded from that gate.

For an intentional change, first inspect the report's extra/missing spans and
the affected inputs. Then explicitly regenerate and review the snapshot:

```sh
python3 tests/evaluation/run.py --binary target/release/examples/evaluate --update-baseline
git diff -- tests/evaluation/corpus.json tests/evaluation/baseline.json
```

Rebuild the example after Rust changes. Keep labels independent of predictions;
explain corrections to labels in review. This gate preserves reviewed behavior,
including known misses. It does not turn those misses into correct detections.
New coverage should add varied independent examples and clean near-misses; a
larger, consented, held-out evaluation is still needed before accuracy claims.

## Latency and memory

The same report records scanner construction plus the first full corpus pass,
then p50/p95 wall-clock scan latency across 20 additional passes (1,160 samples).
Warm samples exclude scanner construction, output serialization, and process
startup. They measure short snippets, not large-document throughput.

On Linux/macOS, Python records the prebuilt evaluator child process's peak RSS
using `getrusage`, normalized to bytes. This includes initialization, the corpus,
all locale scanners, and report buffers; it is not an isolated scanner allocation
measurement. Windows reports `null` for peak RSS. Build before running the script
so compiler memory is excluded.

Reports include OS/architecture and the binary SHA256. Preserve the source
commit, build profile, Rust version, CPU model, and machine conditions alongside
any result you share. Use release builds and idle, identical hardware for
comparisons. CI uses debug builds to check predictions, so its timing values are
not performance claims. The [Criterion suite](benchmarking.md) covers larger
inputs and masking separately.
