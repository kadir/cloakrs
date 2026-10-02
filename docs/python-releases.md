# Python releases

The Python package has its own version, tags, and release workflow. Publishing
it does not publish Rust crates or trigger the native CLI release workflow.

## One-time account setup

On PyPI, verify the maintainer account's email and enable two-factor
authentication. Add a pending GitHub Trusted Publisher under account publishing:

| Field | Value |
| --- | --- |
| Project | `cloakrs` |
| Repository owner | `kadir` |
| Repository | `cloakrs` |
| Workflow filename | `python-release.yml` |
| Environment | `pypi` |

Create the matching `pypi` GitHub environment. If deployment branch/tag rules
are enabled on that environment, allow Python release tags matching `python-v*`.
No PyPI password or long-lived API token is needed in GitHub secrets.
The first successful upload creates the project and activates the pending
publisher. Pending publishers do not reserve project names.

## Prepare and validate

1. Update `bindings/python/Cargo.toml` and its Cargo.lock package entry. Maturin
   converts Cargo prerelease versions such as `0.1.0-alpha.1` to Python `0.1.0a1`.
   Update the Python README's install commands, changelog, and version assertion
   in `bindings/python/tests/test_scanner.py`.
2. Push the change and require green Python binding and Python release checks.
   The release workflow runs on relevant branch pushes and pull requests. A
   manual workflow run on `master` also validates without publishing.
3. Merge the tested changes to `master`. Release tags must reference commits
   already included in `master`; the workflow rejects other commits.

The package validation workflow builds five native wheels: manylinux2014
x86_64/ARM64, macOS 11 Intel/Apple Silicon, and Windows x86_64. It installs each
wheel offline into a fresh Python environment with no runtime dependencies,
then exercises detection, masking, restoration, Unicode offsets, and threading.
The full regression suite, including Rust CLI mapping exchange, runs against
the wheels on CPython 3.11 and 3.14 on all five targets. The binding workflow
also checks Python 3.12/3.13 and the Rust 1.83 minimum.

The source archive includes local Rust dependencies and the binding lockfile.
It is rebuilt through pip outside the checkout on Linux, macOS, and Windows,
then installed and smoke-tested. Maturin uses locked Cargo dependencies for
source builds too. The final artifact check requires exactly five correctly
tagged wheels and one source archive, matching package metadata, type hints,
licenses, and required Rust source files. Twine checks the package descriptions.
The `python-release` workflow artifact contains precisely the validated files.

Local packaging checks (using the development environment from the binding README):

```sh
maturin sdist --manifest-path bindings/python/Cargo.toml --out /tmp/cloakrs-sdist
python bindings/python/release.py source /tmp/cloakrs-sdist
python bindings/python/release.py install bindings/python/dist
```

## Publish

For this corrective prerelease, tag the tested, merged commit:

```sh
git tag -a python-v0.1.0a2 -m 'Python 0.1.0a2'
git push origin python-v0.1.0a2
```

The tag must match the normalized package version. Never move a published tag
or attempt to replace files for an existing PyPI version. Publish a new version
for corrections.

The tag workflow rebuilds and validates the release packages, runs the existing
Rust CI and Python binding checks, and uploads the validated artifact through
`pypa/gh-action-pypi-publish`. Only the publishing job has `id-token: write`; it
uses the `pypi` environment. Build jobs do not receive publishing credentials.

Require every `PyPI install` job to pass before announcing the release. These
jobs download the exact version from PyPI using `--only-binary=:all:` and test
clean installs on all five targets with CPython 3.11 and 3.14. If environment
protection rules pause a run, complete the configured GitHub review. If Trusted
Publishing rejects it, check the repository, workflow filename, and environment
against the PyPI publisher; do not substitute a shared account token.
