# Installation

## Cargo

Install the CLI with Rust/Cargo:

```sh
cargo install cloakrs-cli --locked
cloakrs --version
```

To reproduce the current published version, add `--version 0.3.2`. The workspace
supports Rust 1.75 and newer; use `--locked` to use the tested dependency versions.

## Linux and macOS binaries

Download the installer, inspect it, then run it:

```sh
curl -fsSL https://raw.githubusercontent.com/kadir/cloakrs/master/install.sh -o install-cloakrs.sh
less install-cloakrs.sh
sh install-cloakrs.sh
export PATH="$HOME/.local/bin:$PATH"
cloakrs --version
```

From a repository checkout, use `sh install.sh`. No Rust compiler or root access
is required. The installer needs `curl`, `tar`, `awk`, `mktemp`, and either
`sha256sum` or `shasum`, plus ordinary POSIX utilities.

| Operating system | CPU | Selected release target | Requirement |
| --- | --- | --- | --- |
| Linux | x86_64 | `x86_64-unknown-linux-musl` | Static musl binary |
| Linux | ARM64 | `aarch64-unknown-linux-gnu` | Compatible glibc; Alpine ARM64 is not supported by this binary |
| macOS | Intel | `x86_64-apple-darwin` | Compatible macOS version |
| macOS | Apple Silicon | `aarch64-apple-darwin` | Compatible macOS version |

The installer runs the downloaded binary's `--version` before replacing the
existing installation. If it cannot run on your system, use Cargo to build locally.
macOS binaries are not currently signed/notarized; the installer does not bypass
operating-system security controls.

Pin a version and choose the installation directory:

```sh
CLOAKRS_VERSION=v0.3.2 CLOAKRS_INSTALL_DIR="$HOME/bin" sh install-cloakrs.sh
```

`CLOAKRS_VERSION` accepts `latest`, `v0.3.2`, or `0.3.2`. For `latest`, the
installer reads `SHA256SUMS.txt` and downloads the archive from the specific tag
named there. It verifies that archive's SHA256, checks its contents and binary
version, then atomically replaces the destination. A failed download or checksum
check preserves the existing binary. Rerun to upgrade; remove the installed
`cloakrs` file to uninstall.

`CLOAKRS_REPO=owner/name` selects another GitHub repository, such as a trusted fork.
It changes the source of both checksums and executable code. Leave it unset for
official releases. Checksums detect corruption or mismatched assets; they are not
independent signatures and cannot protect against a compromised release account.

## Windows

Install via Cargo as above, or download the Windows x86_64 ZIP and
`SHA256SUMS.txt` from the same [release](https://github.com/kadir/cloakrs/releases).
For example, after downloading both v0.3.2 files into the current directory:

```powershell
$archive = 'cloakrs-v0.3.2-x86_64-pc-windows-msvc.zip'
$entries = @(Get-Content .\SHA256SUMS.txt | Where-Object { ($_ -split '\s+')[1] -eq $archive })
if ($entries.Count -ne 1) { throw 'Expected one checksum for the archive' }
$expected = ($entries[0] -split '\s+')[0]
if ($expected -notmatch '^[0-9a-fA-F]{64}$') { throw 'Invalid SHA256 checksum' }
if ((Get-FileHash $archive -Algorithm SHA256).Hash -ne $expected) { throw 'Checksum mismatch' }
Expand-Archive $archive -DestinationPath .\cloakrs-install
.\cloakrs-install\cloakrs.exe --version
```

Move `cloakrs.exe` to a directory on your user `PATH`. These binaries target
Windows x86_64; the shell installer is for Linux/macOS only.
