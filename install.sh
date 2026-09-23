#!/usr/bin/env sh
set -eu

REPO="${CLOAKRS_REPO:-kadir/cloakrs}"
VERSION="${CLOAKRS_VERSION:-latest}"
INSTALL_DIR="${CLOAKRS_INSTALL_DIR:-$HOME/.local/bin}"

fail() { echo "cloakrs installer: $*" >&2; exit 1; }
case "$REPO" in
  *[!A-Za-z0-9_./-]*|/*|*/|*/*/*|*..*) fail "invalid repository: $REPO" ;;
  */*) ;;
  *) fail "repository must be owner/name" ;;
esac
case "$VERSION" in
  latest) ;;
  [0-9]*) VERSION="v$VERSION" ;;
esac
case "$VERSION" in
  *[!A-Za-z0-9._-]*) fail "invalid version: $VERSION" ;;
  latest|v[0-9]*) ;;
  *) fail "version must be a release tag such as v0.3.1, or latest" ;;
esac

platform="$(uname -s):$(uname -m)"
case "$platform" in
  Linux:x86_64|Linux:amd64) target="x86_64-unknown-linux-musl" ;;
  Linux:aarch64|Linux:arm64) target="aarch64-unknown-linux-gnu" ;;
  Darwin:x86_64) target="x86_64-apple-darwin" ;;
  Darwin:arm64|Darwin:aarch64) target="aarch64-apple-darwin" ;;
  *) fail "unsupported platform $platform; see README.md for Cargo/Windows installation" ;;
esac
for command in curl tar awk mktemp; do
  command -v "$command" >/dev/null 2>&1 || fail "required command not found: $command"
done
if command -v sha256sum >/dev/null 2>&1; then
  checksum_tool=sha256sum
elif command -v shasum >/dev/null 2>&1; then
  checksum_tool=shasum
else
  fail "sha256sum or shasum is required"
fi

base="https://github.com/$REPO/releases"
if [ "$VERSION" = latest ]; then
  manifest_url="$base/latest/download/SHA256SUMS.txt"
else
  manifest_url="$base/download/$VERSION/SHA256SUMS.txt"
fi

tmp_dir="$(mktemp -d)"
staged_file=""
cleanup() {
  rm -rf "$tmp_dir"
  if [ -n "$staged_file" ]; then rm -f "$staged_file"; fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
fetch() { curl -fsSL --retry 3 --connect-timeout 15 --max-time 180 "$1" -o "$2"; }
fetch "$manifest_url" "$tmp_dir/SHA256SUMS.txt" || fail "could not download release checksums"

# Select only this platform; never run checksum verification on unrelated manifest paths.
awk -v target="$target" -v version="$VERSION" '
  NF == 2 {
    name = $2; sub(/^\*/, "", name)
    if ((version == "latest" && name ~ ("^cloakrs-v[0-9][A-Za-z0-9._-]*-" target "\\.tar\\.gz$")) ||
        name == "cloakrs-" version "-" target ".tar.gz") print $1, name
  }
' "$tmp_dir/SHA256SUMS.txt" > "$tmp_dir/selected"
[ "$(awk 'END { print NR }' "$tmp_dir/selected")" = 1 ] || fail "expected exactly one checksum for $target"
read -r checksum archive_name < "$tmp_dir/selected"
[ "${#checksum}" = 64 ] || fail "invalid SHA256 checksum"
case "$checksum" in *[!0-9a-fA-F]*) fail "invalid SHA256 checksum" ;; esac
release_tag=${archive_name#cloakrs-}
release_tag=${release_tag%-$target.tar.gz}
# Pin the archive to the tag found in the manifest, even if latest changes now.
fetch "$base/download/$release_tag/$archive_name" "$tmp_dir/$archive_name" || fail "could not download $archive_name"
printf '%s  %s\n' "$checksum" "$archive_name" > "$tmp_dir/selected.sha256"
(
  cd "$tmp_dir"
  if [ "$checksum_tool" = sha256sum ]; then sha256sum -c selected.sha256
  else shasum -a 256 -c selected.sha256
  fi
) || fail "checksum mismatch; existing installation was not changed"

[ "$(tar -tzf "$tmp_dir/$archive_name")" = cloakrs ] || fail "unexpected archive contents"
# Stream the single member into a new regular file instead of trusting archive paths/links.
tar -xOzf "$tmp_dir/$archive_name" cloakrs > "$tmp_dir/cloakrs" || fail "could not unpack binary"
chmod 755 "$tmp_dir/cloakrs"
installed_version=$("$tmp_dir/cloakrs" --version) || fail "binary cannot run on this platform (Linux ARM64 requires glibc)"
[ "$installed_version" = "cloakrs ${release_tag#v}" ] || fail "binary version does not match release tag"

mkdir -p "$INSTALL_DIR"
[ ! -d "$INSTALL_DIR/cloakrs" ] || fail "destination cloakrs is a directory"
staged_file=$(mktemp "$INSTALL_DIR/.cloakrs.XXXXXXXX")
cp "$tmp_dir/cloakrs" "$staged_file"
chmod 755 "$staged_file"
mv -f "$staged_file" "$INSTALL_DIR/cloakrs"
staged_file=""
printf 'Installed %s to %s/cloakrs\n' "$installed_version" "$INSTALL_DIR"
case ":$PATH:" in
  *":$INSTALL_DIR:"*) ;;
  *) printf 'Add %s to your PATH to run cloakrs.\n' "$INSTALL_DIR" ;;
esac
