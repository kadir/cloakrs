#!/usr/bin/env sh
set -eu

REPO="${CLOAKRS_REPO:-kadir/cloakrs}"
VERSION="${CLOAKRS_VERSION:-latest}"
INSTALL_DIR="${CLOAKRS_INSTALL_DIR:-$HOME/.local/bin}"

uname_s="$(uname -s)"
uname_m="$(uname -m)"

case "$uname_s:$uname_m" in
  Linux:x86_64) asset="linux-x86_64"; ext="tar.gz" ;;
  Linux:aarch64|Linux:arm64) asset="linux-aarch64"; ext="tar.gz" ;;
  Darwin:x86_64) asset="macos-x86_64"; ext="tar.gz" ;;
  Darwin:arm64) asset="macos-aarch64"; ext="tar.gz" ;;
  *)
    echo "unsupported platform: $uname_s $uname_m" >&2
    exit 1
    ;;
esac

base="https://github.com/$REPO/releases"
if [ "$VERSION" = "latest" ]; then
  url="$base/latest/download/cloakrs-$asset.$ext"
  checksum_url="$base/latest/download/cloakrs-$asset.sha256"
else
  url="$base/download/$VERSION/cloakrs-$asset.$ext"
  checksum_url="$base/download/$VERSION/cloakrs-$asset.sha256"
fi

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

archive="$tmp_dir/cloakrs-$asset.$ext"
checksum="$tmp_dir/cloakrs-$asset.sha256"

curl -fsSL "$url" -o "$archive"
curl -fsSL "$checksum_url" -o "$checksum"

(
  cd "$tmp_dir"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum -c "$checksum"
  else
    shasum -a 256 -c "$checksum"
  fi
  tar -xzf "$archive"
)

mkdir -p "$INSTALL_DIR"
cp "$tmp_dir/cloakrs" "$INSTALL_DIR/cloakrs"
chmod +x "$INSTALL_DIR/cloakrs"

echo "installed cloakrs to $INSTALL_DIR/cloakrs"
