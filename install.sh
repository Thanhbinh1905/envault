#!/bin/sh
set -eu

repo="${ENVAULT_REPOSITORY:-Thanhbinh1905/envault}"
install_dir="${ENVAULT_INSTALL_DIR:-$HOME/.local/bin}"
api_url="https://api.github.com/repos/$repo/releases/latest"

os=$(uname -s)
arch=$(uname -m)
case "$os:$arch" in
  Linux:x86_64) target="x86_64-unknown-linux-gnu" ;;
  Darwin:x86_64) target="x86_64-apple-darwin" ;;
  Darwin:arm64|Darwin:aarch64) target="aarch64-apple-darwin" ;;
  *)
    printf '%s\n' "error: unsupported platform $os/$arch" >&2
    printf '%s\n' 'help: download a supported archive from https://github.com/Thanhbinh1905/envault/releases' >&2
    exit 2
    ;;
esac

require_command() {
  command -v "$1" >/dev/null 2>&1 || {
    printf '%s\n' "error: required command not found: $1" >&2
    exit 1
  }
}

require_command curl
require_command tar
require_command mktemp
require_command install

if command -v sha256sum >/dev/null 2>&1; then
  checksum_tool=sha256sum
elif command -v shasum >/dev/null 2>&1; then
  checksum_tool=shasum
else
  printf '%s\n' 'error: sha256sum or shasum is required to verify the release' >&2
  exit 1
fi

work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' EXIT HUP INT TERM

release_json="$work_dir/release.json"
curl -fsSL "$api_url" -o "$release_json"
asset_url=$(sed -nE 's/.*"browser_download_url": "([^"]*envault-v[^"/]*-'"$target"'\.tar\.gz)".*/\1/p' "$release_json" | head -n 1)
checksums_url=$(sed -nE 's/.*"browser_download_url": "([^"]*SHA256SUMS)".*/\1/p' "$release_json" | head -n 1)

if [ -z "$asset_url" ] || [ -z "$checksums_url" ]; then
  printf '%s\n' "error: no release asset is available for $target" >&2
  exit 1
fi

archive="$work_dir/$(basename "$asset_url")"
checksums="$work_dir/SHA256SUMS"
curl -fsSL "$asset_url" -o "$archive"
curl -fsSL "$checksums_url" -o "$checksums"

archive_name=$(basename "$archive")
if [ "$checksum_tool" = sha256sum ]; then
  expected=$(awk -v file="$archive_name" '$2 == file {print $1; exit}' "$checksums")
  printf '%s  %s\n' "$expected" "$archive" | sha256sum -c - >/dev/null
else
  expected=$(awk -v file="$archive_name" '$2 == file {print $1; exit}' "$checksums")
  actual=$(shasum -a 256 "$archive" | awk '{print $1}')
  [ -n "$expected" ] && [ "$expected" = "$actual" ] || {
    printf '%s\n' "error: SHA-256 verification failed for $archive_name" >&2
    exit 1
  }
fi

tar -xzf "$archive" -C "$work_dir"
bundle=$(find "$work_dir" -mindepth 1 -maxdepth 1 -type d -name 'envault-v*-*' | head -n 1)
if [ -z "$bundle" ]; then
  printf '%s\n' 'error: release archive has an unexpected layout' >&2
  exit 1
fi

mkdir -p "$install_dir"
install -m 0755 "$bundle/envault" "$install_dir/envault"
install -m 0755 "$bundle/envaultd" "$install_dir/envaultd"
install -m 0755 "$bundle/envault-tui" "$install_dir/envault-tui"

printf '%s\n' "installed EnVault ($target) into $install_dir"
printf '%s\n' 'next: run envault init, then envault start'
