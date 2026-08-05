#!/bin/sh
set -eu

repo="${ENVAULT_REPOSITORY:-Thanhbinh1905/envault}"
api_url="https://api.github.com/repos/$repo/releases/latest"

info() {
  printf '%s\n' "==> $1"
}

ok() {
  printf '%s\n' "    ✓ $1"
}

fail() {
  printf '%s\n' "error: $1" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

case "$(uname -s):$(uname -m)" in
  Linux:x86_64) architecture="x86_64" ;;
  *)
    fail "EnVault Desktop release packages currently support Linux x86_64 only"
    ;;
esac

require_command apt-get
require_command curl
require_command mktemp
require_command sha256sum

install_package() {
  if [ "$(id -u)" -ne 0 ]; then
    require_command sudo
    sudo apt-get install -y "$1"
  else
    apt-get install -y "$1"
  fi
}

work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' EXIT HUP INT TERM

info "Fetching the latest EnVault Desktop release"
release_json="$work_dir/release.json"
curl -fsSL "$api_url" -o "$release_json" || fail "could not fetch release metadata"

asset_url=$(sed -nE 's/.*"browser_download_url": "([^"]*envault-desktop-v[^"/]*-'"$architecture"'\.deb)".*/\1/p' "$release_json" | head -n 1)
if [ -z "$asset_url" ]; then
  fail "the latest release does not contain an EnVault Desktop .deb package"
fi

checksum_url="${asset_url}.sha256"
package="$work_dir/$(basename "$asset_url")"
checksum="$work_dir/$(basename "$checksum_url")"

info "Downloading $(basename "$asset_url")"
curl -fsSL "$asset_url" -o "$package" || fail "could not download the desktop package"
curl -fsSL "$checksum_url" -o "$checksum" || fail "could not download the desktop checksum"

info "Verifying the desktop package"
(cd "$work_dir" && sha256sum -c "$(basename "$checksum")") || fail "SHA-256 verification failed"
ok "SHA-256 verified"

info "Installing EnVault Desktop"
install_package "$package" || fail "could not install the desktop package"
ok "EnVault Desktop is installed"

printf '\n%s\n' 'Open EnVault from your application menu.'
printf '%s\n' 'The desktop package includes a fallback daemon and does not install the EnVault CLI.'
