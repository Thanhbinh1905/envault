#!/bin/sh
set -eu

repo="${ENVAULT_REPOSITORY:-Thanhbinh1905/envault}"
install_dir="${ENVAULT_INSTALL_DIR:-$HOME/.local/bin}"
api_url="https://api.github.com/repos/$repo/releases/latest"

info() {
  printf '%s\n' "==> $1"
}

ok() {
  printf '%s\n' "    ✓ $1"
}

warn() {
  printf '%s\n' "    warning: $1" >&2
}

fail() {
  printf '%s\n' "error: $1" >&2
  exit 1
}

os=$(uname -s)
arch=$(uname -m)
info "Detecting platform"
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
ok "$os/$arch -> $target"

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
info "Preparing a temporary download directory"
ok "$work_dir"

release_json="$work_dir/release.json"
info "Fetching the latest release metadata"
curl -fsSL "$api_url" -o "$release_json" || fail "could not fetch release metadata"
release_tag=$(sed -nE 's/.*"tag_name": "([^"]+)".*/\1/p' "$release_json" | head -n 1)
if [ -z "$release_tag" ]; then
  fail "release metadata did not contain a tag"
fi
ok "Found release $release_tag"

asset_url=$(sed -nE 's/.*"browser_download_url": "([^"]*envault-v[^"/]*-'"$target"'\.tar\.gz)".*/\1/p' "$release_json" | head -n 1)
checksums_url=$(sed -nE 's/.*"browser_download_url": "([^"]*SHA256SUMS)".*/\1/p' "$release_json" | head -n 1)

if [ -z "$asset_url" ] || [ -z "$checksums_url" ]; then
  fail "no release asset is available for $target"
fi

archive="$work_dir/$(basename "$asset_url")"
checksums="$work_dir/SHA256SUMS"
archive_name=$(basename "$archive")
info "Downloading $archive_name"
curl -fsSL "$asset_url" -o "$archive" || fail "could not download $archive_name"
ok "Downloaded $archive_name"

info "Downloading SHA-256 manifest"
curl -fsSL "$checksums_url" -o "$checksums" || fail "could not download SHA256SUMS"
ok "Downloaded SHA256SUMS"

info "Verifying the archive checksum"
expected=$(awk -v file="$archive_name" '$2 == file {print $1; exit}' "$checksums")
if [ -z "$expected" ]; then
  fail "SHA256SUMS did not contain a checksum for $archive_name"
fi
if [ "$checksum_tool" = sha256sum ]; then
  if ! printf '%s  %s\n' "$expected" "$archive" | sha256sum -c - >/dev/null; then
    fail "SHA-256 verification failed for $archive_name"
  fi
else
  actual=$(shasum -a 256 "$archive" | awk '{print $1}')
  if [ "$expected" != "$actual" ]; then
    fail "SHA-256 verification failed for $archive_name"
  fi
fi
ok "SHA-256 verified: $expected"

info "Extracting the release archive"
tar -xzf "$archive" -C "$work_dir" || fail "could not extract $archive_name"
bundle=$(find "$work_dir" -mindepth 1 -maxdepth 1 -type d -name 'envault-v*-*' | head -n 1)
if [ -z "$bundle" ]; then
  fail 'release archive has an unexpected layout'
fi
ok "Extracted release contents"

info "Installing EnVault binaries"
mkdir -p "$install_dir"
install -m 0755 "$bundle/envault" "$install_dir/envault"
install -m 0755 "$bundle/envaultd" "$install_dir/envaultd"
install -m 0755 "$bundle/envault-tui" "$install_dir/envault-tui"
ok "$install_dir/envault"
ok "$install_dir/envaultd"
ok "$install_dir/envault-tui"

info "Shell completions"
completions_installed=0

if [ -f "$bundle/completions/envault.bash" ] && command -v bash >/dev/null 2>&1; then
  bash_comp_dir="${XDG_DATA_HOME:-$HOME/.local/share}/bash-completion/completions"
  mkdir -p "$bash_comp_dir"
  cp "$bundle/completions/envault.bash" "$bash_comp_dir/envault"
  ok "bash: $bash_comp_dir/envault"
  completions_installed=1
fi

if [ -f "$bundle/completions/envault.fish" ] && command -v fish >/dev/null 2>&1; then
  fish_comp_dir="${XDG_CONFIG_HOME:-$HOME/.config}/fish/completions"
  mkdir -p "$fish_comp_dir"
  cp "$bundle/completions/envault.fish" "$fish_comp_dir/envault.fish"
  ok "fish: $fish_comp_dir/envault.fish"
  completions_installed=1
fi

if [ -f "$bundle/completions/_envault" ] && command -v zsh >/dev/null 2>&1; then
  zsh_comp_dir="$HOME/.zsh/completions"
  mkdir -p "$zsh_comp_dir"
  cp "$bundle/completions/_envault" "$zsh_comp_dir/_envault"
  completions_installed=1

  zshrc="$HOME/.zshrc"
  zsh_marker="# EnVault completion (added by install.sh)"
  if [ -f "$zshrc" ] && grep -qF "$zsh_marker" "$zshrc"; then
    ok "zsh: $zsh_comp_dir/_envault (fpath already configured in $zshrc)"
  else
    {
      printf '\n%s\n' "$zsh_marker"
      printf 'fpath=(%s $fpath)\n' "$zsh_comp_dir"
      printf 'autoload -Uz compinit && compinit\n'
    } >>"$zshrc"
    ok "zsh: $zsh_comp_dir/_envault (added fpath to $zshrc, restart your shell to enable)"
  fi
fi

if [ "$completions_installed" -eq 0 ]; then
  warn "no supported shell (bash/zsh/fish) detected, or this release archive has no completions/ directory"
fi

if case ":${PATH:-}:" in *":$install_dir:"*) true ;; *) false ;; esac; then
  ok "$install_dir is already on PATH"
else
  warn "$install_dir is not on PATH"
  printf '%s\n' "    add it with: export PATH=\"$install_dir:\$PATH\""
fi

vault_initialized=0
info "Initializing the vault"
case "${ENVAULT_SKIP_INIT:-}" in
  1|true|yes)
    ok "Skipped (ENVAULT_SKIP_INIT is set)"
    ;;
  *)
    if [ -r /dev/tty ] && [ -w /dev/tty ]; then
      printf '%s' "    Set a master password now? [Y/n] " >/dev/tty
      if IFS= read -r init_reply </dev/tty; then
        case "$init_reply" in
          [Nn]*)
            ok "Skipped; run '$install_dir/envault init' later"
            ;;
          *)
            if "$install_dir/envault" init </dev/tty >/dev/tty 2>&1; then
              ok "Vault initialized"
              vault_initialized=1
            else
              warn "Vault initialization did not complete; run '$install_dir/envault init' later"
            fi
            ;;
        esac
      else
        warn "Could not read from the terminal; run '$install_dir/envault init' later"
      fi
    else
      warn "No interactive terminal available; run '$install_dir/envault init' later"
    fi
    ;;
esac

printf '\n%s\n' 'EnVault installation complete.'
printf '%s\n' "  version: $release_tag"
printf '%s\n' "  target:  $target"
printf '%s\n' "  location: $install_dir"
printf '\n%s\n' 'Next steps:'
if [ "$vault_initialized" -eq 1 ]; then
  printf '%s\n' '  1. envault start'
  printf '%s\n' '  2. envault status'
else
  printf '%s\n' '  1. envault init'
  printf '%s\n' '  2. envault start'
  printf '%s\n' '  3. envault status'
fi
