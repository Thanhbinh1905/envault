# Installation

EnVault release `v0.0.1` is prepared on this branch.
After this branch merges into `main`, pushing tag `v0.0.1` publishes the GitHub Release artifacts through the tag-triggered release workflow.
Until that tag is published, install from source or wait for the release artifacts.
The Rust crates are not published to crates.io yet.

## Requirements

Release binaries are self-contained and do not require Rust.
The supported release targets are Linux x86_64, macOS x86_64, macOS arm64, and Windows x86_64.
The daemon and CLI use the operating system's local IPC and keyring facilities.

## Install a GitHub Release

After the `v0.0.1` GitHub Release is published, the supported quick installer detects the platform, downloads the matching latest release, verifies `SHA256SUMS`, and installs into `$HOME/.local/bin`:

```sh
curl -fsSL https://raw.githubusercontent.com/Thanhbinh1905/envault/main/install.sh | sh
```

Set `ENVAULT_INSTALL_DIR` to choose another user-writable installation directory.
Review the script before piping it to a shell when your environment requires a stricter supply-chain process.

The installer reports platform detection, release discovery, archive download, checksum verification, extraction, binary installation, and `PATH` status.
It does not print credentials or vault contents.

When run from an interactive terminal, the installer also offers to run `envault init` immediately after installing the binaries, using the masked prompt on `/dev/tty`.
Answer `n` to skip and initialize later, or set `ENVAULT_SKIP_INIT=1` to skip this step non-interactively (for example in CI or containers).

1. Open the [latest GitHub Release](https://github.com/Thanhbinh1905/envault/releases/latest).
2. Download the archive matching your operating system and CPU architecture.
3. Download `SHA256SUMS` from the same release.
4. Verify the archive before extracting it.

On Linux or macOS:

```sh
sha256sum -c SHA256SUMS --ignore-missing
```

On Windows PowerShell:

```powershell
$expected = (Get-Content .\SHA256SUMS | Where-Object { $_ -match 'envault-.*\.zip$' }).Split()[0]
$actual = (Get-FileHash .\envault-*.zip -Algorithm SHA256).Hash.ToLowerInvariant()
if ($expected -ne $actual) { throw "SHA-256 verification failed" }
```

Extract the archive and place the three binaries in a directory on your `PATH`.
The archive contains `envault`, `envaultd`, and `envault-tui` on Unix systems, and the corresponding `.exe` files on Windows.

For a per-user Unix installation:

```sh
install -d "$HOME/.local/bin"
install -m 0755 envault envaultd envault-tui "$HOME/.local/bin/"
```

Add `$HOME/.local/bin` to `PATH` if it is not already present.
Do not install the binaries into a shared system directory unless the machine's security policy requires it.

For a per-user Windows installation, keep the extracted directory stable and add it to the user's `PATH` from **System Properties > Environment Variables**.

## Initialize and run

Initialize the local vault from an interactive terminal:

```sh
envault init
```

Start the daemon explicitly:

```sh
envault start
envault status
```

Use `envault lock` when the vault should be locked and `envault stop` when the daemon should exit.
The `envault-tui` binary is an optional interactive client and does not replace the daemon.

On Unix, `envault start` can spawn the daemon after the human bootstrap prompt.
On Windows, start `envaultd.exe` from a supervised process or terminal before using client commands because automatic client-side daemon spawning is not available yet.

## Shell completions

The quick installer (`install.sh`) detects `bash`, `zsh`, and `fish` on the machine and installs a completion script for each into the shell's standard completion directory, adding an `fpath` entry to `~/.zshrc` for zsh if one is not already present.
Restart the shell, or source the generated file directly, to pick up completions immediately.

For a manual install, a build without `install.sh`, or `elvish`/`powershell`, generate the script directly:

```sh
# bash
envault completions bash | sudo tee /etc/bash_completion.d/envault >/dev/null

# zsh (any directory on $fpath)
envault completions zsh > "${fpath[1]}/_envault"

# fish
envault completions fish > ~/.config/fish/completions/envault.fish
```

## Agent integration

EnVault supports both an explicit session hook and an installable Agent Skill.
Use the session hook when your agent harness supports `SessionStart` context injection:

```sh
envault session setup
```

Use the Agent Skill when you want on-demand guidance without loading state into every session:

```sh
npx skills add Thanhbinh1905/envault --skill envault
```

These are complementary options, and a user only needs one of them.
The skill never starts the daemon, authenticates, loads or unloads a profile, or requests plaintext credentials.

## Install from source

Source installation is useful for contributors or unsupported targets.
Install Rust 1.97.1 or a compatible toolchain, then run:

```sh
git clone https://github.com/Thanhbinh1905/envault.git
cd envault
cargo build --locked --release -p envault --bins
```

The binaries are written to `target/release/`.
Run the verification gates before installing a locally built release:

```sh
cargo xtask verify
cargo xtask package-verify
```

For a local per-user Unix installation:

```sh
install -d "$HOME/.local/bin"
install -m 0755 target/release/envault target/release/envaultd target/release/envault-tui "$HOME/.local/bin/"
```

## Upgrade and uninstall

Stop the daemon before replacing binaries:

```sh
envault stop
```

Replace only the executable files, then run `envault status` to confirm that the new client can reach the daemon.
Upgrading binaries does not migrate or delete the encrypted vault.

To uninstall the binaries, remove the three executable files from the installation directory.
The vault data is separate and is not removed by uninstalling EnVault.
Back up or securely destroy vault data only after confirming that it is no longer needed.

## Security notes

Never place a master password, transfer password, or plaintext export in shell history, source control, or an environment variable.
Use the masked prompt or the documented `--password-stdin` flow for automation.
Treat downloaded release archives as untrusted until their SHA-256 checksums have been verified.
Read the [threat model](threat-model.md) before granting an agent access to the EnVault skill or broker.
