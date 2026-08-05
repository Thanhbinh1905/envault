# Installation

EnVault publishes verified CLI archives for Linux, macOS, and Windows.
The optional Linux desktop application is a separately installed `.deb` or AppImage package.

## Requirements

Release binaries are self-contained and do not require Rust.
The supported release targets are Linux x86_64, macOS x86_64, macOS arm64, and Windows x86_64.
The daemon and CLI use the operating system's local IPC and keyring facilities.

## Optional EnVault Desktop for Linux

The desktop package is separate from the CLI archive.
Installing the desktop application never installs, replaces, or removes `envault`, `envaultd`, or `envaultui`.
It includes the EnVault logo as the application and launcher icon.

The desktop package never replaces the CLI installation.
It uses the same local vault data and IPC endpoint as an installed CLI.
When it launches, the desktop app ensures a daemon is running, starting its bundled daemon if needed, and immediately shows the tray icon.
The daemon remains locked until the user supplies the master password.
No password is supplied to this startup process.

On Debian and Ubuntu x86_64, install the current desktop release with:

```sh
curl -fsSL https://raw.githubusercontent.com/Thanhbinh1905/envault/main/crates/envault-desktop/install-linux.sh | sh
```

The installer downloads the standalone `.deb`, verifies its sidecar SHA-256 checksum, and invokes `apt-get`.
It needs `sudo` when it is not run as root.

For a manual `.deb` installation:

1. Download `envault-desktop-v<version>-x86_64.deb` and its `.sha256` file from the [latest GitHub Release](https://github.com/Thanhbinh1905/envault/releases/latest).
2. Verify the package.
3. Install it with APT.

```sh
sha256sum -c envault-desktop-v<version>-x86_64.deb.sha256
sudo apt install ./envault-desktop-v<version>-x86_64.deb
```

For a portable AppImage, download `envault-desktop-v<version>-x86_64.AppImage` and its `.sha256` file from the same release:

```sh
sha256sum -c envault-desktop-v<version>-x86_64.AppImage.sha256
chmod +x envault-desktop-v<version>-x86_64.AppImage
./envault-desktop-v<version>-x86_64.AppImage
```

The AppImage runs in place and does not modify a CLI installation.
The desktop app enables opening at sign-in by default.
Use Security settings to disable or re-enable this preference and to start or stop the daemon.
Closing the window hides it and preserves the tray icon and current session.
Choose Quit EnVault from the tray menu to stop the daemon and exit the application.

## Install a GitHub Release

The supported quick installer detects the platform, downloads the matching latest release, verifies `SHA256SUMS`, and installs into `$HOME/.local/bin`:

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
The archive contains `envault`, `envaultd`, and `envaultui` on Unix systems, and the corresponding `.exe` files on Windows.

For a per-user Unix installation:

```sh
install -d "$HOME/.local/bin"
install -m 0755 envault envaultd envaultui "$HOME/.local/bin/"
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
The `envaultui` binary is an optional interactive client and does not replace the daemon.

On Unix, `envault start` can spawn the daemon after the human bootstrap prompt.
On Windows, start `envaultd.exe` from a supervised process or terminal before using client commands because automatic client-side daemon spawning is not available yet.

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
install -m 0755 target/release/envault target/release/envaultd target/release/envaultui "$HOME/.local/bin/"
```

## Upgrade

Stop the daemon before replacing binaries:

```sh
envault stop
```

Replace only the executable files, then run `envault status` to confirm that the new client can reach the daemon.
Upgrading binaries does not migrate or delete the encrypted vault.

## Uninstall

Removing the `envault`, `envaultd`, and `envaultui` executables does not remove the vault.
The vault database, the daemon's runtime state, and (if convenience unlock was enabled) the master password stored in the OS credential store all live outside the installation directory:

| Data | Location |
| --- | --- |
| Vault database | `$XDG_DATA_HOME/envault/vault.db`, or `~/.local/share/envault/vault.db` |
| Daemon runtime state (socket, lock file) | `$XDG_RUNTIME_DIR/envault/`, or `~/.local/share/envault/run/` |
| Convenience-unlock marker | `~/.local/share/envault/convenience-unlock.enabled` |
| Master password (only if convenience unlock is enabled) | OS credential store, service `envault`, account `master-password` |

Use `envault uninstall` to remove all of this in one step, instead of deleting these paths by hand:

```sh
envault uninstall
```

This requires the master password (proving the caller owns the vault before anything is deleted), then asks for confirmation before doing anything destructive.
If a vault database exists, it also offers to export a full backup package first; answering `y` prompts for a destination path (default: the home directory) and a transfer password to encrypt the backup with.
Once the caller confirms, the command stops the daemon, deletes the vault database and daemon runtime directory, and removes any convenience-unlock credential from the OS keyring.
It does not remove the installed binaries themselves - remove `envault`, `envaultd`, and `envaultui` from the installation directory separately.

For scripted or CI use, skip the interactive prompts entirely with:

```sh
envault uninstall --password-stdin --yes --skip-backup
```

`--backup-path` skips only the "where to export" question (the transfer password to encrypt that backup with is always requested on a masked terminal, since it cannot share the same standard input as `--password-stdin`).
Run a backup through `envault portability export` first, then `envault uninstall --password-stdin --yes --skip-backup`, for a fully non-interactive backup-and-uninstall sequence.

`envault uninstall --help` documents every flag.
This action is irreversible without a backup: back up or securely destroy vault data only after confirming it is no longer needed.

## Security notes

Never place a master password, transfer password, or plaintext export in shell history, source control, or an environment variable.
Use the masked prompt or the documented `--password-stdin` flow for automation.
Treat downloaded release archives as untrusted until their SHA-256 checksums have been verified.
Read the [threat model](threat-model.md) before granting an agent access to the EnVault skill or broker.
