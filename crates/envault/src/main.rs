#![forbid(unsafe_code)]

use std::{
    collections::HashSet,
    env, fs,
    io::{self, IsTerminal, Read, Write},
    path::{Path, PathBuf},
    process::ExitCode,
};

use clap::{Parser, Subcommand, ValueEnum};
use envault::client::{self, ClientError};
use envault_core::{
    ConfigFormat, ConfigPreview, ConfigSelector, EnvImportPreview, GeneratorFormat,
    GeneratorLength, GeneratorSpec, ImportConflictStrategy, PackageKind, PlaintextExportSummary,
    PortabilityExportSummary, PortabilityImportSummary, PortabilityPreview, ProfileView,
    SecretVersionView, SecretView, WorkspaceView,
};
use envault_protocol::{
    AdminLeaseStatus, DaemonStatus, EnvVar, ErrorKind, HttpConstraint, HttpContentType, HttpMethod,
    HttpRequest, HttpResponse, Operation, Reply, SensitiveBytes, ServiceState, StructuredError,
};
use envault_service::{SensitiveInput, ServiceError};
use serde::Serialize;
use uuid::Uuid;
use zeroize::Zeroizing;

mod convenience_unlock;
mod project;

#[derive(Debug, Parser)]
#[command(
    name = "envault",
    version,
    about = "Local-first encrypted secret vault"
)]
struct Cli {
    #[arg(short, long, global = true, value_enum, default_value_t = Output::Human)]
    output: Output,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Output {
    Human,
    Json,
    Toon,
}

#[derive(Debug, Subcommand)]
enum Command {
    Init(PasswordArgs),
    Status,
    Start(PasswordArgs),
    Lock,
    Stop,
    Admin {
        #[command(subcommand)]
        command: AdminCommand,
    },
    Profile {
        #[command(subcommand)]
        command: ProfileCommand,
    },
    Secret {
        #[command(subcommand)]
        command: SecretCommand,
    },
    Request {
        #[command(subcommand)]
        command: RequestCommand,
    },
    Portability {
        #[command(subcommand)]
        command: PortabilityCommand,
    },
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    Workspace {
        #[command(subcommand)]
        command: WorkspaceCommand,
    },
    ConvenienceUnlock {
        #[command(subcommand)]
        command: ConvenienceUnlockCommand,
    },
    Session {
        #[command(subcommand)]
        command: SessionCommand,
    },
    Run(RunArgs),
    /// Load the profiles/workspaces listed in this directory's `.envault.toml`,
    /// unloading anything previously auto-loaded for this project that's no
    /// longer listed
    Load,
    /// Unload everything `envault load` previously auto-loaded for this directory
    Unload,
    Uninstall(UninstallArgs),
    /// Not part of the public command surface (absent from `--help` and
    /// `commands.toml`) - built only via the `internal-completions` feature,
    /// which the release workflow enables solely to render shell completion
    /// scripts once at build time for bundling into the release archive.
    #[cfg(feature = "internal-completions")]
    #[command(hide = true)]
    Completions(CompletionsArgs),
}

#[cfg(feature = "internal-completions")]
#[derive(Debug, clap::Args)]
struct CompletionsArgs {
    shell: clap_complete::Shell,
}

#[derive(Debug, clap::Args)]
struct RunArgs {
    #[arg(
        short,
        long,
        conflicts_with = "workspace",
        help = "Profile to resolve secrets from; repeat to merge several profiles (each must already be loaded)"
    )]
    profile: Vec<String>,
    #[arg(
        short,
        long,
        conflicts_with = "profile",
        help = "Workspace whose member profiles to resolve secrets from (each must already be loaded)"
    )]
    workspace: Option<String>,
    #[arg(
        required = true,
        num_args = 1..,
        trailing_var_arg = true,
        allow_hyphen_values = true,
        help = "Command (and its arguments) to run with resolved secrets injected as env vars"
    )]
    command: Vec<String>,
}

#[derive(Debug, Subcommand)]
enum SessionCommand {
    Context(SessionContextArgs),
    #[command(
        long_about = "Installs a SessionStart hook into a Claude Code settings.json so `session context` runs automatically at session start.\nFor Codex, add an equivalent SessionStart hook running `envault session context --output toon` to `.codex/hooks.json` (with `[features].hooks = true` in config.toml) by hand; for OpenCode, wire the same command into a managed plugin under `~/.config/opencode/plugins/`. Neither is automated by this command."
    )]
    Setup(SessionSetupArgs),
}

#[derive(Debug, clap::Args)]
struct SessionContextArgs {
    #[arg(short = 'e', long, hide = true)]
    envault_session_hook: bool,
}

#[derive(Debug, clap::Args)]
struct SessionSetupArgs {
    #[arg(short, long, default_value = ".claude/settings.json")]
    settings_file: PathBuf,
}

#[derive(Debug, Subcommand)]
enum ConvenienceUnlockCommand {
    Enable(ConvenienceUnlockEnableArgs),
    Disable,
    Status,
}

#[derive(Debug, clap::Args)]
struct ConvenienceUnlockEnableArgs {
    #[command(flatten)]
    password: PasswordArgs,
    #[arg(
        short,
        long,
        required = true,
        help = "Acknowledge that the master password will be stored in this operating system's native credential store"
    )]
    acknowledge_os_keystore: bool,
}

#[derive(Clone, Copy, Debug, clap::Args)]
struct PasswordArgs {
    #[arg(short, long, help = "Read the master password from standard input")]
    password_stdin: bool,
}

#[derive(Clone, Copy, Debug, clap::Args)]
struct AdminUnlockArgs {
    #[command(flatten)]
    password: PasswordArgs,
    #[arg(
        short,
        long,
        default_value_t = envault_core::DEFAULT_ADMIN_LEASE_MINUTES,
        conflicts_with = "no_expiration"
    )]
    minutes: u8,
    #[arg(
        short,
        long,
        help = "Lease never expires until `admin lock`/daemon stop or restart"
    )]
    no_expiration: bool,
}

#[derive(Debug, Subcommand)]
enum AdminCommand {
    Unlock(AdminUnlockArgs),
    Status,
    Lock,
}

#[derive(Debug, clap::Args)]
struct UninstallArgs {
    #[command(flatten)]
    password: PasswordArgs,
    #[arg(
        long,
        help = "Skip the interactive \"are you sure?\" confirmation prompt"
    )]
    yes: bool,
    #[arg(
        long,
        conflicts_with = "backup_path",
        help = "Do not export a backup before deleting all local EnVault data"
    )]
    skip_backup: bool,
    #[arg(
        short = 'O',
        long,
        value_name = "PATH",
        help = "Export a backup to this path before deleting all local data, without prompting"
    )]
    backup_path: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
enum RequestCommand {
    Http(HttpRequestArgs),
}

#[derive(Debug, Subcommand)]
enum ProfileCommand {
    Create(ProfileCreateArgs),
    Show(NameArgs),
    List,
    Update(ProfileUpdateArgs),
    Rename(RenameArgs),
    Delete(NameArgs),
    Load(ProfileLoadArgs),
    Unload(NameArgs),
    Export(ProfileExportArgs),
    Import(ProfilePackageImportArgs),
    ImportEnv(EnvImportArgs),
    ExportEnv(PlaintextExportArgs),
}

#[derive(Debug, Subcommand)]
enum PortabilityCommand {
    Export(WorkspaceExportArgs),
    Import(WorkspacePackageImportArgs),
}

#[derive(Debug, Subcommand)]
enum ConfigCommand {
    Export(ConfigExportArgs),
    Import(ConfigImportArgs),
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ConfigFormatArg {
    Yaml,
    Env,
    Encrypted,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, ValueEnum)]
enum ConfigKindArg {
    #[default]
    Vault,
    Profile,
    Workspace,
}

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
enum ConfigConflictStrategyArg {
    #[default]
    Abort,
    Skip,
    Replace,
    Rename,
}

#[derive(Debug, clap::Args)]
struct ConfigExportArgs {
    #[arg(
        short = 'F',
        long,
        value_enum,
        help = "Output format: full-fidelity YAML, flat .env (single profile), or an encrypted package"
    )]
    format: ConfigFormatArg,
    #[arg(
        short = 'k',
        long,
        value_enum,
        default_value_t = ConfigKindArg::Vault,
        help = "Scope: the whole vault, named profiles, or named workspaces"
    )]
    kind: ConfigKindArg,
    #[arg(
        short = 'n',
        long = "name",
        help = "Profile or workspace name to include; repeat for multiple (required unless --kind vault)"
    )]
    names: Vec<String>,
    #[arg(short = 'd', long, default_value = ".", help = "Destination directory")]
    output_dir: PathBuf,
    #[arg(
        short = 'f',
        long,
        help = "File name within --output-dir (default: export.<ext> for the chosen format)"
    )]
    file_name: Option<String>,
    #[command(flatten)]
    password: TransferPasswordArgs,
    #[arg(
        short = 'a',
        long = "age-recipient",
        value_name = "RECIPIENT",
        help = "Add an age recipient key slot; repeat for multiple recipients (--format encrypted only)"
    )]
    age_recipients: Vec<String>,
}

#[derive(Debug, clap::Args)]
struct ConfigImportArgs {
    #[arg(
        value_name = "FILE",
        help = "YAML, .env, or encrypted package to import"
    )]
    input_file: PathBuf,
    #[arg(short = 'F', long, value_enum, help = "Format of the input file")]
    format: ConfigFormatArg,
    #[arg(
        short = 'k',
        long,
        value_enum,
        default_value_t = ConfigKindArg::Vault,
        help = "Expected package kind (--format encrypted only): vault or profile"
    )]
    kind: ConfigKindArg,
    #[arg(
        short = 'n',
        long = "name",
        help = "Destination profile (--format env only, exactly one)"
    )]
    names: Vec<String>,
    #[command(flatten)]
    password: TransferPasswordArgs,
    #[arg(
        short = 'i',
        long,
        value_name = "FILE",
        help = "Private age identity file used to unwrap a package key slot (--format encrypted only)"
    )]
    age_identity: Option<PathBuf>,
    #[arg(
        short = 'S',
        long,
        value_enum,
        default_value_t = ConfigConflictStrategyArg::Abort,
        help = "Conflict strategy for existing profiles, secrets, and workspace membership"
    )]
    strategy: ConfigConflictStrategyArg,
    #[arg(
        short = 'r',
        long,
        value_name = "PROFILE",
        help = "Destination profile for rename, or an existing renamed profile for replace (--format encrypted, --kind profile only)"
    )]
    rename_to: Option<String>,
    #[arg(
        short = 'c',
        long,
        requires = "plan_hash",
        help = "Atomically apply a previously previewed import plan"
    )]
    commit: bool,
    #[arg(
        short = 'H',
        long,
        value_name = "HASH",
        requires = "commit",
        allow_hyphen_values = true,
        help = "Exact plan hash returned by the latest preview"
    )]
    plan_hash: Option<String>,
}

#[derive(Debug, Subcommand)]
enum WorkspaceCommand {
    Create(NameArgs),
    List,
    Show(NameArgs),
    Load(NameArgs),
    Bind(WorkspaceMembershipArgs),
    Unbind(WorkspaceMembershipArgs),
    Delete(NameArgs),
}

#[derive(Debug, clap::Args)]
struct WorkspaceMembershipArgs {
    workspace: String,
    profile: String,
}

#[derive(Debug, Subcommand)]
enum SecretCommand {
    Create(SecretCreateArgs),
    List(SecretListArgs),
    Describe(NameArgs),
    Update(NameDescriptionArgs),
    Rename(RenameArgs),
    Delete(NameArgs),
    Value {
        #[command(subcommand)]
        command: SecretValueCommand,
    },
}

#[derive(Debug, Subcommand)]
enum SecretValueCommand {
    Set(SecretValueSetArgs),
    Generate(SecretValueGenerateArgs),
}

#[derive(Debug, clap::Args)]
struct NameArgs {
    name: String,
}

#[derive(Debug, clap::Args)]
struct NameDescriptionArgs {
    name: String,
    #[arg(short, long)]
    description: Option<String>,
}

#[derive(Debug, clap::Args)]
struct ProfileUpdateArgs {
    name: String,
    #[arg(short, long)]
    description: Option<String>,
    #[arg(
        short,
        long,
        help = "Auto-load this profile every time the vault next unlocks (independent of whether it is loaded in the current session)"
    )]
    activate_on_start: Option<bool>,
}

#[derive(Debug, clap::Args)]
struct ProfileCreateArgs {
    name: String,
    #[arg(short, long)]
    description: Option<String>,
    #[arg(short, long, help = "Group this profile under an existing workspace")]
    workspace: Option<String>,
}

#[derive(Debug, clap::Args)]
struct RenameArgs {
    old_name: String,
    new_name: String,
}

#[derive(Debug, clap::Args)]
struct ProfileLoadArgs {
    name: String,
    #[arg(
        short,
        long,
        help = "Also configure HTTP access for one secret in this profile (bare name, no profile prefix)"
    )]
    secret: Option<String>,
    #[arg(
        short = 'H',
        long,
        help = "Required with --secret: the exact allowed host"
    )]
    host: Option<String>,
    #[arg(short, long, default_value_t = 443)]
    port: u16,
    #[arg(
        short,
        long,
        value_enum,
        value_delimiter = ',',
        help = "Required with --secret: allowed HTTP methods"
    )]
    method: Vec<HttpMethodArg>,
    #[arg(short = 'P', long, default_value = "/")]
    path_prefix: String,
    #[arg(short = 'r', long, default_value_t = 64 * 1024)]
    max_request_bytes: usize,
    #[arg(short = 'R', long, default_value_t = 256 * 1024)]
    max_response_bytes: usize,
    #[arg(
        long,
        help = "With --secret, when no admin lease is active: read the master password from standard input instead of prompting"
    )]
    password_stdin: bool,
}

#[derive(Debug, clap::Args)]
struct SecretCreateArgs {
    name: String,
    #[arg(short, long)]
    description: Option<String>,
    #[arg(short, long, conflicts_with = "generate")]
    stdin: bool,
    #[arg(short, long, value_enum, conflicts_with = "stdin")]
    generate: Option<GeneratorFormatArg>,
    #[command(flatten)]
    length: GeneratorLengthArgs,
}

#[derive(Clone, Debug, clap::Args)]
struct SecretListArgs {
    #[arg(short, long, help = "Deprecated: use `--fields description` instead")]
    describe: bool,
    #[arg(
        short,
        long,
        value_delimiter = ',',
        help = "Additional columns beyond the default schema (supported: description)"
    )]
    fields: Vec<String>,
    #[arg(
        short,
        long,
        help = "Show the effective secret set for this profile (own secrets overlaid on base)"
    )]
    profile: Option<String>,
}

#[derive(Debug, clap::Args)]
struct SecretValueSetArgs {
    name: String,
    #[arg(
        short,
        long,
        required = true,
        help = "Read the replacement value from piped standard input"
    )]
    stdin: bool,
}

#[derive(Debug, clap::Args)]
struct SecretValueGenerateArgs {
    name: String,
    #[arg(short, long, value_enum)]
    format: GeneratorFormatArg,
    #[command(flatten)]
    length: GeneratorLengthArgs,
}

#[derive(Clone, Copy, Debug, Default, clap::Args)]
struct GeneratorLengthArgs {
    #[arg(short, long, conflicts_with = "bytes")]
    chars: Option<usize>,
    #[arg(short, long, conflicts_with = "chars")]
    bytes: Option<usize>,
    #[arg(short, long)]
    allow_weak: bool,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum GeneratorFormatArg {
    UuidV4,
    Base64url,
    Base64,
}

#[derive(Debug, clap::Args)]
struct HttpRequestArgs {
    url: String,
    #[arg(short, long, value_enum, default_value_t = HttpMethodArg::Get)]
    method: HttpMethodArg,
    #[arg(
        short,
        long,
        help = "Secret reference as <profile>.<name>, or bare <name> for base"
    )]
    secret: String,
    #[arg(short, long)]
    body_file: Option<PathBuf>,
    #[arg(short, long, value_enum)]
    content_type: Option<HttpContentTypeArg>,
    #[arg(
        short,
        long,
        help = "Print the complete response body without truncation"
    )]
    full: bool,
}

#[derive(Clone, Copy, Debug, Default, clap::Args)]
struct TransferPasswordArgs {
    #[arg(
        short = 't',
        long,
        conflicts_with = "transfer_password_stdin",
        help = "Prompt for a transfer password on a masked terminal"
    )]
    transfer_password: bool,
    #[arg(
        short = 's',
        long,
        conflicts_with = "transfer_password",
        help = "Read the transfer password from standard input"
    )]
    transfer_password_stdin: bool,
}

#[derive(Debug, clap::Args)]
struct ProfileExportArgs {
    #[arg(value_name = "PROFILE", help = "Profile to export")]
    name: String,
    #[arg(
        short = 'O',
        long,
        value_name = "FILE",
        help = "New .envault-profile package path"
    )]
    output_file: PathBuf,
    #[command(flatten)]
    password: TransferPasswordArgs,
    #[arg(
        short = 'a',
        long = "age-recipient",
        value_name = "RECIPIENT",
        help = "Add an age recipient key slot; repeat for multiple recipients"
    )]
    age_recipients: Vec<String>,
}

#[derive(Debug, clap::Args)]
struct WorkspaceExportArgs {
    #[arg(
        short = 'O',
        long,
        value_name = "FILE",
        help = "New .envault-workspace package path"
    )]
    output_file: PathBuf,
    #[command(flatten)]
    password: TransferPasswordArgs,
    #[arg(
        short = 'a',
        long = "age-recipient",
        value_name = "RECIPIENT",
        help = "Add an age recipient key slot; repeat for multiple recipients"
    )]
    age_recipients: Vec<String>,
}

#[derive(Debug, clap::Args)]
struct ProfilePackageImportArgs {
    #[arg(value_name = "FILE", help = "Encrypted .envault-profile package")]
    input_file: PathBuf,
    #[command(flatten)]
    password: TransferPasswordArgs,
    #[arg(
        short = 'i',
        long,
        value_name = "FILE",
        help = "Private age identity file used to unwrap a package key slot"
    )]
    age_identity: Option<PathBuf>,
    #[arg(
        short = 'S',
        long,
        value_enum,
        default_value_t = ProfileConflictStrategyArg::Abort,
        help = "Conflict strategy for the destination profile"
    )]
    strategy: ProfileConflictStrategyArg,
    #[arg(
        short = 'r',
        long,
        value_name = "PROFILE",
        required_if_eq("strategy", "rename"),
        help = "Destination profile for rename, or an existing renamed profile for replace"
    )]
    rename_to: Option<String>,
    #[arg(
        short = 'c',
        long,
        requires = "plan_hash",
        help = "Atomically apply a previously previewed import plan"
    )]
    commit: bool,
    #[arg(
        short = 'H',
        long,
        value_name = "HASH",
        requires = "commit",
        allow_hyphen_values = true,
        help = "Exact plan hash returned by the latest preview"
    )]
    plan_hash: Option<String>,
}

#[derive(Debug, clap::Args)]
struct WorkspacePackageImportArgs {
    #[arg(value_name = "FILE", help = "Encrypted .envault-workspace package")]
    input_file: PathBuf,
    #[command(flatten)]
    password: TransferPasswordArgs,
    #[arg(
        short = 'i',
        long,
        value_name = "FILE",
        help = "Private age identity file used to unwrap a package key slot"
    )]
    age_identity: Option<PathBuf>,
    #[arg(
        short = 'S',
        long,
        value_enum,
        default_value_t = WorkspaceConflictStrategyArg::Abort,
        help = "Abort unless empty, or atomically replace the workspace"
    )]
    strategy: WorkspaceConflictStrategyArg,
    #[arg(
        short = 'c',
        long,
        requires = "plan_hash",
        help = "Atomically apply a previously previewed import plan"
    )]
    commit: bool,
    #[arg(
        short = 'H',
        long,
        value_name = "HASH",
        requires = "commit",
        allow_hyphen_values = true,
        help = "Exact plan hash returned by the latest preview"
    )]
    plan_hash: Option<String>,
}

struct PackageImportRequest {
    expected_kind: PackageKind,
    input_file: PathBuf,
    password: TransferPasswordArgs,
    age_identity: Option<PathBuf>,
    strategy: ImportConflictStrategy,
    rename_to: Option<String>,
    commit: bool,
    plan_hash: Option<String>,
}

#[derive(Debug, clap::Args)]
struct EnvImportArgs {
    #[arg(value_name = "PROFILE", help = "Destination profile")]
    name: String,
    #[arg(value_name = "FILE", help = "Plaintext .env file to scan and import")]
    input_file: PathBuf,
    #[arg(
        short = 'S',
        long,
        value_enum,
        default_value_t = EnvConflictStrategyArg::Abort,
        help = "Conflict strategy for existing secret names"
    )]
    strategy: EnvConflictStrategyArg,
    #[arg(
        short = 'c',
        long,
        requires = "plan_hash",
        help = "Atomically apply a previously previewed import plan"
    )]
    commit: bool,
    #[arg(
        short = 'H',
        long,
        value_name = "HASH",
        requires = "commit",
        allow_hyphen_values = true,
        help = "Exact plan hash returned by the latest preview"
    )]
    plan_hash: Option<String>,
}

#[derive(Debug, clap::Args)]
struct PlaintextExportArgs {
    #[arg(value_name = "PROFILE", help = "Profile to export")]
    name: String,
    #[arg(
        short = 'O',
        long,
        value_name = "FILE",
        help = "New plaintext .env destination"
    )]
    output_file: PathBuf,
    #[arg(
        short,
        long,
        required = true,
        help = "Acknowledge that the destination contains plaintext secrets"
    )]
    allow_plaintext: bool,
}

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
enum ProfileConflictStrategyArg {
    #[default]
    Abort,
    Skip,
    Replace,
    Rename,
}

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
enum WorkspaceConflictStrategyArg {
    #[default]
    Abort,
    Replace,
}

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
enum EnvConflictStrategyArg {
    #[default]
    Abort,
    Skip,
    Replace,
}

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
enum HttpMethodArg {
    #[default]
    Get,
    Post,
    Put,
    Patch,
    Delete,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum HttpContentTypeArg {
    Json,
    Text,
    Form,
}

#[derive(Debug, Serialize)]
struct StatusView {
    daemon: &'static str,
    service: &'static str,
    profile: Option<String>,
    pid: Option<u32>,
    admin_lease_active: bool,
    help: Vec<&'static str>,
}

fn main() -> ExitCode {
    let _ = envault_platform::harden_sensitive_process();
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => return report_parse_error(&error),
    };
    let no_args = cli.command.is_none();
    let command = cli.command.unwrap_or(Command::Status);
    if no_args {
        print_home_header(cli.output);
    }
    match command {
        Command::Status => print_status(cli.output),
        Command::Init(arguments) => initialize_vault(cli.output, arguments),
        Command::Start(arguments) => start_daemon(cli.output, arguments),
        Command::Lock => lifecycle_request(cli.output, Operation::Lock, "locked"),
        Command::Stop => lifecycle_request(cli.output, Operation::Stop, "stopped"),
        Command::Admin { command } => admin_command(cli.output, &command),
        Command::Profile { command } => profile_command(cli.output, command),
        Command::Secret { command } => secret_command(cli.output, command),
        Command::Request {
            command: RequestCommand::Http(arguments),
        } => http_request(cli.output, arguments),
        Command::Portability { command } => portability_command(cli.output, command),
        Command::Config { command } => config_command(cli.output, command),
        Command::Workspace { command } => workspace_command(cli.output, command),
        Command::ConvenienceUnlock { command } => convenience_unlock_command(cli.output, command),
        Command::Session { command } => session_command(cli.output, command),
        Command::Run(arguments) => run_command(cli.output, arguments),
        Command::Load => cmd_load(cli.output),
        Command::Unload => cmd_unload(cli.output),
        Command::Uninstall(arguments) => uninstall_command(cli.output, &arguments),
        #[cfg(feature = "internal-completions")]
        Command::Completions(arguments) => completions(arguments.shell),
    }
}

#[cfg(feature = "internal-completions")]
fn completions(shell: clap_complete::Shell) -> ExitCode {
    use clap::CommandFactory;
    let mut command = Cli::command();
    let name = command.get_name().to_string();
    clap_complete::generate(shell, &mut command, name, &mut io::stdout());
    ExitCode::SUCCESS
}

/// clap's parse failures cover both real usage errors and the `-h`/`--help`
/// and `-V`/`--version` "errors" it uses internally to short-circuit normal
/// parsing. Only help output goes through `dim_help_descriptions` - clap
/// already renders everything else (usage errors, `--version`) exactly as
/// it should.
fn report_parse_error(error: &clap::Error) -> ExitCode {
    use clap::error::ErrorKind;
    match error.kind() {
        ErrorKind::DisplayHelp | ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand => {
            print!("{}", dim_help_descriptions(&error.to_string()));
            ExitCode::SUCCESS
        }
        _ => error.exit(),
    }
}

/// Dims each row's description column (a command/flag's help text, or a
/// `[default: ...]`/`[possible values: ...]` annotation) so the flag or
/// subcommand name itself stands out. Only applied when stdout is a
/// terminal that isn't opted out via `NO_COLOR`, so piped/redirected help
/// output stays plain text.
fn dim_help_descriptions(help: &str) -> String {
    const DIM: &str = "\x1b[2m";
    const RESET: &str = "\x1b[0m";
    if !io::stdout().is_terminal() || std::env::var_os("NO_COLOR").is_some() {
        return help.to_string();
    }
    let mut out = String::with_capacity(help.len() + 128);
    for chunk in help.split_inclusive('\n') {
        let (line, newline) = match chunk.strip_suffix('\n') {
            Some(rest) => (rest, "\n"),
            None => (chunk, ""),
        };
        match description_column_start(line) {
            Some(boundary) => {
                out.push_str(&line[..boundary]);
                out.push_str(DIM);
                out.push_str(&line[boundary..]);
                out.push_str(RESET);
            }
            None => out.push_str(line),
        }
        out.push_str(newline);
    }
    out
}

/// A help row (a subcommand, flag, or positional argument entry) is rendered
/// as `  <name/usage>  <description>`, two-space indented, with the
/// description column separated by a run of two or more spaces. Returns the
/// byte offset where that separating run starts, so the caller can dim from
/// there to the end of the line. Section headers (`Options:`, `Usage: ...`)
/// and blank lines start at column zero or are all whitespace, so neither
/// matches and both are left untouched.
fn description_column_start(line: &str) -> Option<usize> {
    if !line.starts_with("  ") || line.trim().is_empty() {
        return None;
    }
    let bytes = line.as_bytes();
    (2..bytes.len() - 1).find(|&index| bytes[index] == b' ' && bytes[index + 1] == b' ')
}

fn initialize_vault(output: Output, arguments: PasswordArgs) -> ExitCode {
    let password = match read_master_password(arguments.password_stdin, true) {
        Ok(password) => SensitiveInput::new(password.into_vec()),
        Err(error) => return print_error(output, &error),
    };
    let database_path = match vault_database_path() {
        Ok(path) => path,
        Err(error) => return print_error(output, &error),
    };
    match envault_service::initialize_with_recommended_kdf(&database_path, &password) {
        Ok(initialization) => {
            match output {
                Output::Human => println!(
                    "vault: initialized · profile: base · id: {} · database: {}",
                    initialization.vault_id.0,
                    database_path.display()
                ),
                Output::Json => println!(
                    "{}",
                    serde_json::to_string(&initialization).expect("initialization serializes")
                ),
                Output::Toon => println!(
                    "vault{{status,id,profile,database}}: initialized,{},base,{}",
                    initialization.vault_id.0,
                    toon_string(&database_path.display().to_string())
                ),
            }
            ExitCode::SUCCESS
        }
        Err(error) => print_error(output, &service_error(&error)),
    }
}

fn start_daemon(output: Output, arguments: PasswordArgs) -> ExitCode {
    match client::request(Operation::Status) {
        Ok(Reply::Status(status)) if status.service == ServiceState::Unlocked => {
            return print_running_status(output, &status);
        }
        Ok(Reply::Status(_)) | Err(ClientError::NotRunning) => {}
        Ok(_) => return print_error(output, &unexpected_response()),
        Err(error) => return print_error(output, &client_error(error)),
    }
    let password = match resolve_start_password(arguments.password_stdin) {
        Ok(password) => password,
        Err(error) => return print_error(output, &error),
    };
    match client::start(password) {
        Ok(status) => print_running_status(output, &status),
        Err(error) => print_error(output, &client_error(error)),
    }
}

fn resolve_start_password(password_stdin: bool) -> Result<SensitiveBytes, StructuredError> {
    if convenience_unlock::is_enabled() {
        match convenience_unlock::read_stored_password(&convenience_unlock::RealKeystore) {
            Ok(password) => return Ok(password),
            Err(_) => eprintln!(
                "convenience unlock: stored master password is unavailable, falling back to the password prompt"
            ),
        }
    }
    read_master_password(password_stdin, false)
}

/// Permanently removes every local trace of `EnVault`: the vault database, the
/// daemon's runtime socket/lock directory, and (if convenience unlock was
/// enabled) the master password stored in the OS credential store. This does
/// not touch the installed binaries themselves - see the "Upgrade and
/// uninstall" section of `docs/INSTALLATION.md`.
#[allow(clippy::too_many_lines)]
fn uninstall_command(output: Output, arguments: &UninstallArgs) -> ExitCode {
    let database_path = match vault_database_path() {
        Ok(path) => path,
        Err(error) => return print_error(output, &error),
    };
    let vault_exists = database_path.exists();

    // Proving the caller holds the master password gates the whole
    // operation on the same authority as every other admin-level command,
    // even when the caller ends up declining the backup below. The admin
    // lease acquired here is also what `ExportPackage` requires later.
    if vault_exists {
        let password = match read_master_password(arguments.password.password_stdin, false) {
            Ok(password) => password,
            Err(error) => return print_error(output, &error),
        };
        if let Err(error) = client::start(password.clone()) {
            return print_error(output, &client_error(error));
        }
        match client::request(Operation::AdminUnlock {
            password,
            ttl_minutes: Some(envault_core::DEFAULT_ADMIN_LEASE_MINUTES),
        }) {
            Ok(Reply::AdminStatus(_)) => {}
            Ok(_) => return print_error(output, &unexpected_response()),
            Err(error) => return print_error(output, &client_error(error)),
        }
    }

    if !arguments.yes {
        match confirm(
            "This permanently deletes the EnVault vault database, daemon runtime state, and any \
             stored convenience-unlock credential on this machine. This cannot be undone. \
             Continue? [y/N] ",
            false,
        ) {
            Ok(true) => {}
            Ok(false) => {
                println!("uninstall: aborted");
                return ExitCode::SUCCESS;
            }
            Err(error) => return print_error(output, &error),
        }
    }

    if vault_exists && !arguments.skip_backup {
        let backup_path = match arguments.backup_path.clone() {
            Some(path) => Some(path),
            None => match confirm(
                "Export a backup of everything before deleting? [Y/n] ",
                true,
            ) {
                Ok(true) => match prompt_line("Backup path (default: ~): ") {
                    Ok(input) => match resolve_backup_path(&input) {
                        Ok(path) => Some(path),
                        Err(error) => return print_error(output, &error),
                    },
                    Err(error) => return print_error(output, &error),
                },
                Ok(false) => None,
                Err(error) => return print_error(output, &error),
            },
        };
        if let Some(backup_path) = backup_path {
            let transfer_password_args = TransferPasswordArgs {
                transfer_password: true,
                transfer_password_stdin: arguments.password.password_stdin,
            };
            let operation = match build_export_request(
                PackageKind::Workspace,
                None,
                &backup_path,
                transfer_password_args,
                Vec::new(),
            ) {
                Ok(operation) => operation,
                Err(error) => return print_error(output, &error),
            };
            match client::request(operation) {
                Ok(Reply::PortabilityExport(summary)) => {
                    print_portability_export(output, &summary);
                }
                Ok(_) => return print_error(output, &unexpected_response()),
                Err(error) => return print_error(output, &client_error(error)),
            }
        }
    }

    match client::request(Operation::Stop) {
        Ok(Reply::Acknowledged { .. }) | Err(ClientError::NotRunning) => {}
        Ok(_) => return print_error(output, &unexpected_response()),
        Err(error) => return print_error(output, &client_error(error)),
    }

    if let Err(error) = convenience_unlock::disable(&convenience_unlock::RealKeystore) {
        return print_error(
            output,
            &input_error(
                "io_error",
                &format!("failed to remove the stored convenience-unlock credential: {error}"),
            ),
        );
    }

    let Ok(runtime_directory) = envault_platform::runtime_directory() else {
        return print_error(
            output,
            &input_error(
                "io_error",
                "unable to resolve the EnVault runtime directory",
            ),
        );
    };
    if let Err(error) = remove_directory_tree(&runtime_directory) {
        return print_error(output, &error);
    }
    if let Err(error) = remove_directory_tree(database_path.parent().unwrap_or(&database_path)) {
        return print_error(output, &error);
    }

    match output {
        Output::Human => println!("envault: uninstalled - all local vault data has been removed"),
        Output::Json => println!("{{\"status\":\"uninstalled\"}}"),
        Output::Toon => println!("envault{{status}}: uninstalled"),
    }
    ExitCode::SUCCESS
}

fn confirm(prompt: &str, default: bool) -> Result<bool, StructuredError> {
    if !io::stdin().is_terminal() {
        return Err(input_error(
            "interactive_terminal_required",
            "use `--yes` and either `--skip-backup` or `--backup-path` when standard input is not a terminal",
        ));
    }
    print!("{prompt}");
    io::stdout()
        .flush()
        .map_err(|_| input_error("io_error", "failed to write the confirmation prompt"))?;
    let mut line = String::new();
    io::stdin()
        .read_line(&mut line)
        .map_err(|_| input_error("io_error", "failed to read the confirmation response"))?;
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Ok(default);
    }
    Ok(matches!(trimmed.to_ascii_lowercase().as_str(), "y" | "yes"))
}

fn prompt_line(prompt: &str) -> Result<String, StructuredError> {
    if !io::stdin().is_terminal() {
        return Err(input_error(
            "interactive_terminal_required",
            "use `--backup-path` when standard input is not a terminal",
        ));
    }
    print!("{prompt}");
    io::stdout()
        .flush()
        .map_err(|_| input_error("io_error", "failed to write the prompt"))?;
    let mut line = String::new();
    io::stdin()
        .read_line(&mut line)
        .map_err(|_| input_error("io_error", "failed to read the response"))?;
    Ok(line.trim().to_owned())
}

/// Resolves the user's answer to the "backup path" prompt: an empty answer
/// or a bare `~` defaults to the home directory, and any directory (existing
/// or the home-directory default) gets a generated package file name
/// appended so the export always has a concrete destination file.
fn resolve_backup_path(input: &str) -> Result<PathBuf, StructuredError> {
    let trimmed = input.trim();
    let expanded = if trimmed.is_empty() || trimmed == "~" {
        let home = env::var_os("HOME").ok_or_else(|| {
            input_error(
                "io_error",
                "unable to resolve the home directory; pass --backup-path instead",
            )
        })?;
        PathBuf::from(home)
    } else if let Some(rest) = trimmed.strip_prefix("~/") {
        let home = env::var_os("HOME").ok_or_else(|| {
            input_error(
                "io_error",
                "unable to resolve the home directory; pass --backup-path instead",
            )
        })?;
        PathBuf::from(home).join(rest)
    } else {
        PathBuf::from(trimmed)
    };
    if expanded.is_dir() {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or_default();
        Ok(expanded.join(format!("envault-backup-{timestamp}.envault-workspace")))
    } else {
        Ok(expanded)
    }
}

fn remove_directory_tree(path: &Path) -> Result<(), StructuredError> {
    match fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(input_error(
            "io_error",
            &format!("failed to remove {}: {error}", path.display()),
        )),
    }
}

fn convenience_unlock_command(output: Output, command: ConvenienceUnlockCommand) -> ExitCode {
    match command {
        ConvenienceUnlockCommand::Enable(arguments) => {
            let password = match read_master_password(arguments.password.password_stdin, false) {
                Ok(password) => password,
                Err(error) => return print_error(output, &error),
            };
            let database_path = match vault_database_path() {
                Ok(path) => path,
                Err(error) => return print_error(output, &error),
            };
            let verification = SensitiveInput::new(password.as_slice().to_vec());
            if let Err(error) = envault_service::VaultSession::unlock(&database_path, &verification)
            {
                return print_error(output, &service_error(&error));
            }
            match convenience_unlock::enable(&password, &convenience_unlock::RealKeystore) {
                Ok(()) => {
                    println!(
                        "convenience unlock: enabled · the master password is now stored in this operating system's native credential store and `start` will no longer prompt for it · this lowers the vault's practical unlock guarantee to \"requires access to the current OS session\" · disable with `envault convenience-unlock disable`"
                    );
                    ExitCode::SUCCESS
                }
                Err(error) => print_error(
                    output,
                    &input_error(
                        "io_error",
                        &format!("failed to enable convenience unlock: {error}"),
                    ),
                ),
            }
        }
        ConvenienceUnlockCommand::Disable => {
            match convenience_unlock::disable(&convenience_unlock::RealKeystore) {
                Ok(()) => {
                    println!(
                        "convenience unlock: disabled · the stored master password was removed from the OS credential store · `start` will prompt again"
                    );
                    ExitCode::SUCCESS
                }
                Err(error) => print_error(
                    output,
                    &input_error(
                        "io_error",
                        &format!("failed to disable convenience unlock: {error}"),
                    ),
                ),
            }
        }
        ConvenienceUnlockCommand::Status => {
            let enabled = convenience_unlock::is_enabled();
            match output {
                Output::Human => println!(
                    "convenience unlock: {}",
                    if enabled { "enabled" } else { "disabled" }
                ),
                Output::Json => println!("{{\"enabled\":{enabled}}}"),
                Output::Toon => println!("convenience_unlock{{enabled}}: {enabled}"),
            }
            ExitCode::SUCCESS
        }
    }
}

/// Directory-scoped, token-budget-aware dashboard suitable for a
/// `SessionStart` hook (AXI guideline §7): only what an agent needs to
/// orient before taking any action, never the full status view's agent
/// session count or admin lease detail, and never secret material.
fn session_command(output: Output, command: SessionCommand) -> ExitCode {
    match command {
        SessionCommand::Context(_) => print_session_context(output),
        SessionCommand::Setup(arguments) => session_setup(output, &arguments),
    }
}

fn print_session_context(output: Output) -> ExitCode {
    match client::request(Operation::Status) {
        Ok(Reply::Status(status)) => {
            let service = match status.service {
                ServiceState::Unlocked => "unlocked",
                ServiceState::Locked => "locked",
            };
            let profiles = status.loaded_profiles.join(", ");
            let profiles = if profiles.is_empty() {
                None
            } else {
                Some(profiles.as_str())
            };
            print_session_context_view(output, "running", service, profiles)
        }
        Ok(_) => print_error(output, &unexpected_response()),
        Err(ClientError::NotRunning) => {
            print_session_context_view(output, "stopped", "inactive", None)
        }
        Err(error) => print_error(output, &client_error(error)),
    }
}

fn print_session_context_view(
    output: Output,
    daemon: &str,
    service: &str,
    profile: Option<&str>,
) -> ExitCode {
    match output {
        Output::Human => println!(
            "envault: daemon {daemon} · service {service} · profile {}",
            profile.unwrap_or("none")
        ),
        Output::Json => println!(
            "{}",
            serde_json::json!({ "daemon": daemon, "service": service, "profile": profile })
        ),
        Output::Toon => println!(
            "session{{daemon,service,profile}}: {},{},{}",
            daemon,
            service,
            optional_toon(profile)
        ),
    }
    ExitCode::SUCCESS
}

const SESSION_HOOK_MARKER: &str = "--envault-session-hook";

fn session_setup(output: Output, arguments: &SessionSetupArgs) -> ExitCode {
    let Ok(executable) = std::env::current_exe() else {
        return print_error(
            output,
            &input_error(
                "io_error",
                "unable to resolve the current executable's path",
            ),
        );
    };
    let command = session_hook_command(&executable);
    match install_session_hook(&arguments.settings_file, &command) {
        Ok(HookInstallOutcome::Installed) => print_session_setup_result(output, "installed"),
        Ok(HookInstallOutcome::Repaired) => print_session_setup_result(output, "repaired"),
        Ok(HookInstallOutcome::Unchanged) => print_session_setup_result(output, "unchanged"),
        Err(message) => print_error(output, &input_error("io_error", &message)),
    }
}

fn print_session_setup_result(output: Output, state: &str) -> ExitCode {
    match output {
        Output::Human => println!("session hook: {state}"),
        Output::Json => println!("{{\"status\":{}}}", toon_string(state)),
        Output::Toon => println!("session_hook{{status}}: {}", toon_string(state)),
    }
    ExitCode::SUCCESS
}

/// A PATH-verified binary name is portable across machines and survives a
/// relocated install; the absolute path is the fallback only when the
/// current executable isn't the one `PATH` would actually resolve, so a
/// stale `PATH` entry can never shadow this hook with a different binary.
fn session_hook_command(executable: &Path) -> String {
    let binary_name = executable
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("envault");
    let resolves_to_current = which_on_path(binary_name)
        .is_some_and(|resolved| paths_reference_the_same_file(&resolved, executable));
    let program = if resolves_to_current {
        binary_name.to_owned()
    } else {
        shell_quote(&executable.display().to_string())
    };
    format!("{program} session context --output toon {SESSION_HOOK_MARKER}")
}

#[cfg(windows)]
fn shell_quote(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\\\""))
}

#[cfg(not(windows))]
fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn which_on_path(binary_name: &str) -> Option<PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    std::env::split_paths(&path_var)
        .map(|directory| directory.join(binary_name))
        .find(|candidate| candidate.is_file())
}

fn paths_reference_the_same_file(left: &Path, right: &Path) -> bool {
    match (fs::canonicalize(left), fs::canonicalize(right)) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
    }
}

enum HookInstallOutcome {
    Installed,
    Repaired,
    Unchanged,
}

/// Installs (or repairs) a `SessionStart` hook entry whose command contains
/// [`SESSION_HOOK_MARKER`], matching the "explicit opt-in setup command,
/// idempotent on repeat, path repair on relocation" contract AXI guideline
/// §7 sets for ambient session integrations.
fn install_session_hook(settings_path: &Path, command: &str) -> Result<HookInstallOutcome, String> {
    let mut settings: serde_json::Value = if settings_path.exists() {
        let text = fs::read_to_string(settings_path)
            .map_err(|error| format!("failed to read {}: {error}", settings_path.display()))?;
        if text.trim().is_empty() {
            serde_json::json!({})
        } else {
            serde_json::from_str(&text).map_err(|error| {
                format!(
                    "{} contains invalid JSON and was left untouched: {error}",
                    settings_path.display()
                )
            })?
        }
    } else {
        serde_json::json!({})
    };

    let hooks = settings
        .as_object_mut()
        .ok_or_else(|| format!("{} is not a JSON object", settings_path.display()))?
        .entry("hooks")
        .or_insert_with(|| serde_json::json!({}));
    let session_start = hooks
        .as_object_mut()
        .ok_or_else(|| format!("{} `hooks` is not a JSON object", settings_path.display()))?
        .entry("SessionStart")
        .or_insert_with(|| serde_json::json!([]));
    let session_start_entries = session_start.as_array_mut().ok_or_else(|| {
        format!(
            "{} `hooks.SessionStart` is not an array",
            settings_path.display()
        )
    })?;

    let existing_hook = session_start_entries.iter_mut().find_map(|entry| {
        entry
            .get_mut("hooks")?
            .as_array_mut()?
            .iter_mut()
            .find(|hook| {
                hook.get("command")
                    .and_then(|value| value.as_str())
                    .is_some_and(|existing| existing.contains(SESSION_HOOK_MARKER))
            })
    });

    let outcome = if let Some(hook) = existing_hook {
        let current = hook.get("command").and_then(|value| value.as_str());
        if current == Some(command) {
            HookInstallOutcome::Unchanged
        } else {
            hook["command"] = serde_json::Value::String(command.to_owned());
            HookInstallOutcome::Repaired
        }
    } else {
        session_start_entries.push(serde_json::json!({
            "matcher": "*",
            "hooks": [{ "type": "command", "command": command }],
        }));
        HookInstallOutcome::Installed
    };

    if matches!(
        outcome,
        HookInstallOutcome::Installed | HookInstallOutcome::Repaired
    ) {
        if let Some(parent) = settings_path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)
                .map_err(|error| format!("failed to create {}: {error}", parent.display()))?;
        }
        let rendered = serde_json::to_string_pretty(&settings)
            .map_err(|error| format!("failed to serialize settings: {error}"))?;
        fs::write(settings_path, rendered + "\n")
            .map_err(|error| format!("failed to write {}: {error}", settings_path.display()))?;
    }

    Ok(outcome)
}

fn admin_command(output: Output, command: &AdminCommand) -> ExitCode {
    match command {
        AdminCommand::Unlock(arguments) => {
            let password = match read_master_password(arguments.password.password_stdin, false) {
                Ok(password) => password,
                Err(error) => return print_error(output, &error),
            };
            let ttl_minutes = if arguments.no_expiration {
                None
            } else {
                Some(arguments.minutes)
            };
            match client::request(Operation::AdminUnlock {
                password,
                ttl_minutes,
            }) {
                Ok(Reply::AdminStatus(status)) => print_admin_status(output, &status),
                Ok(_) => print_error(output, &unexpected_response()),
                Err(error) => print_error(output, &client_error(error)),
            }
        }
        AdminCommand::Status => match client::request(Operation::AdminStatus) {
            Ok(Reply::AdminStatus(status)) => print_admin_status(output, &status),
            Ok(_) => print_error(output, &unexpected_response()),
            Err(error) => print_error(output, &client_error(error)),
        },
        AdminCommand::Lock => lifecycle_request(output, Operation::AdminLock, "admin_locked"),
    }
}

fn profile_command(output: Output, command: ProfileCommand) -> ExitCode {
    match command {
        ProfileCommand::Export(arguments) => {
            return export_package(
                output,
                PackageKind::Profile,
                Some(arguments.name),
                &arguments.output_file,
                arguments.password,
                arguments.age_recipients,
            );
        }
        ProfileCommand::Import(arguments) => return import_profile_package(output, arguments),
        ProfileCommand::ImportEnv(arguments) => return import_env(output, arguments),
        ProfileCommand::ExportEnv(arguments) => return export_plaintext_env(output, arguments),
        ProfileCommand::Load(arguments) => return profile_load(output, arguments),
        ProfileCommand::Create(_)
        | ProfileCommand::Show(_)
        | ProfileCommand::List
        | ProfileCommand::Update(_)
        | ProfileCommand::Rename(_)
        | ProfileCommand::Delete(_)
        | ProfileCommand::Unload(_) => {}
    }
    let operation = match command {
        ProfileCommand::Create(arguments) => Operation::CreateProfile {
            name: arguments.name,
            description: arguments.description,
            workspace: arguments.workspace,
        },
        ProfileCommand::Show(arguments) => Operation::ShowProfile {
            name: arguments.name,
        },
        ProfileCommand::List => Operation::ListProfiles,
        ProfileCommand::Update(arguments) => Operation::UpdateProfile {
            name: arguments.name,
            description: arguments.description,
            activate_on_start: arguments.activate_on_start,
        },
        ProfileCommand::Rename(arguments) => Operation::RenameProfile {
            old_name: arguments.old_name,
            new_name: arguments.new_name,
        },
        ProfileCommand::Delete(arguments) => Operation::DeleteProfile {
            name: arguments.name,
        },
        ProfileCommand::Unload(arguments) => Operation::UnloadProfile {
            name: arguments.name,
        },
        ProfileCommand::Export(_)
        | ProfileCommand::Import(_)
        | ProfileCommand::ImportEnv(_)
        | ProfileCommand::ExportEnv(_)
        | ProfileCommand::Load(_) => unreachable!("handled above"),
    };
    let is_list = matches!(&operation, Operation::ListProfiles);
    let show_name = match &operation {
        Operation::ShowProfile { name } => Some(name.clone()),
        _ => None,
    };
    match client::request(operation) {
        Ok(Reply::Profile(profile)) => print_profiles(output, &[profile], &[]),
        Ok(Reply::Profiles(profiles)) if is_list => {
            let help: &[&str] = if profiles.is_empty() {
                &["Run `envault profile create \"<name>\"` to add a profile"]
            } else {
                &["Run `envault profile show \"<name>\"` to see full details"]
            };
            print_profiles(output, &profiles, help)
        }
        Ok(Reply::Profiles(profiles)) => print_profiles(output, &profiles, &[]),
        Ok(Reply::Acknowledged { no_op }) => {
            print_acknowledgement(output, "profile_deleted", no_op)
        }
        Ok(_) => print_error(output, &unexpected_response()),
        Err(ClientError::Remote(error)) if show_name.is_some() => print_error(
            output,
            &suggest_on_not_found(error, &show_name.unwrap(), &profile_names()),
        ),
        Err(error) => print_error(output, &client_error(error)),
    }
}

fn profile_load(output: Output, arguments: ProfileLoadArgs) -> ExitCode {
    let Some(secret) = arguments.secret else {
        return match client::request(Operation::LoadProfile {
            name: arguments.name,
        }) {
            Ok(Reply::Profile(profile)) => print_profiles(output, &[profile], &[]),
            Ok(_) => print_error(output, &unexpected_response()),
            Err(error) => print_error(output, &client_error(error)),
        };
    };
    let Some(host) = arguments.host else {
        return print_error(
            output,
            &input_error(
                "http_access_requires_host",
                "`--secret` requires an exact `--host`",
            ),
        );
    };
    if arguments.method.is_empty() {
        return print_error(
            output,
            &input_error(
                "http_access_requires_method",
                "`--secret` requires at least one `--method`",
            ),
        );
    }
    let constraint = HttpConstraint {
        host,
        port: arguments.port,
        methods: arguments.method.iter().copied().map(http_method).collect(),
        path_prefix: arguments.path_prefix,
        max_request_bytes: arguments.max_request_bytes,
        max_response_bytes: arguments.max_response_bytes,
    };
    set_secret_http_access(
        output,
        arguments.name,
        secret,
        constraint,
        arguments.password_stdin,
    )
}

/// Tries the admin-gated grant against the caller's active admin lease
/// first. If none is active, prompts inline for the master password (or
/// reads it from `--password-stdin`) and retries as a one-shot call that
/// proves identity for just this request, instead of forcing a separate
/// `envault admin unlock` round trip first.
fn set_secret_http_access(
    output: Output,
    profile: String,
    name: String,
    constraint: HttpConstraint,
    password_stdin: bool,
) -> ExitCode {
    match client::request(Operation::SetSecretHttpAccess {
        profile: profile.clone(),
        name: name.clone(),
        constraint: constraint.clone(),
        password: None,
    }) {
        Ok(Reply::Acknowledged { no_op }) => {
            print_acknowledgement(output, "http_access_set", no_op)
        }
        Ok(_) => print_error(output, &unexpected_response()),
        Err(ClientError::Remote(error)) if error.code == "admin_auth_required" => {
            let password = match read_master_password(password_stdin, false) {
                Ok(password) => password,
                Err(error) => return print_error(output, &error),
            };
            match client::request(Operation::SetSecretHttpAccess {
                profile,
                name,
                constraint,
                password: Some(password),
            }) {
                Ok(Reply::Acknowledged { no_op }) => {
                    print_acknowledgement(output, "http_access_set", no_op)
                }
                Ok(_) => print_error(output, &unexpected_response()),
                Err(error) => print_error(output, &client_error(error)),
            }
        }
        Err(error) => print_error(output, &client_error(error)),
    }
}

#[derive(Debug, Serialize)]
struct LoadSummary {
    loaded: Vec<ProfileView>,
    unloaded: Vec<String>,
}

impl JsonPrintable for LoadSummary {}

fn print_load_summary(output: Output, summary: &LoadSummary) -> ExitCode {
    match output {
        Output::Json => {
            print_json(summary);
            ExitCode::SUCCESS
        }
        Output::Toon => {
            print_profiles(output, &summary.loaded, &[]);
            println!("unloaded[{}]{{name}}:", summary.unloaded.len());
            for name in &summary.unloaded {
                println!("  {}", toon_string(name));
            }
            ExitCode::SUCCESS
        }
        Output::Human => {
            print_profiles(output, &summary.loaded, &[]);
            if !summary.unloaded.is_empty() {
                println!("unloaded: {}", summary.unloaded.join(", "));
            }
            ExitCode::SUCCESS
        }
    }
}

#[derive(Debug, Serialize)]
struct UnloadSummary {
    unloaded: Vec<String>,
}

impl JsonPrintable for UnloadSummary {}

fn print_unload_summary(output: Output, summary: &UnloadSummary) -> ExitCode {
    match output {
        Output::Json => print_json(summary),
        Output::Toon => {
            println!("unloaded[{}]{{name}}:", summary.unloaded.len());
            for name in &summary.unloaded {
                println!("  {}", toon_string(name));
            }
        }
        Output::Human if summary.unloaded.is_empty() => {
            println!("status: project_unloaded (no-op)");
        }
        Output::Human => println!("unloaded: {}", summary.unloaded.join(", ")),
    }
    ExitCode::SUCCESS
}

/// Reads `.envault.toml` from the current directory and loads every profile
/// and workspace it lists, then unloads whatever this same project directory
/// had auto-loaded on a previous `envault load` that is no longer listed.
/// Only profiles this mechanism itself loaded are ever candidates for
/// unloading - profiles the user loaded some other way are left alone. To
/// tell the two apart, each profile's loaded state is checked before this
/// call loads it: a profile already loaded that this project did not
/// previously track as its own is someone else's and is left out of the
/// tracked set, even though loading it here is still requested and shown.
fn load_manifest_profiles(
    output: Output,
    names: Vec<String>,
    previous: &project::ProjectLoadState,
    loaded: &mut Vec<ProfileView>,
    seen: &mut HashSet<String>,
    effective: &mut HashSet<String>,
) -> Result<(), ExitCode> {
    for name in names {
        let was_loaded_before = match client::request(Operation::ShowProfile { name: name.clone() })
        {
            Ok(Reply::Profile(profile)) => profile.loaded,
            Ok(_) => return Err(print_error(output, &unexpected_response())),
            Err(error) => return Err(print_error(output, &client_error(error))),
        };
        match client::request(Operation::LoadProfile { name }) {
            Ok(Reply::Profile(profile)) => {
                if !was_loaded_before || previous.effective_profiles.contains(&profile.name) {
                    effective.insert(profile.name.clone());
                }
                if seen.insert(profile.name.clone()) {
                    loaded.push(profile);
                }
            }
            Ok(_) => return Err(print_error(output, &unexpected_response())),
            Err(error) => return Err(print_error(output, &client_error(error))),
        }
    }
    Ok(())
}

fn load_manifest_workspaces(
    output: Output,
    names: Vec<String>,
    previous: &project::ProjectLoadState,
    loaded: &mut Vec<ProfileView>,
    seen: &mut HashSet<String>,
    effective: &mut HashSet<String>,
) -> Result<(), ExitCode> {
    for name in names {
        let already_loaded: HashSet<String> =
            match client::request(Operation::ShowWorkspace { name: name.clone() }) {
                Ok(Reply::WorkspaceProfiles(profiles)) => profiles
                    .into_iter()
                    .filter(|profile| profile.loaded)
                    .map(|profile| profile.name)
                    .collect(),
                Ok(_) => return Err(print_error(output, &unexpected_response())),
                Err(error) => return Err(print_error(output, &client_error(error))),
            };
        match client::request(Operation::LoadWorkspace { name }) {
            Ok(Reply::WorkspaceProfiles(profiles)) => {
                for profile in profiles {
                    if !already_loaded.contains(&profile.name)
                        || previous.effective_profiles.contains(&profile.name)
                    {
                        effective.insert(profile.name.clone());
                    }
                    if seen.insert(profile.name.clone()) {
                        loaded.push(profile);
                    }
                }
            }
            Ok(_) => return Err(print_error(output, &unexpected_response())),
            Err(error) => return Err(print_error(output, &client_error(error))),
        }
    }
    Ok(())
}

fn cmd_load(output: Output) -> ExitCode {
    let cwd = match env::current_dir() {
        Ok(cwd) => cwd,
        Err(error) => {
            return print_error(
                output,
                &input_error(
                    "io_error",
                    &format!("Failed to resolve current directory: {error}"),
                ),
            );
        }
    };
    let manifest = match project::load_manifest(&cwd) {
        Ok(manifest) => manifest,
        Err(error) => return print_error(output, &error),
    };
    let project_key = match project::project_key(&cwd) {
        Ok(key) => key,
        Err(error) => return print_error(output, &error),
    };
    let mut state = match project::read_state() {
        Ok(state) => state,
        Err(error) => return print_error(output, &error),
    };
    let previous = state.remove(&project_key).unwrap_or_default();

    let mut loaded = Vec::new();
    let mut seen = HashSet::new();
    let mut effective = HashSet::new();
    if let Err(code) = load_manifest_profiles(
        output,
        manifest.profiles,
        &previous,
        &mut loaded,
        &mut seen,
        &mut effective,
    ) {
        return code;
    }
    if let Err(code) = load_manifest_workspaces(
        output,
        manifest.workspaces,
        &previous,
        &mut loaded,
        &mut seen,
        &mut effective,
    ) {
        return code;
    }

    let mut unloaded = Vec::new();
    for name in previous.effective_profiles {
        if effective.contains(&name) {
            continue;
        }
        match client::request(Operation::UnloadProfile { name: name.clone() }) {
            Ok(Reply::Profile(_)) => unloaded.push(name),
            Ok(_) => return print_error(output, &unexpected_response()),
            Err(error) => {
                let error = client_error(error);
                if error.code != "not_found" {
                    return print_error(output, &error);
                }
            }
        }
    }

    let mut effective_profiles: Vec<String> = effective.into_iter().collect();
    effective_profiles.sort();
    state.insert(
        project_key,
        project::ProjectLoadState { effective_profiles },
    );
    if let Err(error) = project::write_state(&state) {
        return print_error(output, &error);
    }

    print_load_summary(output, &LoadSummary { loaded, unloaded })
}

/// Unloads everything `envault load` previously auto-loaded for the current
/// directory's project path and clears its tracked state. A no-op (not an
/// error) when this project has no tracked auto-loaded profiles.
fn cmd_unload(output: Output) -> ExitCode {
    let cwd = match env::current_dir() {
        Ok(cwd) => cwd,
        Err(error) => {
            return print_error(
                output,
                &input_error(
                    "io_error",
                    &format!("Failed to resolve current directory: {error}"),
                ),
            );
        }
    };
    let project_key = match project::project_key(&cwd) {
        Ok(key) => key,
        Err(error) => return print_error(output, &error),
    };
    let mut state = match project::read_state() {
        Ok(state) => state,
        Err(error) => return print_error(output, &error),
    };
    let Some(previous) = state.remove(&project_key) else {
        return print_unload_summary(
            output,
            &UnloadSummary {
                unloaded: Vec::new(),
            },
        );
    };
    for name in &previous.effective_profiles {
        match client::request(Operation::UnloadProfile { name: name.clone() }) {
            Ok(Reply::Profile(_)) => {}
            Ok(_) => return print_error(output, &unexpected_response()),
            Err(error) => {
                let error = client_error(error);
                if error.code != "not_found" {
                    return print_error(output, &error);
                }
            }
        }
    }
    if let Err(error) = project::write_state(&state) {
        return print_error(output, &error);
    }
    print_unload_summary(
        output,
        &UnloadSummary {
            unloaded: previous.effective_profiles,
        },
    )
}

fn portability_command(output: Output, command: PortabilityCommand) -> ExitCode {
    match command {
        PortabilityCommand::Export(arguments) => export_package(
            output,
            PackageKind::Workspace,
            None,
            &arguments.output_file,
            arguments.password,
            arguments.age_recipients,
        ),
        PortabilityCommand::Import(arguments) => import_workspace_package(output, arguments),
    }
}

fn workspace_command(output: Output, command: WorkspaceCommand) -> ExitCode {
    match command {
        WorkspaceCommand::Create(arguments) => {
            match client::request(Operation::CreateWorkspace {
                name: arguments.name,
            }) {
                Ok(Reply::Workspace(scope)) => print_workspace_scope(output, &scope),
                Ok(_) => print_error(output, &unexpected_response()),
                Err(error) => print_error(output, &client_error(error)),
            }
        }
        WorkspaceCommand::List => match client::request(Operation::ListWorkspaces) {
            Ok(Reply::Workspaces(scopes)) => {
                for scope in &scopes {
                    print_workspace_scope(output, scope);
                }
                ExitCode::SUCCESS
            }
            Ok(_) => print_error(output, &unexpected_response()),
            Err(error) => print_error(output, &client_error(error)),
        },
        WorkspaceCommand::Show(arguments) => {
            match client::request(Operation::ShowWorkspace {
                name: arguments.name,
            }) {
                Ok(Reply::WorkspaceProfiles(profiles)) => print_profiles(output, &profiles, &[]),
                Ok(_) => print_error(output, &unexpected_response()),
                Err(error) => print_error(output, &client_error(error)),
            }
        }
        WorkspaceCommand::Load(arguments) => {
            match client::request(Operation::LoadWorkspace {
                name: arguments.name,
            }) {
                Ok(Reply::WorkspaceProfiles(profiles)) => print_profiles(output, &profiles, &[]),
                Ok(_) => print_error(output, &unexpected_response()),
                Err(error) => print_error(output, &client_error(error)),
            }
        }
        WorkspaceCommand::Bind(arguments) => {
            match client::request(Operation::BindProfileToWorkspace {
                workspace: arguments.workspace,
                profile: arguments.profile,
            }) {
                Ok(Reply::Acknowledged { no_op }) => {
                    print_acknowledgement(output, "workspace_profile_bound", no_op)
                }
                Ok(_) => print_error(output, &unexpected_response()),
                Err(error) => print_error(output, &client_error(error)),
            }
        }
        WorkspaceCommand::Unbind(arguments) => {
            match client::request(Operation::UnbindProfileFromWorkspace {
                workspace: arguments.workspace,
                profile: arguments.profile,
            }) {
                Ok(Reply::Acknowledged { no_op }) => {
                    print_acknowledgement(output, "workspace_profile_unbound", no_op)
                }
                Ok(_) => print_error(output, &unexpected_response()),
                Err(error) => print_error(output, &client_error(error)),
            }
        }
        WorkspaceCommand::Delete(arguments) => {
            match client::request(Operation::DeleteWorkspace {
                name: arguments.name,
            }) {
                Ok(Reply::Acknowledged { no_op }) => {
                    print_acknowledgement(output, "workspace_deleted", no_op)
                }
                Ok(_) => print_error(output, &unexpected_response()),
                Err(error) => print_error(output, &client_error(error)),
            }
        }
    }
}

fn print_workspace_scope(output: Output, workspace: &WorkspaceView) -> ExitCode {
    match output {
        Output::Human => println!("workspace: {} · id: {}", workspace.name, workspace.id.0),
        Output::Json => println!(
            "{}",
            serde_json::json!({ "name": workspace.name, "id": workspace.id.0.to_string() })
        ),
        Output::Toon => println!(
            "workspace{{name,id}}: {},{}",
            workspace.name, workspace.id.0
        ),
    }
    ExitCode::SUCCESS
}

fn build_export_request(
    kind: PackageKind,
    profile_name: Option<String>,
    output_file: &Path,
    password_arguments: TransferPasswordArgs,
    age_recipients: Vec<String>,
) -> Result<Operation, StructuredError> {
    let transfer_password = read_optional_transfer_password(password_arguments, true)?;
    if transfer_password.is_none() && age_recipients.is_empty() {
        return Err(input_error(
            "package_credential_required",
            "choose a transfer password or at least one age recipient",
        ));
    }
    let output_path = protocol_path(output_file)?;
    Ok(Operation::ExportPackage {
        kind,
        profile_name,
        output_path,
        transfer_password,
        age_recipients,
    })
}

fn export_package(
    output: Output,
    kind: PackageKind,
    profile_name: Option<String>,
    output_file: &Path,
    password_arguments: TransferPasswordArgs,
    age_recipients: Vec<String>,
) -> ExitCode {
    let operation = match build_export_request(
        kind,
        profile_name,
        output_file,
        password_arguments,
        age_recipients,
    ) {
        Ok(operation) => operation,
        Err(error) => return print_error(output, &error),
    };
    match client::request(operation) {
        Ok(Reply::PortabilityExport(summary)) => print_portability_export(output, &summary),
        Ok(_) => print_error(output, &unexpected_response()),
        Err(error) => print_error(output, &client_error(error)),
    }
}

fn import_profile_package(output: Output, arguments: ProfilePackageImportArgs) -> ExitCode {
    import_package(
        output,
        PackageImportRequest {
            expected_kind: PackageKind::Profile,
            input_file: arguments.input_file,
            password: arguments.password,
            age_identity: arguments.age_identity,
            strategy: import_profile_strategy(arguments.strategy),
            rename_to: arguments.rename_to,
            commit: arguments.commit,
            plan_hash: arguments.plan_hash,
        },
    )
}

fn import_workspace_package(output: Output, arguments: WorkspacePackageImportArgs) -> ExitCode {
    import_package(
        output,
        PackageImportRequest {
            expected_kind: PackageKind::Workspace,
            input_file: arguments.input_file,
            password: arguments.password,
            age_identity: arguments.age_identity,
            strategy: import_workspace_strategy(arguments.strategy),
            rename_to: None,
            commit: arguments.commit,
            plan_hash: arguments.plan_hash,
        },
    )
}

fn import_package(output: Output, request: PackageImportRequest) -> ExitCode {
    let transfer_password = match read_optional_transfer_password(request.password, false) {
        Ok(password) => password,
        Err(error) => return print_error(output, &error),
    };
    if transfer_password.is_none() && request.age_identity.is_none() {
        return print_error(
            output,
            &input_error(
                "package_credential_required",
                "choose a transfer password or an age identity file",
            ),
        );
    }
    let input_path = match protocol_path(&request.input_file) {
        Ok(path) => path,
        Err(error) => return print_error(output, &error),
    };
    let age_identity_path = match request
        .age_identity
        .as_deref()
        .map(protocol_path)
        .transpose()
    {
        Ok(path) => path,
        Err(error) => return print_error(output, &error),
    };
    let operation = if request.commit {
        Operation::CommitPackageImport {
            expected_kind: request.expected_kind,
            input_path,
            transfer_password,
            age_identity_path,
            strategy: request.strategy,
            rename_to: request.rename_to,
            expected_plan_hash: request
                .plan_hash
                .expect("clap requires a plan hash for commit"),
        }
    } else {
        Operation::PreviewPackageImport {
            expected_kind: request.expected_kind,
            input_path,
            transfer_password,
            age_identity_path,
            strategy: request.strategy,
            rename_to: request.rename_to,
        }
    };
    match client::request(operation) {
        Ok(Reply::PortabilityPreview(preview)) => print_portability_preview(output, &preview),
        Ok(Reply::PortabilityImport(summary)) => print_portability_import(output, &summary),
        Ok(_) => print_error(output, &unexpected_response()),
        Err(error) => print_error(output, &client_error(error)),
    }
}

fn import_env(output: Output, arguments: EnvImportArgs) -> ExitCode {
    let input_path = match protocol_path(&arguments.input_file) {
        Ok(path) => path,
        Err(error) => return print_error(output, &error),
    };
    let strategy = import_env_strategy(arguments.strategy);
    let operation = if arguments.commit {
        Operation::CommitEnvImport {
            profile_name: arguments.name,
            input_path,
            strategy,
            expected_plan_hash: arguments
                .plan_hash
                .expect("clap requires a plan hash for commit"),
        }
    } else {
        Operation::PreviewEnvImport {
            profile_name: arguments.name,
            input_path,
            strategy,
        }
    };
    match client::request(operation) {
        Ok(Reply::EnvImportPreview(preview)) => print_env_import_preview(output, &preview),
        Ok(Reply::PortabilityImport(summary)) => print_portability_import(output, &summary),
        Ok(_) => print_error(output, &unexpected_response()),
        Err(error) => print_error(output, &client_error(error)),
    }
}

fn export_plaintext_env(output: Output, arguments: PlaintextExportArgs) -> ExitCode {
    let output_path = match protocol_path(&arguments.output_file) {
        Ok(path) => path,
        Err(error) => return print_error(output, &error),
    };
    match client::request(Operation::ExportPlaintextEnv {
        profile_name: arguments.name,
        output_path,
        allow_plaintext: arguments.allow_plaintext,
    }) {
        Ok(Reply::PlaintextExport(summary)) => print_plaintext_export(output, &summary),
        Ok(_) => print_error(output, &unexpected_response()),
        Err(error) => print_error(output, &client_error(error)),
    }
}

fn config_command(output: Output, command: ConfigCommand) -> ExitCode {
    match command {
        ConfigCommand::Export(arguments) => export_config(output, arguments),
        ConfigCommand::Import(arguments) => import_config(output, arguments),
    }
}

fn default_config_file_name(format: ConfigFormatArg, kind: ConfigKindArg) -> &'static str {
    match format {
        ConfigFormatArg::Yaml => "export.yml",
        ConfigFormatArg::Env => "export.env",
        ConfigFormatArg::Encrypted => match kind {
            ConfigKindArg::Vault | ConfigKindArg::Workspace => "export.envault-workspace",
            ConfigKindArg::Profile => "export.envault-profile",
        },
    }
}

fn export_config(output: Output, arguments: ConfigExportArgs) -> ExitCode {
    let output_file =
        arguments
            .output_dir
            .join(arguments.file_name.clone().unwrap_or_else(|| {
                default_config_file_name(arguments.format, arguments.kind).to_owned()
            }));
    match arguments.format {
        ConfigFormatArg::Yaml => export_config_yaml(output, &arguments, &output_file),
        ConfigFormatArg::Env => export_config_env(output, &arguments, &output_file),
        ConfigFormatArg::Encrypted => export_config_encrypted(output, arguments, &output_file),
    }
}

fn export_config_yaml(
    output: Output,
    arguments: &ConfigExportArgs,
    output_file: &Path,
) -> ExitCode {
    let selector = match arguments.kind {
        ConfigKindArg::Vault => {
            if !arguments.names.is_empty() {
                return print_error(
                    output,
                    &input_error(
                        "invalid_input",
                        "--name is not accepted with `--kind vault`",
                    ),
                );
            }
            ConfigSelector::Vault
        }
        ConfigKindArg::Profile => {
            if arguments.names.is_empty() {
                return print_error(
                    output,
                    &input_error(
                        "invalid_input",
                        "`--kind profile` requires at least one `--name`",
                    ),
                );
            }
            ConfigSelector::Profiles(arguments.names.clone())
        }
        ConfigKindArg::Workspace => {
            if arguments.names.is_empty() {
                return print_error(
                    output,
                    &input_error(
                        "invalid_input",
                        "`--kind workspace` requires at least one `--name`",
                    ),
                );
            }
            ConfigSelector::Workspaces(arguments.names.clone())
        }
    };
    let output_path = match protocol_path(output_file) {
        Ok(path) => path,
        Err(error) => return print_error(output, &error),
    };
    match client::request(Operation::ExportConfig {
        selector,
        format: ConfigFormat::Yaml,
        output_path,
    }) {
        Ok(Reply::PortabilityExport(summary)) => print_portability_export(output, &summary),
        Ok(_) => print_error(output, &unexpected_response()),
        Err(error) => print_error(output, &client_error(error)),
    }
}

fn export_config_env(output: Output, arguments: &ConfigExportArgs, output_file: &Path) -> ExitCode {
    if arguments.kind != ConfigKindArg::Profile && arguments.kind != ConfigKindArg::Vault {
        return print_error(
            output,
            &input_error(
                "invalid_input",
                "`--format env` requires `--kind profile` (a flat .env file holds exactly one profile)",
            ),
        );
    }
    let [name] = arguments.names.as_slice() else {
        return print_error(
            output,
            &input_error(
                "invalid_input",
                "`--format env` requires exactly one `--name`",
            ),
        );
    };
    let output_path = match protocol_path(output_file) {
        Ok(path) => path,
        Err(error) => return print_error(output, &error),
    };
    match client::request(Operation::ExportPlaintextEnv {
        profile_name: name.clone(),
        output_path,
        allow_plaintext: true,
    }) {
        Ok(Reply::PlaintextExport(summary)) => print_plaintext_export(output, &summary),
        Ok(_) => print_error(output, &unexpected_response()),
        Err(error) => print_error(output, &client_error(error)),
    }
}

fn export_config_encrypted(
    output: Output,
    arguments: ConfigExportArgs,
    output_file: &Path,
) -> ExitCode {
    let (kind, profile_name) = match arguments.kind {
        ConfigKindArg::Vault => (PackageKind::Workspace, None),
        ConfigKindArg::Profile => {
            let [name] = arguments.names.as_slice() else {
                return print_error(
                    output,
                    &input_error(
                        "invalid_input",
                        "`--format encrypted --kind profile` requires exactly one `--name`",
                    ),
                );
            };
            (PackageKind::Profile, Some(name.clone()))
        }
        ConfigKindArg::Workspace => {
            return print_error(
                output,
                &input_error(
                    "invalid_input",
                    "`--format encrypted` does not support `--kind workspace`; use `--kind vault` for the whole encrypted vault package",
                ),
            );
        }
    };
    export_package(
        output,
        kind,
        profile_name,
        output_file,
        arguments.password,
        arguments.age_recipients,
    )
}

fn config_import_strategy(strategy: ConfigConflictStrategyArg) -> ImportConflictStrategy {
    match strategy {
        ConfigConflictStrategyArg::Abort => ImportConflictStrategy::Abort,
        ConfigConflictStrategyArg::Skip => ImportConflictStrategy::Skip,
        ConfigConflictStrategyArg::Replace => ImportConflictStrategy::Replace,
        ConfigConflictStrategyArg::Rename => ImportConflictStrategy::Rename,
    }
}

fn import_config(output: Output, arguments: ConfigImportArgs) -> ExitCode {
    let strategy = config_import_strategy(arguments.strategy);
    match arguments.format {
        ConfigFormatArg::Yaml => import_config_yaml(output, arguments, strategy),
        ConfigFormatArg::Env => import_config_env(output, arguments, strategy),
        ConfigFormatArg::Encrypted => import_config_encrypted(output, arguments, strategy),
    }
}

fn import_config_yaml(
    output: Output,
    arguments: ConfigImportArgs,
    strategy: ImportConflictStrategy,
) -> ExitCode {
    if !matches!(
        strategy,
        ImportConflictStrategy::Abort
            | ImportConflictStrategy::Skip
            | ImportConflictStrategy::Replace
    ) {
        return print_error(
            output,
            &input_error(
                "invalid_input",
                "`--format yaml` does not support `--strategy rename`",
            ),
        );
    }
    let input_path = match protocol_path(&arguments.input_file) {
        Ok(path) => path,
        Err(error) => return print_error(output, &error),
    };
    let operation = if arguments.commit {
        Operation::CommitConfigImport {
            format: ConfigFormat::Yaml,
            input_path,
            strategy,
            expected_plan_hash: arguments
                .plan_hash
                .expect("clap requires a plan hash for commit"),
        }
    } else {
        Operation::PreviewConfigImport {
            format: ConfigFormat::Yaml,
            input_path,
            strategy,
        }
    };
    match client::request(operation) {
        Ok(Reply::ConfigPlan(preview)) => print_config_preview(output, &preview),
        Ok(Reply::PortabilityImport(summary)) => print_portability_import(output, &summary),
        Ok(_) => print_error(output, &unexpected_response()),
        Err(error) => print_error(output, &client_error(error)),
    }
}

fn import_config_env(
    output: Output,
    arguments: ConfigImportArgs,
    strategy: ImportConflictStrategy,
) -> ExitCode {
    if !matches!(
        strategy,
        ImportConflictStrategy::Abort
            | ImportConflictStrategy::Skip
            | ImportConflictStrategy::Replace
    ) {
        return print_error(
            output,
            &input_error(
                "invalid_input",
                "`--format env` does not support `--strategy rename`",
            ),
        );
    }
    let [name] = arguments.names.as_slice() else {
        return print_error(
            output,
            &input_error(
                "invalid_input",
                "`--format env` requires exactly one `--name`",
            ),
        );
    };
    let name = name.clone();
    import_env(
        output,
        EnvImportArgs {
            name,
            input_file: arguments.input_file,
            strategy: match strategy {
                ImportConflictStrategy::Abort => EnvConflictStrategyArg::Abort,
                ImportConflictStrategy::Skip => EnvConflictStrategyArg::Skip,
                ImportConflictStrategy::Replace => EnvConflictStrategyArg::Replace,
                ImportConflictStrategy::Rename => unreachable!("rejected above"),
            },
            commit: arguments.commit,
            plan_hash: arguments.plan_hash,
        },
    )
}

fn import_config_encrypted(
    output: Output,
    arguments: ConfigImportArgs,
    strategy: ImportConflictStrategy,
) -> ExitCode {
    match arguments.kind {
        ConfigKindArg::Vault => import_package(
            output,
            PackageImportRequest {
                expected_kind: PackageKind::Workspace,
                input_file: arguments.input_file,
                password: arguments.password,
                age_identity: arguments.age_identity,
                strategy: import_workspace_strategy(match strategy {
                    ImportConflictStrategy::Abort => WorkspaceConflictStrategyArg::Abort,
                    ImportConflictStrategy::Replace => WorkspaceConflictStrategyArg::Replace,
                    ImportConflictStrategy::Skip | ImportConflictStrategy::Rename => {
                        return print_error(
                            output,
                            &input_error(
                                "invalid_input",
                                "`--format encrypted --kind vault` only supports `--strategy abort|replace`",
                            ),
                        );
                    }
                }),
                rename_to: None,
                commit: arguments.commit,
                plan_hash: arguments.plan_hash,
            },
        ),
        ConfigKindArg::Profile => import_package(
            output,
            PackageImportRequest {
                expected_kind: PackageKind::Profile,
                input_file: arguments.input_file,
                password: arguments.password,
                age_identity: arguments.age_identity,
                strategy,
                rename_to: arguments.rename_to,
                commit: arguments.commit,
                plan_hash: arguments.plan_hash,
            },
        ),
        ConfigKindArg::Workspace => print_error(
            output,
            &input_error(
                "invalid_input",
                "`--format encrypted` does not support `--kind workspace`; use `--kind vault` for the whole encrypted vault package",
            ),
        ),
    }
}

fn print_config_preview(output: Output, preview: &ConfigPreview) -> ExitCode {
    match output {
        Output::Human => {
            println!(
                "config import: preview · profiles: {} · secrets: {} · workspaces: {} · memberships: {} · strategy: {:?}",
                preview.counts.profiles,
                preview.counts.secrets,
                preview.counts.workspaces,
                preview.counts.memberships,
                preview.strategy
            );
            for entry in &preview.profiles {
                println!("profile: {} · action: {:?}", entry.name, entry.action);
            }
            for entry in &preview.secrets {
                println!(
                    "secret: {}.{} · action: {:?}",
                    entry.profile, entry.name, entry.action
                );
            }
            for entry in &preview.workspaces {
                println!("workspace: {} · action: {:?}", entry.name, entry.action);
            }
            for entry in &preview.memberships {
                println!(
                    "membership: {}.{} · action: {:?}",
                    entry.workspace, entry.profile, entry.action
                );
            }
            println!("plan_hash: {}", preview.plan_hash);
            println!(
                "commit: repeat the command with `--commit --plan-hash {}`",
                preview.plan_hash
            );
            for warning in &preview.warnings {
                println!("warning: {warning}");
            }
        }
        Output::Json => print_json(preview),
        Output::Toon => {
            println!(
                "config_import{{status,profiles,secrets,workspaces,memberships,strategy,plan_hash}}: preview,{},{},{},{},{:?},{}",
                preview.counts.profiles,
                preview.counts.secrets,
                preview.counts.workspaces,
                preview.counts.memberships,
                preview.strategy,
                preview.plan_hash
            );
            for entry in &preview.profiles {
                println!(
                    "profile{{name,action}}: {},{:?}",
                    toon_string(&entry.name),
                    entry.action
                );
            }
            for entry in &preview.secrets {
                println!(
                    "secret{{profile,name,action}}: {},{},{:?}",
                    toon_string(&entry.profile),
                    toon_string(&entry.name),
                    entry.action
                );
            }
            for entry in &preview.workspaces {
                println!(
                    "workspace{{name,action}}: {},{:?}",
                    toon_string(&entry.name),
                    entry.action
                );
            }
            for entry in &preview.memberships {
                println!(
                    "membership{{workspace,profile,action}}: {},{},{:?}",
                    toon_string(&entry.workspace),
                    toon_string(&entry.profile),
                    entry.action
                );
            }
        }
    }
    ExitCode::SUCCESS
}

/// No arm here may issue `Operation::RevealSecretValue` or print a
/// `Reply::SecretPlaintext` - that path is reserved for the TUI's
/// admin-gated `Reveal` action. `no_cli_subcommand_is_named_or_aliased_reveal`
/// guards the CLI surface for this; keep it in mind before adding a "show
/// value" style subcommand here.
fn secret_command(output: Output, command: SecretCommand) -> ExitCode {
    match command {
        SecretCommand::Create(arguments) => create_secret(output, arguments),
        SecretCommand::List(arguments) => list_secrets(output, &arguments),
        SecretCommand::Describe(arguments) => {
            let (profile, name) = parse_secret_ref(&arguments.name);
            match client::request(Operation::DescribeSecret {
                profile: profile.clone(),
                name: name.clone(),
            }) {
                Ok(Reply::Secret(secret)) => print_secrets(output, &[secret], &[]),
                Ok(_) => print_error(output, &unexpected_response()),
                Err(ClientError::Remote(error)) => print_error(
                    output,
                    &suggest_on_not_found(error, &name, &secret_names_in_profile(&profile)),
                ),
                Err(error) => print_error(output, &client_error(error)),
            }
        }
        SecretCommand::Update(arguments) => {
            let (profile, name) = parse_secret_ref(&arguments.name);
            request_secret(
                output,
                Operation::UpdateSecret {
                    profile,
                    name,
                    description: arguments.description,
                },
            )
        }
        SecretCommand::Rename(arguments) => {
            let (profile, old_name) = parse_secret_ref(&arguments.old_name);
            let (_, new_name) = parse_secret_ref(&arguments.new_name);
            request_secret(
                output,
                Operation::RenameSecret {
                    profile,
                    old_name,
                    new_name,
                },
            )
        }
        SecretCommand::Delete(arguments) => {
            let (profile, name) = parse_secret_ref(&arguments.name);
            lifecycle_request(
                output,
                Operation::DeleteSecret { profile, name },
                "secret_deleted",
            )
        }
        SecretCommand::Value { command } => secret_value_command(output, command),
    }
}

fn create_secret(output: Output, arguments: SecretCreateArgs) -> ExitCode {
    let (profile, name) = parse_secret_ref(&arguments.name);
    let operation = if let Some(format) = arguments.generate {
        let generator = match generator_spec(format, arguments.length) {
            Ok(generator) => generator,
            Err(error) => return print_error(output, &error),
        };
        Operation::CreateGeneratedSecret {
            profile,
            name,
            description: arguments.description,
            generator,
        }
    } else {
        // Neither `--stdin` nor `--generate`: `--stdin` only ever changes
        // whether a non-interactive terminal is rejected, since
        // `read_secret_value_interactive` already reads piped input the same
        // way `--stdin` does.
        let value = match read_secret_value_interactive() {
            Ok(value) => value,
            Err(error) => return print_error(output, &error),
        };
        Operation::CreateSecret {
            profile,
            name,
            description: arguments.description,
            value,
        }
    };
    request_secret(output, operation)
}

const SECRET_LIST_SUPPORTED_FIELDS: &[&str] = &["description"];

fn list_secrets(output: Output, arguments: &SecretListArgs) -> ExitCode {
    if let Some(field) = arguments
        .fields
        .iter()
        .find(|field| !SECRET_LIST_SUPPORTED_FIELDS.contains(&field.as_str()))
    {
        return print_error(
            output,
            &input_error(
                "unknown_field",
                &format!(
                    "unknown field `{field}` for `secret list`; supported fields: {}",
                    SECRET_LIST_SUPPORTED_FIELDS.join(", ")
                ),
            ),
        );
    }
    let include_description =
        arguments.describe || arguments.fields.iter().any(|field| field == "description");
    if let Some(profile) = &arguments.profile {
        return match client::request(Operation::ListResolvedSecrets {
            profile: profile.clone(),
        }) {
            Ok(Reply::ResolvedSecrets(resolved)) => {
                let mut secrets: Vec<SecretView> =
                    resolved.into_iter().map(|entry| entry.secret).collect();
                if !include_description {
                    for secret in &mut secrets {
                        secret.description = None;
                    }
                }
                let help: &[&str] = if secrets.is_empty() {
                    &["Run `envault secret create \"<profile>.<name>\" --stdin` to add a secret"]
                } else {
                    &["Run `envault secret describe \"<name>\"` to see full details"]
                };
                print_secrets(output, &secrets, help)
            }
            Ok(_) => print_error(output, &unexpected_response()),
            Err(error) => print_error(output, &client_error(error)),
        };
    }
    let result = client::request(Operation::ListSecrets);
    match result {
        Ok(Reply::Secrets(mut secrets)) => {
            if !include_description {
                for secret in &mut secrets {
                    secret.description = None;
                }
            }
            let help: &[&str] = if secrets.is_empty() {
                &["Run `envault secret create \"<name>\" --stdin` to add a secret"]
            } else {
                &["Run `envault secret describe \"<name>\"` to see full details"]
            };
            print_secrets(output, &secrets, help)
        }
        Ok(_) => print_error(output, &unexpected_response()),
        Err(error) => print_error(output, &client_error(error)),
    }
}

/// Same constraint as `secret_command`: no arm here may issue
/// `Operation::RevealSecretValue` or print plaintext.
fn secret_value_command(output: Output, command: SecretValueCommand) -> ExitCode {
    let operation = match command {
        SecretValueCommand::Set(arguments) => {
            let value = match read_secret_value() {
                Ok(value) => value,
                Err(error) => return print_error(output, &error),
            };
            let (profile, name) = parse_secret_ref(&arguments.name);
            Operation::SetSecretValue {
                profile,
                name,
                value,
            }
        }
        SecretValueCommand::Generate(arguments) => {
            let generator = match generator_spec(arguments.format, arguments.length) {
                Ok(generator) => generator,
                Err(error) => return print_error(output, &error),
            };
            let (profile, name) = parse_secret_ref(&arguments.name);
            Operation::GenerateSecretValue {
                profile,
                name,
                generator,
            }
        }
    };
    match client::request(operation) {
        Ok(Reply::SecretValueSet(value)) => print_value_set(output, &value, &[]),
        Ok(_) => print_error(output, &unexpected_response()),
        Err(error) => print_error(output, &client_error(error)),
    }
}

fn request_secret(output: Output, operation: Operation) -> ExitCode {
    match client::request(operation) {
        Ok(Reply::Secret(secret)) => print_secrets(output, &[secret], &[]),
        Ok(_) => print_error(output, &unexpected_response()),
        Err(error) => print_error(output, &client_error(error)),
    }
}

fn http_request(output: Output, arguments: HttpRequestArgs) -> ExitCode {
    let body = match arguments.body_file {
        Some(path) => match read_bounded_file(&path, envault_protocol::MAX_FRAME_BYTES / 2) {
            Ok(body) => body,
            Err(error) => return print_error(output, &error),
        },
        None => Vec::new(),
    };
    let full = arguments.full;
    let (profile, name) = parse_secret_ref(&arguments.secret);
    let request = HttpRequest {
        url: arguments.url,
        method: http_method(arguments.method),
        body,
        content_type: arguments.content_type.map(http_content_type),
    };
    match client::request(Operation::HttpRequest {
        profile,
        name,
        request,
    }) {
        Ok(Reply::HttpResponse(response)) => print_http_response(output, &response, full),
        Ok(_) => print_error(output, &unexpected_response()),
        Err(error) => print_error(output, &client_error(error)),
    }
}

/// Finds every `{{profile.NAME}}` placeholder across `tokens`, returning the
/// distinct `(profile, name)` pairs referenced. Does not mutate `tokens`.
fn find_placeholders(tokens: &[String]) -> Result<Vec<(String, String)>, String> {
    let mut refs: Vec<(String, String)> = Vec::new();
    for token in tokens {
        let mut rest = token.as_str();
        while let Some(start) = rest.find("{{") {
            let after = &rest[start + 2..];
            let Some(end) = after.find("}}") else {
                return Err(format!("unterminated `{{{{` placeholder in `{token}`"));
            };
            let inner = &after[..end];
            let invalid = || format!("placeholder `{{{{{inner}}}}}` must be `<profile>.<name>`");
            let dot = inner.find('.').ok_or_else(invalid)?;
            let (profile, name) = (&inner[..dot], &inner[dot + 1..]);
            if profile.is_empty() || name.is_empty() {
                return Err(invalid());
            }
            let reference = (profile.to_string(), name.to_string());
            if !refs.contains(&reference) {
                refs.push(reference);
            }
            rest = &after[end + 2..];
        }
    }
    Ok(refs)
}

/// Replaces every occurrence of the `{{profile.name}}` placeholder across
/// `tokens` with `replacement` (a `/dev/fd/<n>` path, never the plaintext).
fn substitute_placeholder(tokens: &mut [String], profile: &str, name: &str, replacement: &str) {
    let needle = format!("{{{{{profile}.{name}}}}}");
    for token in tokens.iter_mut() {
        if token.contains(&needle) {
            *token = token.replace(&needle, replacement);
        }
    }
}

/// Opens an anonymous pipe, spawns a thread that writes `bytes` into it and
/// closes the write end, and returns a `/dev/fd/<n>` path for the read end
/// plus the read end itself (kept open until after the child is spawned, so
/// the same fd number stays valid in the child via fork inheritance).
/// Plaintext never touches disk or argv - only this pipe.
#[cfg(unix)]
fn spawn_argv_secret_pipe(
    bytes: Zeroizing<Vec<u8>>,
) -> nix::Result<(String, std::os::fd::OwnedFd)> {
    use std::os::fd::AsRawFd;
    let (read_fd, write_fd) = nix::unistd::pipe()?;
    // Without this, the write end (never CLOEXEC by default) would also be
    // inherited by the very child we spawn, and by any other child process
    // started while it's open, leaving an extra open writer that keeps the
    // pipe from ever reaching EOF for the reader.
    nix::fcntl::fcntl(
        &write_fd,
        nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::FD_CLOEXEC),
    )?;
    let path = format!("/dev/fd/{}", read_fd.as_raw_fd());
    std::thread::spawn(move || {
        let mut remaining = bytes.as_slice();
        while !remaining.is_empty() {
            match nix::unistd::write(&write_fd, remaining) {
                Ok(0) | Err(_) => break,
                Ok(written) => remaining = &remaining[written..],
            }
        }
        drop(write_fd);
    });
    Ok((path, read_fd))
}

/// Resolves `--profile`/`--workspace` into the flat profile list `RunEnv`
/// expects. Both are optional inputs; an empty result is valid when the
/// command relies solely on `{{profile.NAME}}` placeholders instead.
fn resolve_run_profiles(
    output: Output,
    profile: Vec<String>,
    workspace: Option<String>,
) -> Result<Vec<String>, ExitCode> {
    if !profile.is_empty() {
        return Ok(profile);
    }
    let Some(workspace) = workspace else {
        return Ok(Vec::new());
    };
    match client::request(Operation::ShowWorkspace { name: workspace }) {
        Ok(Reply::WorkspaceProfiles(members)) => {
            Ok(members.into_iter().map(|profile| profile.name).collect())
        }
        Ok(_) => Err(print_error(output, &unexpected_response())),
        Err(error) => Err(print_error(output, &client_error(error))),
    }
}

/// Resolves every secret across `profiles` into `(NAME, value)` pairs ready
/// for `Command::env`. Empty `profiles` yields an empty result without a
/// round trip.
fn resolve_env_vars(
    output: Output,
    profiles: Vec<String>,
) -> Result<Vec<(String, Zeroizing<String>)>, ExitCode> {
    if profiles.is_empty() {
        return Ok(Vec::new());
    }
    let vars = match client::request(Operation::RunEnv { profiles }) {
        Ok(Reply::RunEnv(vars)) => vars,
        Ok(_) => return Err(print_error(output, &unexpected_response())),
        Err(error) => return Err(print_error(output, &client_error(error))),
    };
    let mut env_vars = Vec::with_capacity(vars.len());
    for EnvVar { name, value } in vars {
        let text = match std::str::from_utf8(value.as_slice()) {
            Ok(text) => Zeroizing::new(text.to_string()),
            Err(_) => {
                return Err(print_error(
                    output,
                    &input_error(
                        "secret_not_utf8",
                        "envault run only supports UTF-8 secret values",
                    ),
                ));
            }
        };
        env_vars.push((name.to_uppercase(), text));
    }
    Ok(env_vars)
}

#[cfg(unix)]
type PlaceholderGuards = Vec<std::os::fd::OwnedFd>;
#[cfg(not(unix))]
type PlaceholderGuards = ();

/// Resolves every `{{profile.NAME}}` placeholder found by `find_placeholders`
/// and rewrites `command_tokens` in place to reference each one's `/dev/fd`
/// path instead. The returned guards must stay alive (unused is fine) until
/// after the child is spawned, so the fd numbers stay valid through fork.
fn resolve_placeholders(
    output: Output,
    placeholders: &[(String, String)],
    command_tokens: &mut [String],
) -> Result<PlaceholderGuards, ExitCode> {
    #[cfg(not(unix))]
    {
        if !placeholders.is_empty() {
            return Err(print_error(
                output,
                &input_error(
                    "argv_placeholder_unsupported",
                    "{{profile.NAME}} placeholders in command args are not yet supported on this platform",
                ),
            ));
        }
    }
    #[cfg(unix)]
    let mut guards = Vec::with_capacity(placeholders.len());
    for (profile, name) in placeholders {
        let value = match client::request(Operation::ResolveArgvSecret {
            profile: profile.clone(),
            name: name.clone(),
        }) {
            Ok(Reply::ArgvSecret(value)) => value,
            Ok(_) => return Err(print_error(output, &unexpected_response())),
            Err(error) => return Err(print_error(output, &client_error(error))),
        };
        #[cfg(unix)]
        {
            let bytes = Zeroizing::new(value.as_slice().to_vec());
            let (path, read_fd) = match spawn_argv_secret_pipe(bytes) {
                Ok(result) => result,
                Err(error) => {
                    return Err(print_error(
                        output,
                        &input_error(
                            "argv_pipe_failed",
                            &format!("failed to create pipe for {profile}.{name}: {error}"),
                        ),
                    ));
                }
            };
            substitute_placeholder(command_tokens, profile, name, &path);
            guards.push(read_fd);
        }
    }
    #[cfg(unix)]
    return Ok(guards);
    #[cfg(not(unix))]
    Ok(())
}

/// Resolves secrets for a profile or workspace and injects them as env vars
/// into a spawned child process, and/or resolves `{{profile.NAME}}`
/// placeholders in the command's own args into `/dev/fd/<n>` paths backed
/// by an anonymous pipe. Plaintext is never printed here - it only ever
/// reaches the child process's own environment or an inherited pipe fd.
fn run_command(output: Output, arguments: RunArgs) -> ExitCode {
    let mut command_tokens = arguments.command;
    let placeholders = match find_placeholders(&command_tokens) {
        Ok(placeholders) => placeholders,
        Err(message) => return print_error(output, &input_error("invalid_placeholder", &message)),
    };
    let profiles = match resolve_run_profiles(output, arguments.profile, arguments.workspace) {
        Ok(profiles) => profiles,
        Err(exit_code) => return exit_code,
    };
    if profiles.is_empty() && placeholders.is_empty() {
        return print_error(
            output,
            &input_error(
                "run_target_required",
                "pass --profile, --workspace, or a {{profile.NAME}} placeholder in the command",
            ),
        );
    }

    let env_vars = match resolve_env_vars(output, profiles) {
        Ok(env_vars) => env_vars,
        Err(exit_code) => return exit_code,
    };
    let placeholder_guards = match resolve_placeholders(output, &placeholders, &mut command_tokens)
    {
        Ok(guards) => guards,
        Err(exit_code) => return exit_code,
    };

    let (program, args) = command_tokens
        .split_first()
        .expect("clap requires at least one command token");
    let mut command = std::process::Command::new(program);
    command.args(args);
    for (name, value) in &env_vars {
        command.env(name, value.as_str());
    }
    let status = command.status();
    drop(env_vars);
    drop(placeholder_guards);
    match status {
        Ok(status) => {
            let code = u8::try_from(status.code().unwrap_or(1).clamp(0, 255)).unwrap_or(1);
            ExitCode::from(code)
        }
        Err(error) => print_error(
            output,
            &input_error(
                "run_spawn_failed",
                &format!("failed to spawn {program}: {error}"),
            ),
        ),
    }
}

/// Splits a `<profile>.<secret>` reference into `(profile, secret)`. A bare
/// name with no `.` addresses the permanent `base` profile.
fn parse_secret_ref(input: &str) -> (String, String) {
    match input.split_once('.') {
        Some((profile, secret)) => (profile.to_string(), secret.to_string()),
        None => ("base".to_string(), input.to_string()),
    }
}

fn read_secret_value() -> Result<SensitiveBytes, StructuredError> {
    if io::stdin().is_terminal() {
        return Err(input_error(
            "secret_stdin_requires_pipe",
            "secret values are accepted only through piped standard input",
        ));
    }
    let maximum = envault_protocol::MAX_FRAME_BYTES / 2;
    // Preallocated to the exact read cap so `read_to_end` never reallocates
    // mid-read - a realloc would leave an unzeroed prefix of the plaintext
    // behind in the freed heap chunk.
    let mut value = Vec::with_capacity(maximum + 1);
    io::stdin()
        .take(u64::try_from(maximum + 1).expect("bounded input limit"))
        .read_to_end(&mut value)
        .map_err(|_| input_error("io_error", "failed to read the secret value"))?;
    let value = SensitiveBytes::new(value);
    validate_secret_value_length(value)
}

/// Prompts on a masked terminal when standard input is interactive,
/// otherwise reads a piped value exactly like `read_secret_value`. Used only
/// where the CLI offers a fallback to typing a value directly, not where
/// `--stdin` was explicitly requested.
fn read_secret_value_interactive() -> Result<SensitiveBytes, StructuredError> {
    if !io::stdin().is_terminal() {
        return read_secret_value();
    }
    let value = SensitiveBytes::new(
        rpassword::prompt_password("Secret value: ")
            .map_err(|_| input_error("io_error", "failed to read the secret value"))?
            .into_bytes(),
    );
    validate_secret_value_length(value)
}

fn validate_secret_value_length(value: SensitiveBytes) -> Result<SensitiveBytes, StructuredError> {
    let maximum = envault_protocol::MAX_FRAME_BYTES / 2;
    if value.is_empty() || value.len() > maximum {
        return Err(input_error(
            "invalid_secret_value",
            "secret value must contain between 1 byte and 512 KiB",
        ));
    }
    Ok(value)
}

fn read_bounded_file(path: &Path, maximum: usize) -> Result<Vec<u8>, StructuredError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| input_error("io_error", "unable to inspect the request body file"))?;
    if !metadata.file_type().is_file() || metadata.len() > maximum as u64 {
        return Err(input_error(
            "invalid_request_body",
            "request body must be a regular file no larger than 512 KiB",
        ));
    }
    let body = fs::read(path)
        .map_err(|_| input_error("io_error", "unable to read the request body file"))?;
    if body.len() > maximum {
        return Err(input_error(
            "invalid_request_body",
            "request body exceeds the maximum size",
        ));
    }
    Ok(body)
}

fn generator_spec(
    format: GeneratorFormatArg,
    length: GeneratorLengthArgs,
) -> Result<GeneratorSpec, StructuredError> {
    let allow_weak = length.allow_weak;
    let format = match format {
        GeneratorFormatArg::UuidV4 => GeneratorFormat::UuidV4,
        GeneratorFormatArg::Base64url => GeneratorFormat::Base64Url,
        GeneratorFormatArg::Base64 => GeneratorFormat::Base64,
    };
    let length = match (length.chars, length.bytes) {
        (None, None) => GeneratorLength::Default,
        (Some(chars), None) => GeneratorLength::Chars(chars),
        (None, Some(bytes)) => GeneratorLength::Bytes(bytes),
        (Some(_), Some(_)) => {
            return Err(input_error(
                "invalid_generator_length",
                "choose only one generator length unit",
            ));
        }
    };
    let spec = GeneratorSpec {
        format,
        length,
        allow_weak,
    };
    envault_core::validate_generator(spec).map_err(|_| {
        input_error(
            "invalid_generator",
            "generator arguments violate the contract",
        )
    })
}

const fn http_method(method: HttpMethodArg) -> HttpMethod {
    match method {
        HttpMethodArg::Get => HttpMethod::Get,
        HttpMethodArg::Post => HttpMethod::Post,
        HttpMethodArg::Put => HttpMethod::Put,
        HttpMethodArg::Patch => HttpMethod::Patch,
        HttpMethodArg::Delete => HttpMethod::Delete,
    }
}

const fn http_content_type(content_type: HttpContentTypeArg) -> HttpContentType {
    match content_type {
        HttpContentTypeArg::Json => HttpContentType::Json,
        HttpContentTypeArg::Text => HttpContentType::Text,
        HttpContentTypeArg::Form => HttpContentType::Form,
    }
}

fn lifecycle_request(output: Output, operation: Operation, state: &str) -> ExitCode {
    match client::request(operation) {
        Ok(Reply::Acknowledged { no_op }) => {
            match output {
                Output::Human if no_op => println!("service: {state} (no-op)"),
                Output::Human => println!("service: {state}"),
                Output::Json => {
                    println!("{{\"status\":{},\"no_op\":{no_op}}}", toon_string(state));
                }
                Output::Toon => {
                    println!("service{{status,no_op}}: {},{no_op}", toon_string(state));
                }
            }
            ExitCode::SUCCESS
        }
        Ok(_) => print_error(output, &unexpected_response()),
        Err(error) => print_error(output, &client_error(error)),
    }
}

fn read_master_password(
    from_stdin: bool,
    require_confirmation: bool,
) -> Result<SensitiveBytes, StructuredError> {
    if from_stdin {
        if io::stdin().is_terminal() {
            return Err(input_error(
                "password_stdin_requires_pipe",
                "`--password-stdin` requires piped standard input",
            ));
        }
        let mut bytes = Vec::new();
        io::stdin()
            .take(4097)
            .read_to_end(&mut bytes)
            .map_err(|_| input_error("io_error", "failed to read the master password"))?;
        while matches!(bytes.last(), Some(b'\n' | b'\r')) {
            bytes.pop();
        }
        return validate_password(SensitiveBytes::new(bytes));
    }
    if !io::stdin().is_terminal() {
        return Err(input_error(
            "interactive_terminal_required",
            "use `--password-stdin` when standard input is not a terminal",
        ));
    }
    let password = SensitiveBytes::new(
        rpassword::prompt_password("Master password: ")
            .map_err(|_| input_error("io_error", "failed to read the master password"))?
            .into_bytes(),
    );
    if require_confirmation {
        let confirmation = SensitiveBytes::new(
            rpassword::prompt_password("Confirm master password: ")
                .map_err(|_| input_error("io_error", "failed to confirm the master password"))?
                .into_bytes(),
        );
        if !password.matches(&confirmation) {
            return Err(input_error(
                "password_confirmation_mismatch",
                "master password confirmation does not match",
            ));
        }
    }
    validate_password(password)
}

fn read_optional_transfer_password(
    arguments: TransferPasswordArgs,
    require_confirmation: bool,
) -> Result<Option<SensitiveBytes>, StructuredError> {
    if !arguments.transfer_password && !arguments.transfer_password_stdin {
        return Ok(None);
    }
    let password = if arguments.transfer_password_stdin {
        if io::stdin().is_terminal() {
            return Err(input_error(
                "transfer_password_stdin_requires_pipe",
                "`--transfer-password-stdin` requires piped standard input",
            ));
        }
        let mut bytes = Vec::new();
        io::stdin()
            .take(4097)
            .read_to_end(&mut bytes)
            .map_err(|_| input_error("io_error", "failed to read the transfer password"))?;
        while matches!(bytes.last(), Some(b'\n' | b'\r')) {
            bytes.pop();
        }
        SensitiveBytes::new(bytes)
    } else {
        if !io::stdin().is_terminal() {
            return Err(input_error(
                "interactive_terminal_required",
                "use `--transfer-password-stdin` when standard input is not a terminal",
            ));
        }
        let password = SensitiveBytes::new(
            rpassword::prompt_password("Transfer password: ")
                .map_err(|_| input_error("io_error", "failed to read the transfer password"))?
                .into_bytes(),
        );
        if require_confirmation {
            let confirmation = SensitiveBytes::new(
                rpassword::prompt_password("Confirm transfer password: ")
                    .map_err(|_| {
                        input_error("io_error", "failed to confirm the transfer password")
                    })?
                    .into_bytes(),
            );
            if !password.matches(&confirmation) {
                return Err(input_error(
                    "transfer_password_confirmation_mismatch",
                    "transfer password confirmation does not match",
                ));
            }
        }
        password
    };
    if password.len() < 12 || password.len() > 4096 {
        return Err(input_error(
            "invalid_transfer_password_length",
            "transfer password must contain between 12 and 4096 bytes",
        ));
    }
    Ok(Some(password))
}

fn protocol_path(path: &Path) -> Result<String, StructuredError> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|_| input_error("io_error", "unable to resolve the current directory"))?
            .join(path)
    };
    absolute
        .to_str()
        .map(str::to_owned)
        .ok_or_else(|| input_error("invalid_path", "path must be valid UTF-8"))
}

const fn import_profile_strategy(strategy: ProfileConflictStrategyArg) -> ImportConflictStrategy {
    match strategy {
        ProfileConflictStrategyArg::Abort => ImportConflictStrategy::Abort,
        ProfileConflictStrategyArg::Skip => ImportConflictStrategy::Skip,
        ProfileConflictStrategyArg::Replace => ImportConflictStrategy::Replace,
        ProfileConflictStrategyArg::Rename => ImportConflictStrategy::Rename,
    }
}

const fn import_workspace_strategy(
    strategy: WorkspaceConflictStrategyArg,
) -> ImportConflictStrategy {
    match strategy {
        WorkspaceConflictStrategyArg::Abort => ImportConflictStrategy::Abort,
        WorkspaceConflictStrategyArg::Replace => ImportConflictStrategy::Replace,
    }
}

const fn import_env_strategy(strategy: EnvConflictStrategyArg) -> ImportConflictStrategy {
    match strategy {
        EnvConflictStrategyArg::Abort => ImportConflictStrategy::Abort,
        EnvConflictStrategyArg::Skip => ImportConflictStrategy::Skip,
        EnvConflictStrategyArg::Replace => ImportConflictStrategy::Replace,
    }
}

fn validate_password(password: SensitiveBytes) -> Result<SensitiveBytes, StructuredError> {
    if password.len() < 12 || password.len() > 4096 {
        Err(input_error(
            "invalid_password_length",
            "master password must contain between 12 and 4096 bytes",
        ))
    } else {
        Ok(password)
    }
}

fn vault_database_path() -> Result<PathBuf, StructuredError> {
    envault_platform::data_directory()
        .map(|directory| directory.join("vault.db"))
        .map_err(|_| input_error("io_error", "unable to resolve the EnVault data directory"))
}

fn print_portability_export(output: Output, summary: &PortabilityExportSummary) -> ExitCode {
    match output {
        Output::Human => println!(
            "package: exported · kind: {:?} · id: {} · profiles: {} · secrets: {} · workspaces: {} · memberships: {} · path: {}",
            summary.kind,
            summary.package_id,
            summary.counts.profiles,
            summary.counts.secrets,
            summary.counts.workspaces,
            summary.counts.memberships,
            summary.output_path
        ),
        Output::Json => print_json(summary),
        Output::Toon => println!(
            "package{{status,kind,id,profiles,secrets,workspaces,memberships,password_slots,age_slots,path}}: exported,{:?},{},{},{},{},{},{},{},{}",
            summary.kind,
            summary.package_id,
            summary.counts.profiles,
            summary.counts.secrets,
            summary.counts.workspaces,
            summary.counts.memberships,
            summary.password_slots,
            summary.age_slots,
            toon_string(&summary.output_path)
        ),
    }
    ExitCode::SUCCESS
}

fn print_portability_preview(output: Output, preview: &PortabilityPreview) -> ExitCode {
    match output {
        Output::Human => {
            println!(
                "import: preview · kind: {:?} · profiles: {} · secrets: {} · workspaces: {} · memberships: {} · strategy: {:?}",
                preview.kind,
                preview.counts.profiles,
                preview.counts.secrets,
                preview.counts.workspaces,
                preview.counts.memberships,
                preview.strategy
            );
            for conflict in &preview.conflicts {
                println!(
                    "action: {:?} · resource: {} · name: {}",
                    conflict.action, conflict.resource, conflict.name
                );
            }
            println!("plan_hash: {}", preview.plan_hash);
            println!(
                "commit: repeat the command with `--commit --plan-hash {}`",
                preview.plan_hash
            );
            for warning in &preview.warnings {
                println!("warning: {warning}");
            }
        }
        Output::Json => print_json(preview),
        Output::Toon => {
            println!(
                "import{{status,kind,profiles,secrets,workspaces,memberships,strategy,plan_hash}}: preview,{:?},{},{},{},{},{:?},{}",
                preview.kind,
                preview.counts.profiles,
                preview.counts.secrets,
                preview.counts.workspaces,
                preview.counts.memberships,
                preview.strategy,
                preview.plan_hash
            );
            for conflict in &preview.conflicts {
                println!(
                    "conflict{{resource,name,action}}: {},{},{:?}",
                    toon_string(&conflict.resource),
                    toon_string(&conflict.name),
                    conflict.action
                );
            }
        }
    }
    ExitCode::SUCCESS
}

fn print_env_import_preview(output: Output, preview: &EnvImportPreview) -> ExitCode {
    match output {
        Output::Human => {
            println!(
                "env import: preview · profile: {} · entries: {} · strategy: {:?}",
                preview.profile,
                preview.entries.len(),
                preview.strategy
            );
            for entry in &preview.entries {
                println!(
                    "secret: {} · value: [REDACTED {} bytes] · action: {:?}",
                    entry.name, entry.value_bytes, entry.action
                );
            }
            println!("plan_hash: {}", preview.plan_hash);
            println!(
                "commit: repeat the command with `--commit --plan-hash {}`",
                preview.plan_hash
            );
            for warning in &preview.warnings {
                println!("warning: {warning}");
            }
        }
        Output::Json => print_json(preview),
        Output::Toon => {
            println!(
                "env_import{{status,profile,entries,strategy,plan_hash}}: preview,{},{},{:?},{}",
                toon_string(&preview.profile),
                preview.entries.len(),
                preview.strategy,
                preview.plan_hash
            );
            for entry in &preview.entries {
                println!(
                    "entry{{name,value_bytes,action}}: {},{},{:?}",
                    toon_string(&entry.name),
                    entry.value_bytes,
                    entry.action
                );
            }
        }
    }
    ExitCode::SUCCESS
}

fn print_portability_import(output: Output, summary: &PortabilityImportSummary) -> ExitCode {
    match output {
        Output::Human => println!(
            "import: committed · created: {} · replaced: {} · skipped: {}",
            summary.created, summary.replaced, summary.skipped
        ),
        Output::Json => print_json(summary),
        Output::Toon => println!(
            "import{{status,created,replaced,skipped}}: committed,{},{},{}",
            summary.created, summary.replaced, summary.skipped
        ),
    }
    ExitCode::SUCCESS
}

fn print_plaintext_export(output: Output, summary: &PlaintextExportSummary) -> ExitCode {
    match output {
        Output::Human => println!(
            "plaintext export: written · profile: {} · secrets: {} · path: {} · mode: 0600",
            summary.profile, summary.secret_count, summary.output_path
        ),
        Output::Json => print_json(summary),
        Output::Toon => println!(
            "plaintext_export{{status,profile,secrets,path,mode}}: written,{},{},{},0600",
            toon_string(&summary.profile),
            summary.secret_count,
            toon_string(&summary.output_path)
        ),
    }
    ExitCode::SUCCESS
}

/// Prints the next-step suggestions a list or mutation view carries, per
/// AXI guideline §9. Called after the primary data so the hints read as
/// supplementary rather than part of the record itself.
fn print_human_help(help: &[&str]) {
    for item in help {
        println!("help: {item}");
    }
}

fn print_toon_help(help: &[&str]) {
    if !help.is_empty() {
        println!(
            "help[{}]: {}",
            help.len(),
            help.iter()
                .map(|item| toon_string(item))
                .collect::<Vec<_>>()
                .join(",")
        );
    }
}

/// The first 8 characters of a UUID's canonical hex representation, used as
/// a human-scannable table column; the full UUID remains available via
/// `--output json`.
fn short_id(id: Uuid) -> String {
    id.simple().to_string()[..8].to_string()
}

fn human_table(header: Vec<&str>) -> comfy_table::Table {
    let mut table = comfy_table::Table::new();
    table
        .load_preset(comfy_table::presets::UTF8_FULL_CONDENSED)
        .set_content_arrangement(comfy_table::ContentArrangement::Dynamic)
        .set_header(header);
    table
}

fn print_profiles(output: Output, profiles: &[ProfileView], help: &[&str]) -> ExitCode {
    match output {
        Output::Json => {
            print_json(profiles);
        }
        Output::Toon => {
            println!(
                "profiles[{}]{{id,scope_id,name,description,loaded,activate_on_start,generation}}:",
                profiles.len()
            );
            for profile in profiles {
                println!(
                    "  {},{},{},{},{},{},{}",
                    profile.id.0,
                    profile.scope_id.0,
                    toon_string(&profile.name),
                    optional_toon(profile.description.as_deref()),
                    profile.loaded,
                    profile.activate_on_start,
                    profile.generation
                );
            }
            print_toon_help(help);
        }
        Output::Human => {
            if profiles.is_empty() {
                println!("profiles: 0 profiles found");
            } else {
                let mut table = human_table(vec![
                    "name",
                    "id",
                    "scope",
                    "loaded",
                    "activate_on_start",
                    "description",
                ]);
                for profile in profiles {
                    table.add_row(vec![
                        profile.name.clone(),
                        short_id(profile.id.0),
                        short_id(profile.scope_id.0),
                        profile.loaded.to_string(),
                        profile.activate_on_start.to_string(),
                        profile.description.clone().unwrap_or_default(),
                    ]);
                }
                println!("{table}");
            }
            print_human_help(help);
        }
    }
    ExitCode::SUCCESS
}

fn print_secrets(output: Output, secrets: &[SecretView], help: &[&str]) -> ExitCode {
    match output {
        Output::Json => {
            print_json(secrets);
        }
        Output::Toon => {
            println!(
                "secrets[{}]{{id,scope_id,name,description,status}}:",
                secrets.len()
            );
            for secret in secrets {
                println!(
                    "  {},{},{},{},{:?}",
                    secret.id.0,
                    secret.scope_id.0,
                    toon_string(&secret.name),
                    optional_toon(secret.description.as_deref()),
                    secret.status
                );
            }
            print_toon_help(help);
        }
        Output::Human => {
            if secrets.is_empty() {
                println!("secrets: 0 secrets found");
            } else {
                let mut table = human_table(vec!["name", "id", "scope", "status", "description"]);
                for secret in secrets {
                    table.add_row(vec![
                        secret.name.clone(),
                        short_id(secret.id.0),
                        short_id(secret.scope_id.0),
                        format!("{:?}", secret.status),
                        secret.description.clone().unwrap_or_default(),
                    ]);
                }
                println!("{table}");
            }
            print_human_help(help);
        }
    }
    ExitCode::SUCCESS
}

/// Confirms a secret's value was set/generated - the value overwrites
/// in place, so there is nothing further to list (no version history).
fn print_value_set(output: Output, value: &SecretVersionView, help: &[&str]) -> ExitCode {
    match output {
        Output::Json => {
            print_json(value);
        }
        Output::Toon => {
            println!("value_set{{id,secret_id,generator,generated_length,entropy_bits}}:");
            println!(
                "  {},{},{:?},{},{}",
                value.id.0,
                value.secret_id.0,
                value.generator,
                optional_number(value.generated_length),
                optional_number(value.entropy_bits)
            );
            print_toon_help(help);
        }
        Output::Human => {
            println!("value set for secret {}", short_id(value.secret_id.0));
            if let Some(generator) = value.generator {
                println!(
                    "  generator: {generator:?}, length: {}, entropy_bits: {}",
                    optional_number(value.generated_length),
                    optional_number(value.entropy_bits)
                );
            }
            print_human_help(help);
        }
    }
    ExitCode::SUCCESS
}

/// Content large enough to justify truncation costs an agent tokens whether
/// shown in full or omitted; per AXI guideline §3 the response is always a
/// bounded preview plus the total size and the flag that reveals the rest,
/// never a silent drop.
const TRUNCATION_LIMIT: usize = 1000;

fn truncate_preview(value: &str, full: bool) -> (&str, Option<usize>) {
    if full || value.len() <= TRUNCATION_LIMIT {
        return (value, None);
    }
    let mut boundary = TRUNCATION_LIMIT;
    while !value.is_char_boundary(boundary) {
        boundary -= 1;
    }
    (&value[..boundary], Some(value.len()))
}

fn print_http_response(output: Output, response: &HttpResponse, full: bool) -> ExitCode {
    let (preview, total_size) = truncate_preview(&response.body, full);
    match output {
        Output::Human => {
            println!("status: {}", response.status);
            println!(
                "content-type: {}",
                response.content_type.as_deref().unwrap_or("none")
            );
            print!("{preview}");
            let _ = io::stdout().flush();
            if let Some(total) = total_size {
                println!(
                    "\n... (truncated, {total} bytes total, run with `--full` to see the complete body)"
                );
            }
        }
        Output::Json => {
            if let Some(total) = total_size {
                println!(
                    "{}",
                    serde_json::json!({
                        "status": response.status,
                        "content_type": response.content_type,
                        "body": preview,
                        "truncated": true,
                        "total_bytes": total,
                        "help": ["Rerun with `--full` to see the complete body"],
                    })
                );
            } else {
                print_json(response);
            }
        }
        Output::Toon => {
            if let Some(total) = total_size {
                println!(
                    "http{{status,content_type,body,truncated,total_bytes}}: {},{},{},true,{}",
                    response.status,
                    optional_toon(response.content_type.as_deref()),
                    toon_string(preview),
                    total
                );
                println!(
                    "help[1]: {}",
                    toon_string("Rerun with `--full` to see the complete body")
                );
            } else {
                println!(
                    "http{{status,content_type,body}}: {},{},{}",
                    response.status,
                    optional_toon(response.content_type.as_deref()),
                    toon_string(preview)
                );
            }
        }
    }
    ExitCode::SUCCESS
}

fn print_acknowledgement(output: Output, state: &str, no_op: bool) -> ExitCode {
    match output {
        Output::Human if no_op => println!("status: {state} (no-op)"),
        Output::Human => println!("status: {state}"),
        Output::Json => println!("{{\"status\":{},\"no_op\":{no_op}}}", toon_string(state)),
        Output::Toon => println!("status{{state,no_op}}: {},{no_op}", toon_string(state)),
    }
    ExitCode::SUCCESS
}

/// Marks types safe to hand to `print_json`. Deliberately **not**
/// implemented for `Reply`, `EnvVar`, or `SensitiveBytes`-bearing types even
/// though they derive `Serialize` for the wire protocol: a future CLI path
/// that tried `print_json(&reply)` to shortcut its own view type would dump
/// raw secret bytes to stdout, and this bound turns that into a compile
/// error instead of a silent regression.
trait JsonPrintable: Serialize {}

impl<T: JsonPrintable> JsonPrintable for [T] {}

impl JsonPrintable for ProfileView {}
impl JsonPrintable for SecretView {}
impl JsonPrintable for SecretVersionView {}
impl JsonPrintable for PortabilityExportSummary {}
impl JsonPrintable for PortabilityPreview {}
impl JsonPrintable for EnvImportPreview {}
impl JsonPrintable for PortabilityImportSummary {}
impl JsonPrintable for PlaintextExportSummary {}
impl JsonPrintable for ConfigPreview {}
impl JsonPrintable for HttpResponse {}

fn print_json<T: JsonPrintable + ?Sized>(value: &T) {
    println!(
        "{}",
        serde_json::to_string(value).expect("value serializes")
    );
}

fn optional_toon(value: Option<&str>) -> String {
    value.map_or_else(|| "null".into(), toon_string)
}

fn optional_number<T: ToString>(value: Option<T>) -> String {
    value.map_or_else(|| "null".into(), |number| number.to_string())
}

const HOME_HEADER_DESCRIPTION: &str = "Manage the local encrypted secrets vault and agent access";

/// Identifies the tool itself ahead of live state, per AXI guideline §10: an
/// agent seeing bare state has no way to tell what produced it or where the
/// binary lives, so a no-args invocation names both first.
fn print_home_header(output: Output) {
    let bin = home_collapsed_executable_path();
    match output {
        Output::Human => {
            println!("bin: {bin}");
            println!("description: {HOME_HEADER_DESCRIPTION}");
        }
        Output::Json => {}
        Output::Toon => println!(
            "bin{{path,description}}: {},{}",
            toon_string(&bin),
            toon_string(HOME_HEADER_DESCRIPTION)
        ),
    }
}

fn home_collapsed_executable_path() -> String {
    let Ok(executable) = std::env::current_exe() else {
        return "envault".to_owned();
    };
    let home = std::env::var("HOME")
        .ok()
        .or_else(|| std::env::var("USERPROFILE").ok());
    collapse_home(&executable.display().to_string(), home.as_deref())
}

fn collapse_home(path: &str, home: Option<&str>) -> String {
    match home {
        Some(home) if !home.is_empty() && path.starts_with(home) => {
            format!("~{}", &path[home.len()..])
        }
        _ => path.to_owned(),
    }
}

fn print_status(output: Output) -> ExitCode {
    match client::request(Operation::Status) {
        Ok(Reply::Status(status)) => print_running_status(output, &status),
        Ok(_) => print_error(output, &unexpected_response()),
        Err(ClientError::NotRunning) => print_status_view(output, &stopped_status()),
        Err(error) => print_error(output, &client_error(error)),
    }
}

fn print_running_status(output: Output, status: &DaemonStatus) -> ExitCode {
    let service = match status.service {
        ServiceState::Unlocked => "unlocked",
        ServiceState::Locked => "locked",
    };
    let help = if status.service == ServiceState::Locked {
        vec!["Run `envault start`"]
    } else {
        Vec::new()
    };
    print_status_view(
        output,
        &StatusView {
            daemon: "running",
            service,
            profile: (!status.loaded_profiles.is_empty())
                .then(|| status.loaded_profiles.join(", ")),
            pid: Some(status.pid),
            admin_lease_active: status.admin_lease_active,
            help,
        },
    )
}

fn stopped_status() -> StatusView {
    StatusView {
        daemon: "stopped",
        service: "inactive",
        profile: None,
        pid: None,
        admin_lease_active: false,
        help: vec!["Run `envault start`"],
    }
}

fn print_status_view(output: Output, status: &StatusView) -> ExitCode {
    match output {
        Output::Human => {
            println!(
                "daemon: {} · service: {} · profile: {} · admin: {}",
                status.daemon,
                status.service,
                status.profile.as_deref().unwrap_or("none"),
                if status.admin_lease_active {
                    "unlocked"
                } else {
                    "locked"
                }
            );
            for help in &status.help {
                println!("help: {help}");
            }
        }
        Output::Json => println!(
            "{}",
            serde_json::to_string(status).expect("status serializes")
        ),
        Output::Toon => {
            println!(
                "status{{daemon,service,profile,pid,admin_lease_active}}: {},{},{},{},{}",
                status.daemon,
                status.service,
                status
                    .profile
                    .as_deref()
                    .map_or_else(|| "null".to_owned(), toon_string),
                status
                    .pid
                    .map_or_else(|| "null".to_owned(), |pid| pid.to_string()),
                status.admin_lease_active
            );
            if !status.help.is_empty() {
                println!(
                    "help[{}]: {}",
                    status.help.len(),
                    status
                        .help
                        .iter()
                        .map(|item| toon_string(item))
                        .collect::<Vec<_>>()
                        .join(",")
                );
            }
        }
    }
    ExitCode::SUCCESS
}

fn print_admin_status(output: Output, status: &AdminLeaseStatus) -> ExitCode {
    match output {
        Output::Human => println!(
            "admin: {} · expires_at: {}",
            if status.active { "unlocked" } else { "locked" },
            status
                .expires_at
                .map_or_else(|| "none".to_owned(), |value| value.to_string())
        ),
        Output::Json => println!(
            "{}",
            serde_json::to_string(status).expect("admin status serializes")
        ),
        Output::Toon => println!(
            "admin{{active,expires_at}}: {},{}",
            status.active,
            status
                .expires_at
                .map_or_else(|| "null".to_owned(), |value| value.to_string())
        ),
    }
    ExitCode::SUCCESS
}

fn service_error(error: &ServiceError) -> StructuredError {
    let (code, message, retryable) = match error {
        ServiceError::AlreadyInitialized => (
            "vault_already_initialized",
            "EnVault is already initialized",
            false,
        ),
        ServiceError::NotInitialized => {
            ("vault_not_initialized", "EnVault is not initialized", false)
        }
        ServiceError::AuthenticationFailed => (
            "authentication_failed",
            "master password authentication failed",
            true,
        ),
        ServiceError::InvalidPasswordLength => (
            "invalid_password_length",
            "master password must contain between 12 and 4096 bytes",
            false,
        ),
        ServiceError::Conflict => ("conflict", "resource conflict", false),
        ServiceError::NotFound => ("not_found", "resource was not found", false),
        ServiceError::Invariant(_) => ("invalid_input", "input violates the vault contract", false),
        ServiceError::Corrupt | ServiceError::Store(_) => {
            ("vault_corrupt", "vault integrity validation failed", false)
        }
        _ => ("io_error", "vault initialization failed", true),
    };
    StructuredError {
        code: code.into(),
        message: message.into(),
        help: vec!["Run `envault status` for current state".into()],
        request_id: Uuid::new_v4(),
        retryable,
        kind: ErrorKind::Runtime,
    }
}

/// Appends a "did you mean" hint to a `not_found` error when some candidate
/// name is close enough (Levenshtein distance <= 2) to what was requested.
/// A best-effort UX aid, not authoritative: the daemon has already decided
/// the lookup failed, this only helps a human correct a typo.
fn suggest_on_not_found(
    mut error: StructuredError,
    identifier: &str,
    candidates: &[String],
) -> StructuredError {
    if error.code == "not_found"
        && let Some(suggestion) = closest_match(identifier, candidates)
    {
        error.help.push(format!("did you mean \"{suggestion}\"?"));
    }
    error
}

fn closest_match(target: &str, candidates: &[String]) -> Option<String> {
    candidates
        .iter()
        .map(|candidate| (candidate, levenshtein_distance(target, candidate)))
        .filter(|(_, distance)| (1..=2).contains(distance))
        .min_by_key(|(_, distance)| *distance)
        .map(|(candidate, _)| candidate.clone())
}

fn levenshtein_distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut previous: Vec<usize> = (0..=b.len()).collect();
    for (i, &character_a) in a.iter().enumerate() {
        let mut current = vec![i + 1];
        for (j, &character_b) in b.iter().enumerate() {
            let cost = usize::from(character_a != character_b);
            current.push(
                (previous[j + 1] + 1)
                    .min(current[j] + 1)
                    .min(previous[j] + cost),
            );
        }
        previous = current;
    }
    previous[b.len()]
}

fn secret_names_in_profile(profile: &str) -> Vec<String> {
    match client::request(Operation::ListResolvedSecrets {
        profile: profile.to_string(),
    }) {
        Ok(Reply::ResolvedSecrets(resolved)) => resolved
            .into_iter()
            .map(|entry| entry.secret.name)
            .collect(),
        _ => Vec::new(),
    }
}

fn profile_names() -> Vec<String> {
    match client::request(Operation::ListProfiles) {
        Ok(Reply::Profiles(profiles)) => profiles.into_iter().map(|profile| profile.name).collect(),
        _ => Vec::new(),
    }
}

fn client_error(error: ClientError) -> StructuredError {
    match error {
        ClientError::Remote(error) => error,
        ClientError::NotRunning => StructuredError {
            code: "envault_not_running".into(),
            message: "EnVault daemon is not running".into(),
            help: vec!["Run `envault start`".into()],
            request_id: Uuid::new_v4(),
            retryable: true,
            kind: ErrorKind::Runtime,
        },
        ClientError::Timeout => StructuredError {
            code: "request_timeout".into(),
            message: "EnVault daemon did not respond before the deadline".into(),
            help: vec!["Retry the request".into()],
            request_id: Uuid::new_v4(),
            retryable: true,
            kind: ErrorKind::Runtime,
        },
        ClientError::PortabilityTimeout => StructuredError {
            code: "request_timeout".into(),
            message: "EnVault portability operation did not respond before the deadline".into(),
            help: vec![
                "Preview current state before retrying because an atomic commit may have completed"
                    .into(),
            ],
            request_id: Uuid::new_v4(),
            retryable: false,
            kind: ErrorKind::Runtime,
        },
        ClientError::UnsupportedPlatform => StructuredError {
            code: "platform_not_supported".into(),
            message: "runtime support is not available on this platform in the current phase"
                .into(),
            help: vec!["Use Linux or macOS until Phase 7".into()],
            request_id: Uuid::new_v4(),
            retryable: false,
            kind: ErrorKind::Runtime,
        },
        ClientError::Protocol | ClientError::UnexpectedResponse => unexpected_response(),
    }
}

fn unexpected_response() -> StructuredError {
    StructuredError {
        code: "protocol_error".into(),
        message: "EnVault IPC response violated the protocol".into(),
        help: vec!["Stop and restart EnVault".into()],
        request_id: Uuid::new_v4(),
        retryable: true,
        kind: ErrorKind::Runtime,
    }
}

fn input_error(code: &str, message: &str) -> StructuredError {
    let retryable = code == "io_error";
    StructuredError {
        code: code.into(),
        message: message.into(),
        help: vec![if retryable {
            "Check the trusted local input source and retry".into()
        } else {
            "Correct the command input before retrying".into()
        }],
        request_id: Uuid::new_v4(),
        retryable,
        kind: ErrorKind::Usage,
    }
}

fn print_error(output: Output, error: &StructuredError) -> ExitCode {
    match output {
        Output::Human => eprintln!(
            "error: {} · {} · request_id: {} · retryable: {} · help: {}",
            error.code,
            error.message,
            error.request_id,
            error.retryable,
            error.help.join("; ")
        ),
        Output::Json => eprintln!(
            "{}",
            serde_json::to_string(error).expect("error serializes")
        ),
        Output::Toon => eprintln!(
            "error{{code,message,request_id,retryable,help}}: {},{},{},{},[{}]",
            toon_string(&error.code),
            toon_string(&error.message),
            error.request_id,
            error.retryable,
            error
                .help
                .iter()
                .map(|item| toon_string(item))
                .collect::<Vec<_>>()
                .join(",")
        ),
    }
    match error.kind {
        ErrorKind::Usage => ExitCode::from(2),
        ErrorKind::Runtime => ExitCode::FAILURE,
    }
}

fn toon_string(value: &str) -> String {
    serde_json::to_string(value).expect("string serializes")
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use clap::CommandFactory;

    use super::*;

    #[derive(serde::Deserialize)]
    struct Contract {
        command: Vec<ContractCommand>,
    }

    #[derive(serde::Deserialize)]
    struct ContractCommand {
        path: String,
        #[serde(default = "implemented_by_default")]
        implemented: bool,
    }

    const fn implemented_by_default() -> bool {
        true
    }

    #[test]
    fn bootstrap_command_surface_is_stable() {
        let command = Cli::command();
        let names = command
            .get_subcommands()
            .filter(|subcommand| !subcommand.is_hide_set())
            .map(|subcommand| subcommand.get_name().to_owned())
            .collect::<Vec<_>>();
        assert_eq!(
            names,
            [
                "init",
                "status",
                "start",
                "lock",
                "stop",
                "admin",
                "profile",
                "secret",
                "request",
                "portability",
                "config",
                "workspace",
                "convenience-unlock",
                "session",
                "run",
                "load",
                "unload",
                "uninstall"
            ]
        );
    }

    #[test]
    fn convenience_unlock_enable_requires_explicit_acknowledgement() {
        assert!(
            Cli::try_parse_from(["envault", "convenience-unlock", "enable"]).is_err(),
            "enabling without --acknowledge-os-keystore must fail to parse"
        );
        assert!(
            Cli::try_parse_from([
                "envault",
                "convenience-unlock",
                "enable",
                "--acknowledge-os-keystore",
            ])
            .is_ok()
        );
    }

    #[test]
    fn secret_value_set_requires_stdin() {
        assert!(Cli::try_parse_from(["envault", "secret", "value", "set", "API_TOKEN"]).is_err());
        assert!(
            Cli::try_parse_from(["envault", "secret", "value", "set", "API_TOKEN", "--stdin",])
                .is_ok()
        );
    }

    #[test]
    fn canonical_contract_has_no_plaintext_value_flag() {
        let contract = include_str!("../commands.toml");
        assert!(!contract.contains("--value"));
        assert!(!contract.contains("get_secret"));
    }

    /// `Operation::RevealSecretValue` is meant to be reachable only from the
    /// TUI's admin-gated `Reveal` action (see its doc comment in
    /// `envault-protocol`), never from a CLI subcommand - the CLI must keep
    /// printing metadata only, even as admin. This walks the entire clap
    /// command tree so a future subcommand added "by analogy" next to an
    /// existing `secret`/`secret value` command fails this test the moment
    /// it's named, before anyone has to notice it also wires up reveal.
    #[test]
    fn no_cli_subcommand_is_named_or_aliased_reveal() {
        fn assert_no_reveal_subcommand(command: &clap::Command) {
            for subcommand in command.get_subcommands() {
                let name = subcommand.get_name();
                assert!(
                    !name.to_ascii_lowercase().contains("reveal"),
                    "found a CLI subcommand named {name:?} - RevealSecretValue must stay TUI-only"
                );
                for alias in subcommand.get_all_aliases() {
                    assert!(
                        !alias.to_ascii_lowercase().contains("reveal"),
                        "found a CLI subcommand alias {alias:?} on {name:?} - RevealSecretValue must stay TUI-only"
                    );
                }
                assert_no_reveal_subcommand(subcommand);
            }
        }
        assert_no_reveal_subcommand(&Cli::command());
    }

    #[test]
    fn generator_arguments_preserve_format_length_and_weak_override() {
        assert_eq!(
            generator_spec(
                GeneratorFormatArg::Base64url,
                GeneratorLengthArgs::default()
            )
            .expect("default generator"),
            GeneratorSpec {
                format: GeneratorFormat::Base64Url,
                length: GeneratorLength::Default,
                allow_weak: false,
            }
        );
        assert_eq!(
            generator_spec(
                GeneratorFormatArg::Base64url,
                GeneratorLengthArgs {
                    chars: Some(12),
                    bytes: None,
                    allow_weak: true,
                },
            )
            .expect("explicit weak generator"),
            GeneratorSpec {
                format: GeneratorFormat::Base64Url,
                length: GeneratorLength::Chars(12),
                allow_weak: true,
            }
        );
    }

    #[test]
    fn portability_commands_expose_only_supported_conflict_strategies() {
        assert!(
            Cli::try_parse_from([
                "envault",
                "profile",
                "import",
                "profile.envault-profile",
                "--strategy",
                "rename",
                "--rename-to",
                "copy",
                "--transfer-password-stdin",
            ])
            .is_ok()
        );
        assert!(
            Cli::try_parse_from([
                "envault",
                "profile",
                "import",
                "profile.envault-profile",
                "--strategy",
                "rename",
                "--transfer-password-stdin",
            ])
            .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "envault",
                "workspace",
                "import",
                "workspace.envault-workspace",
                "--strategy",
                "skip",
                "--transfer-password-stdin",
            ])
            .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "envault",
                "profile",
                "import-env",
                "base",
                ".env",
                "--strategy",
                "rename",
            ])
            .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "envault",
                "profile",
                "import-env",
                "base",
                ".env",
                "--commit",
                "--plan-hash",
                "-X_base64url-plan-hash",
            ])
            .is_ok()
        );
    }

    #[test]
    fn local_portability_timeout_requires_preview_instead_of_blind_retry() {
        let error = client_error(ClientError::PortabilityTimeout);
        assert_eq!(error.code, "request_timeout");
        assert!(!error.retryable);
        assert!(error.help[0].contains("Preview current state"));
    }

    #[test]
    fn collapse_home_replaces_only_a_matching_prefix() {
        assert_eq!(
            collapse_home("/home/alice/.local/bin/envault", Some("/home/alice")),
            "~/.local/bin/envault"
        );
        assert_eq!(
            collapse_home("/usr/local/bin/envault", Some("/home/alice")),
            "/usr/local/bin/envault"
        );
        assert_eq!(
            collapse_home("/usr/local/bin/envault", None),
            "/usr/local/bin/envault"
        );
    }

    #[test]
    fn shell_quote_protects_hook_paths() {
        #[cfg(windows)]
        assert_eq!(
            shell_quote(r#"C:\Program Files\o\"matic"#),
            r#""C:\Program Files\o\\"matic""#
        );
        #[cfg(not(windows))]
        assert_eq!(
            shell_quote("/opt/En Vault/o'matic"),
            "'/opt/En Vault/o'\\''matic'"
        );
    }

    #[test]
    fn truncate_preview_passes_short_values_through_untouched() {
        let (preview, total) = truncate_preview("short body", false);
        assert_eq!(preview, "short body");
        assert_eq!(total, None);
    }

    #[test]
    fn truncate_preview_bounds_long_values_and_reports_total_size() {
        let body = "x".repeat(TRUNCATION_LIMIT + 500);
        let (preview, total) = truncate_preview(&body, false);
        assert_eq!(preview.len(), TRUNCATION_LIMIT);
        assert_eq!(total, Some(body.len()));
    }

    #[test]
    fn truncate_preview_full_flag_always_returns_the_complete_value() {
        let body = "x".repeat(TRUNCATION_LIMIT + 500);
        let (preview, total) = truncate_preview(&body, true);
        assert_eq!(preview.len(), body.len());
        assert_eq!(total, None);
    }

    #[test]
    fn implemented_cli_leaf_paths_match_the_canonical_contract() {
        let mut actual = BTreeSet::new();
        collect_leaf_paths(&Cli::command(), "", &mut actual);
        let contract: Contract =
            toml::from_str(include_str!("../commands.toml")).expect("canonical command contract");
        let expected = contract
            .command
            .into_iter()
            .filter(|command| command.implemented)
            .map(|command| command.path)
            .collect::<BTreeSet<_>>();
        assert_eq!(actual, expected);
    }

    fn collect_leaf_paths(command: &clap::Command, prefix: &str, paths: &mut BTreeSet<String>) {
        for child in command.get_subcommands() {
            if child.is_hide_set() {
                continue;
            }
            let path = if prefix.is_empty() {
                child.get_name().to_owned()
            } else {
                format!("{prefix} {}", child.get_name())
            };
            if child.has_subcommands() {
                collect_leaf_paths(child, &path, paths);
            } else {
                paths.insert(path);
            }
        }
    }

    #[test]
    fn levenshtein_distance_matches_known_values() {
        assert_eq!(levenshtein_distance("", ""), 0);
        assert_eq!(levenshtein_distance("abc", "abc"), 0);
        assert_eq!(levenshtein_distance("abc", "abd"), 1);
        assert_eq!(levenshtein_distance("kitten", "sitting"), 3);
        assert_eq!(levenshtein_distance("DATABASE_URI", "DATABASE_URL"), 1);
    }

    #[test]
    fn closest_match_ignores_exact_and_distant_names() {
        let candidates = vec![
            "DATABASE_URL".to_string(),
            "API_KEY".to_string(),
            "STRIPE_SECRET".to_string(),
        ];
        assert_eq!(
            closest_match("DATABASE_URI", &candidates),
            Some("DATABASE_URL".to_string())
        );
        // An exact match is not a typo suggestion.
        assert_eq!(closest_match("API_KEY", &candidates), None);
        // Nothing within distance 2 of a wildly different name.
        assert_eq!(closest_match("COMPLETELY_UNRELATED", &candidates), None);
    }
}
