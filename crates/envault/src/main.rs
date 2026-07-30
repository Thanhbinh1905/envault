#![forbid(unsafe_code)]

use std::{
    io::{self, IsTerminal, Read},
    path::PathBuf,
    process::ExitCode,
};

use clap::{Parser, Subcommand, ValueEnum};
use envault::client::{self, ClientError};
use envault_protocol::{
    AdminLeaseStatus, DaemonStatus, Operation, Reply, SensitiveBytes, ServiceState, StructuredError,
};
use envault_service::{SensitiveInput, ServiceError};
use serde::Serialize;
use uuid::Uuid;

#[derive(Debug, Parser)]
#[command(
    name = "envault",
    version,
    about = "Local-first encrypted secret vault"
)]
struct Cli {
    #[arg(long, global = true, value_enum, default_value_t = Output::Human)]
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
    Context,
    Admin {
        #[command(subcommand)]
        command: AdminCommand,
    },
    Profile,
    Secret,
    Request {
        #[command(subcommand)]
        command: RequestCommand,
    },
    Workspace,
}

#[derive(Clone, Copy, Debug, clap::Args)]
struct PasswordArgs {
    #[arg(long, help = "Read the master password from standard input")]
    password_stdin: bool,
}

#[derive(Clone, Copy, Debug, clap::Args)]
struct AdminUnlockArgs {
    #[command(flatten)]
    password: PasswordArgs,
    #[arg(long, default_value_t = envault_core::DEFAULT_ADMIN_LEASE_MINUTES)]
    minutes: u8,
}

#[derive(Clone, Copy, Debug, Subcommand)]
enum AdminCommand {
    Unlock(AdminUnlockArgs),
    Status,
    Lock,
}

#[derive(Debug, Subcommand)]
enum RequestCommand {
    Http,
}

#[derive(Debug, Serialize)]
struct StatusView {
    daemon: &'static str,
    service: &'static str,
    profile: Option<String>,
    pid: Option<u32>,
    admin_lease_active: bool,
    agent_session_count: u32,
    help: Vec<&'static str>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let command = cli.command.unwrap_or(Command::Status);
    match command {
        Command::Status => print_status(cli.output),
        Command::Init(arguments) => initialize_vault(cli.output, arguments),
        Command::Start(arguments) => start_daemon(cli.output, arguments),
        Command::Lock => lifecycle_request(cli.output, Operation::Lock, "locked"),
        Command::Stop => lifecycle_request(cli.output, Operation::Stop, "stopped"),
        Command::Admin { command } => admin_command(cli.output, command),
        Command::Context => phase_pending(cli.output, "context"),
        Command::Profile => phase_pending(cli.output, "profile"),
        Command::Secret => phase_pending(cli.output, "secret"),
        Command::Request {
            command: RequestCommand::Http,
        } => phase_pending(cli.output, "request http"),
        Command::Workspace => phase_pending(cli.output, "workspace"),
    }
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
    let password = match read_master_password(arguments.password_stdin, false) {
        Ok(password) => password,
        Err(error) => return print_error(output, &error),
    };
    match client::start(password) {
        Ok(status) => print_running_status(output, &status),
        Err(error) => print_error(output, &client_error(error)),
    }
}

fn admin_command(output: Output, command: AdminCommand) -> ExitCode {
    match command {
        AdminCommand::Unlock(arguments) => {
            let password = match read_master_password(arguments.password.password_stdin, false) {
                Ok(password) => password,
                Err(error) => return print_error(output, &error),
            };
            match client::request(Operation::AdminUnlock {
                password,
                ttl_minutes: arguments.minutes,
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

fn lifecycle_request(output: Output, operation: Operation, state: &str) -> ExitCode {
    match client::request(operation) {
        Ok(Reply::Acknowledged) => {
            match output {
                Output::Human => println!("service: {state}"),
                Output::Json => println!("{{\"status\":{}}}", toon_string(state)),
                Output::Toon => println!("service{{status}}: {}", toon_string(state)),
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
            profile: status.active_profile.clone(),
            pid: Some(status.pid),
            admin_lease_active: status.admin_lease_active,
            agent_session_count: status.agent_session_count,
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
        agent_session_count: 0,
        help: vec!["Run `envault start`"],
    }
}

fn print_status_view(output: Output, status: &StatusView) -> ExitCode {
    match output {
        Output::Human => {
            println!(
                "daemon: {} · service: {} · profile: {} · admin: {} · agents: {}",
                status.daemon,
                status.service,
                status.profile.as_deref().unwrap_or("none"),
                if status.admin_lease_active {
                    "unlocked"
                } else {
                    "locked"
                },
                status.agent_session_count
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
                "status{{daemon,service,profile,pid,admin_lease_active,agent_session_count}}: {},{},{},{},{},{}",
                status.daemon,
                status.service,
                status
                    .profile
                    .as_deref()
                    .map_or_else(|| "null".to_owned(), toon_string),
                status
                    .pid
                    .map_or_else(|| "null".to_owned(), |pid| pid.to_string()),
                status.admin_lease_active,
                status.agent_session_count
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

fn phase_pending(output: Output, action: &str) -> ExitCode {
    match client::request(Operation::Status) {
        Ok(Reply::Status(status)) if status.service == ServiceState::Locked => print_error(
            output,
            &StructuredError {
                code: "envault_locked".into(),
                message: "EnVault daemon is locked".into(),
                help: vec!["Run `envault start`".into()],
                request_id: Uuid::new_v4(),
                retryable: true,
            },
        ),
        Ok(Reply::Status(_)) => not_implemented(output, action),
        Ok(_) => print_error(output, &unexpected_response()),
        Err(error) => print_error(output, &client_error(error)),
    }
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
        },
        ClientError::Timeout => StructuredError {
            code: "request_timeout".into(),
            message: "EnVault daemon did not respond before the deadline".into(),
            help: vec!["Retry the request".into()],
            request_id: Uuid::new_v4(),
            retryable: true,
        },
        ClientError::UnsupportedPlatform => StructuredError {
            code: "platform_not_supported".into(),
            message: "runtime support is not available on this platform in the current phase"
                .into(),
            help: vec!["Use Linux or macOS until Phase 7".into()],
            request_id: Uuid::new_v4(),
            retryable: false,
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
    }
}

fn input_error(code: &str, message: &str) -> StructuredError {
    StructuredError {
        code: code.into(),
        message: message.into(),
        help: vec!["Use a trusted terminal or `--password-stdin`".into()],
        request_id: Uuid::new_v4(),
        retryable: true,
    }
}

fn not_implemented(output: Output, action: &str) -> ExitCode {
    print_error(
        output,
        &StructuredError {
            code: "phase_not_implemented".into(),
            message: format!(
                "`envault {action}` is defined by the contract but not implemented yet"
            ),
            help: vec!["Track implementation status in the phase roadmap".into()],
            request_id: Uuid::new_v4(),
            retryable: false,
        },
    )
}

fn print_error(output: Output, error: &StructuredError) -> ExitCode {
    match output {
        Output::Human => eprintln!(
            "error: {} · {} · request_id: {} · help: {}",
            error.code,
            error.message,
            error.request_id,
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
    ExitCode::FAILURE
}

fn toon_string(value: &str) -> String {
    serde_json::to_string(value).expect("string serializes")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bootstrap_command_surface_is_stable() {
        use clap::CommandFactory;

        let command = Cli::command();
        let names = command
            .get_subcommands()
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
                "context",
                "admin",
                "profile",
                "secret",
                "request",
                "workspace"
            ]
        );
    }

    #[test]
    fn canonical_contract_has_no_plaintext_value_flag() {
        let contract = include_str!("../../../commands.toml");
        assert!(!contract.contains("--value"));
        assert!(!contract.contains("get_secret"));
    }
}
