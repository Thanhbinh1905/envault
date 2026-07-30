#![forbid(unsafe_code)]

use std::{
    io::{self, IsTerminal, Read},
    path::PathBuf,
    process::ExitCode,
};

use clap::{Parser, Subcommand, ValueEnum};
use envault_protocol::StructuredError;
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
    Init(InitArgs),
    Status,
    Start,
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
struct InitArgs {
    #[arg(long, help = "Read the master password from standard input")]
    password_stdin: bool,
}

#[derive(Debug, Subcommand)]
enum AdminCommand {
    Unlock,
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
    profile: Option<&'static str>,
    help: Vec<&'static str>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let command = cli.command.unwrap_or(Command::Status);
    match command {
        Command::Status => print_status(cli.output),
        Command::Init(arguments) => initialize_vault(cli.output, arguments),
        Command::Start => not_implemented(cli.output, "start"),
        Command::Lock
        | Command::Stop
        | Command::Context
        | Command::Profile
        | Command::Secret
        | Command::Request {
            command: RequestCommand::Http,
        }
        | Command::Workspace => inactive(cli.output),
        Command::Admin { command } => {
            let action = match command {
                AdminCommand::Unlock => "admin unlock",
                AdminCommand::Status => "admin status",
                AdminCommand::Lock => "admin lock",
            };
            not_implemented(cli.output, action)
        }
    }
}

fn initialize_vault(output: Output, arguments: InitArgs) -> ExitCode {
    let password = match read_master_password(arguments.password_stdin) {
        Ok(password) => password,
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
                    database_path.display()
                ),
            }
            ExitCode::SUCCESS
        }
        Err(error) => print_error(output, &service_error(&error)),
    }
}

fn read_master_password(from_stdin: bool) -> Result<SensitiveInput, StructuredError> {
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
        return validate_password(SensitiveInput::new(bytes));
    }
    if !io::stdin().is_terminal() {
        return Err(input_error(
            "interactive_terminal_required",
            "use `--password-stdin` when standard input is not a terminal",
        ));
    }
    let password = SensitiveInput::new(
        rpassword::prompt_password("Master password: ")
            .map_err(|_| input_error("io_error", "failed to read the master password"))?
            .into_bytes(),
    );
    let confirmation = SensitiveInput::new(
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
    validate_password(password)
}

fn validate_password(password: SensitiveInput) -> Result<SensitiveInput, StructuredError> {
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

fn input_error(code: &str, message: &str) -> StructuredError {
    StructuredError {
        code: code.into(),
        message: message.into(),
        help: vec!["Run `envault init --help` for safe password input".into()],
        request_id: Uuid::new_v4(),
        retryable: true,
    }
}

fn socket_path() -> Option<PathBuf> {
    envault_platform::runtime_directory()
        .ok()
        .map(|directory| directory.join("envault.sock"))
}

fn print_status(output: Output) -> ExitCode {
    let running = socket_path().is_some_and(|path| path.exists());
    let status = if running {
        StatusView {
            daemon: "running",
            service: "locked",
            profile: None,
            help: vec!["Run `envault start`"],
        }
    } else {
        StatusView {
            daemon: "stopped",
            service: "inactive",
            profile: None,
            help: vec!["Run `envault start`"],
        }
    };
    match output {
        Output::Human => println!(
            "daemon: {} · service: {} · help: envault start",
            status.daemon, status.service
        ),
        Output::Json => println!(
            "{}",
            serde_json::to_string(&status).expect("status serializes")
        ),
        Output::Toon => println!(
            "status{{daemon,service,profile,help}}: {},{},{},[envault start]",
            status.daemon,
            status.service,
            status.profile.unwrap_or("null")
        ),
    }
    ExitCode::SUCCESS
}

fn inactive(output: Output) -> ExitCode {
    let code = if socket_path().is_some_and(|path| path.exists()) {
        "envault_locked"
    } else {
        "envault_not_running"
    };
    print_error(
        output,
        &StructuredError {
            code: code.into(),
            message: "EnVault service is not active".into(),
            help: vec!["Run `envault start`".into()],
            request_id: Uuid::new_v4(),
            retryable: true,
        },
    )
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
            serde_json::to_string(&error).expect("error serializes")
        ),
        Output::Toon => eprintln!(
            "error{{code,message,request_id,retryable,help}}: {},{},{},{},[{}]",
            error.code,
            error.message,
            error.request_id,
            error.retryable,
            error.help.join(";")
        ),
    }
    ExitCode::FAILURE
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
