#![forbid(unsafe_code)]

use std::{path::PathBuf, process::ExitCode};

use clap::{Parser, Subcommand, ValueEnum};
use envault_protocol::StructuredError;
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
    Init,
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
        Command::Init => not_implemented(cli.output, "init"),
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
