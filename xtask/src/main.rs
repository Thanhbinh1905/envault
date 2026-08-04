#![forbid(unsafe_code)]

use std::{
    collections::BTreeSet,
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{Context, Result, bail};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Contract {
    schema_version: u32,
    command: Vec<CommandContract>,
}

#[derive(Debug, Deserialize)]
struct CommandContract {
    path: String,
    auth: String,
    daemon: String,
    agent: toml::Value,
    outputs: Vec<String>,
    errors: Vec<String>,
}

fn main() -> Result<()> {
    let task = env::args().nth(1).unwrap_or_else(|| "help".to_owned());
    match task.as_str() {
        "contract" => verify_contract(),
        "package-verify" => verify_packages(),
        "sync-contract" => sync_contract(),
        "verify" => verify(),
        _ => {
            println!("xtask commands: contract, package-verify, sync-contract, verify");
            Ok(())
        }
    }
}

fn verify_packages() -> Result<()> {
    const PACKAGES: &[&str] = &[
        "envault-core",
        "envault-windows-ffi",
        "envault-platform",
        "envault-broker",
        "envault-protocol",
        "envault-crypto",
        "envault-store",
        "envault-service",
        "envault",
    ];

    verify_contract()?;
    run(
        "cargo",
        &["package", "--workspace", "--allow-dirty", "--no-verify"],
    )?;
    let version = env!("CARGO_PKG_VERSION");
    let verification_root = PathBuf::from("target/package-verification");
    if verification_root.exists() {
        fs::remove_dir_all(&verification_root).context("clear package verification directory")?;
    }
    fs::create_dir_all(&verification_root).context("create package verification directory")?;
    for package in PACKAGES {
        let archive = format!("target/package/{package}-{version}.crate");
        run(
            "tar",
            &[
                "-xzf",
                &archive,
                "-C",
                verification_root
                    .to_str()
                    .context("package verification path is not UTF-8")?,
            ],
        )?;
    }
    let members = PACKAGES
        .iter()
        .map(|package| format!("  \"{package}-{version}\","))
        .collect::<Vec<_>>()
        .join("\n");
    let patches = PACKAGES
        .iter()
        .map(|package| format!("{package} = {{ path = \"{package}-{version}\" }}"))
        .collect::<Vec<_>>()
        .join("\n");
    fs::write(
        verification_root.join("Cargo.toml"),
        format!(
            "[workspace]\nmembers = [\n{members}\n]\nresolver = \"3\"\n\n[patch.crates-io]\n{patches}\n"
        ),
    )
    .context("write package verification workspace")?;
    run_in(
        &verification_root,
        "cargo",
        &["test", "--workspace", "--all-targets", "--no-run"],
    )?;
    println!("packaged crate tarballs compile together with local registry patches");
    Ok(())
}

fn sync_contract() -> Result<()> {
    fs::copy("commands.toml", "crates/envault/commands.toml")
        .context("synchronize packaged command contract")?;
    println!("packaged command contract synchronized");
    Ok(())
}

fn verify() -> Result<()> {
    verify_contract()?;
    run("cargo", &["fmt", "--all", "--", "--check"])?;
    run(
        "cargo",
        &[
            "clippy",
            "--workspace",
            "--exclude",
            "envault-desktop",
            "--all-targets",
            "--",
            "-D",
            "warnings",
        ],
    )?;
    run(
        "cargo",
        &["test", "--workspace", "--exclude", "envault-desktop"],
    )?;
    run(
        "cargo",
        &[
            "test",
            "--workspace",
            "--exclude",
            "envault-desktop",
            "--doc",
        ],
    )?;
    Ok(())
}

fn verify_contract() -> Result<()> {
    let source = fs::read_to_string("commands.toml").context("read commands.toml")?;
    let packaged_contract = fs::read_to_string("crates/envault/commands.toml")
        .context("read packaged command contract")?;
    if packaged_contract != source {
        bail!("packaged command contract has drifted; copy commands.toml into crates/envault");
    }
    let contract: Contract = toml::from_str(&source).context("parse commands.toml")?;
    if contract.schema_version != 1 {
        bail!("unsupported command contract schema");
    }
    let mut paths = BTreeSet::new();
    for command in &contract.command {
        validate_command_contract(command, &mut paths)?;
    }
    if Path::new(".agents/skills/envault").is_dir() {
        let skill = fs::read_to_string(".agents/skills/envault/SKILL.md").context("read skill")?;
        for required in [
            "envault start",
            "envault session setup",
            "secret list --fields description",
            "envault run --profile",
            "no capability token",
            "Never reveal",
            "Never start the daemon",
            "Never authenticate",
        ] {
            if !skill.contains(required) {
                bail!("skill is missing contract text: {required}");
            }
        }
        for path in [
            ".agents/skills/envault/references/command-contract.md",
            ".agents/skills/envault/references/security-boundary.md",
            ".agents/skills/envault/agents/openai.yaml",
        ] {
            if !Path::new(path).is_file() {
                bail!("required skill resource is missing: {path}");
            }
        }
        let command_reference =
            fs::read_to_string(".agents/skills/envault/references/command-contract.md")
                .context("read skill command reference")?;
        for required in [
            "session context",
            "session setup",
            "secret list --fields description",
            "envault request http",
            "envault run --profile",
            "no capability token",
        ] {
            if !command_reference.contains(required) {
                bail!("skill command reference is missing: {required}");
            }
        }
        let security_reference =
            fs::read_to_string(".agents/skills/envault/references/security-boundary.md")
                .context("read skill security reference")?;
        for required in [
            "Never use admin commands",
            "Never start EnVault",
            "Never authenticate",
            "Never ask for plaintext",
        ] {
            if !security_reference.contains(required) {
                bail!("skill security reference is missing: {required}");
            }
        }
        let openai = fs::read_to_string(".agents/skills/envault/agents/openai.yaml")
            .context("read skill OpenAI metadata")?;
        if !openai.contains("$envault") || !openai.contains("short_description: \"") {
            bail!("skill OpenAI metadata is not generated from the contract");
        }
    } else {
        println!(
            "skipping agent skill contract check: .agents/ is untracked dev-only content and absent here"
        );
    }
    for path in [
        "docs/threat-model.md",
        "docs/adr/0001-crypto-key-hierarchy.md",
        "docs/adr/0002-explicit-daemon-lifecycle.md",
        "docs/adr/0003-authenticated-ipc.md",
        "docs/adr/0004-capability-tokens.md",
        "docs/adr/0005-encrypted-portability-packages.md",
        "docs/adr/0006-agent-blind-broker.md",
        "docs/adr/0007-application-service-boundary.md",
        "docs/adr/0008-deterministic-scope-policy.md",
        "docs/adr/0009-daemon-runtime-state.md",
        "docs/adr/0010-agent-context-and-http-broker.md",
        "docs/adr/0011-portability-import-plans.md",
        "docs/adr/0012-tui-no-plaintext-disclosure.md",
        "docs/adr/0013-windows-named-pipe-transport.md",
        "docs/adr/0014-os-keystore-convenience-unlock.md",
    ] {
        if !Path::new(path).is_file() {
            bail!("required architecture document is missing: {path}");
        }
    }
    println!("command and security contracts are consistent");
    Ok(())
}

fn validate_command_contract(
    command: &CommandContract,
    paths: &mut BTreeSet<String>,
) -> Result<()> {
    const AUTH_CLASSES: &[&str] = &[
        "bootstrap",
        "human",
        "service",
        "admin",
        "agent",
        "service_or_agent",
    ];
    const DAEMON_CLASSES: &[&str] = &["forbidden", "optional", "spawns", "required"];
    let outputs = command
        .outputs
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let expected_outputs = ["human", "json", "toon"]
        .into_iter()
        .collect::<BTreeSet<_>>();
    let errors = command
        .errors
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let valid_agent = command.agent.as_bool().is_some()
        || matches!(command.agent.as_str(), Some("discovery_only"));
    if command.path.trim().is_empty()
        || !AUTH_CLASSES.contains(&command.auth.as_str())
        || !DAEMON_CLASSES.contains(&command.daemon.as_str())
        || !valid_agent
        || outputs != expected_outputs
        || command.errors.is_empty()
        || errors.len() != command.errors.len()
        || command.errors.iter().any(|error| error.trim().is_empty())
    {
        bail!("invalid command contract entry: {}", command.path);
    }
    if !paths.insert(command.path.clone()) {
        bail!("duplicate command contract path: {}", command.path);
    }
    Ok(())
}

fn run(program: &str, arguments: &[&str]) -> Result<()> {
    let mut command = Command::new(program);
    run_command(&mut command, program, arguments)
}

fn run_in(directory: &Path, program: &str, arguments: &[&str]) -> Result<()> {
    let mut command = Command::new(program);
    command.current_dir(directory);
    run_command(&mut command, program, arguments)
}

fn run_command(command: &mut Command, program: &str, arguments: &[&str]) -> Result<()> {
    let status = command
        .args(arguments)
        .status()
        .with_context(|| format!("run {program}"))?;
    if !status.success() {
        bail!("{program} failed with {status}");
    }
    Ok(())
}
