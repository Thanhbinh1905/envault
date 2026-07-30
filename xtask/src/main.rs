#![forbid(unsafe_code)]

use std::{env, fs, path::Path, process::Command};

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
        "verify" => verify(),
        _ => {
            println!("xtask commands: contract, verify");
            Ok(())
        }
    }
}

fn verify() -> Result<()> {
    verify_contract()?;
    run("cargo", &["fmt", "--all", "--", "--check"])?;
    run(
        "cargo",
        &[
            "clippy",
            "--workspace",
            "--all-targets",
            "--",
            "-D",
            "warnings",
        ],
    )?;
    run("cargo", &["test", "--workspace"])?;
    run("cargo", &["test", "--workspace", "--doc"])?;
    Ok(())
}

fn verify_contract() -> Result<()> {
    let source = fs::read_to_string("commands.toml").context("read commands.toml")?;
    let contract: Contract = toml::from_str(&source).context("parse commands.toml")?;
    if contract.schema_version != 1 {
        bail!("unsupported command contract schema");
    }
    for command in &contract.command {
        if command.path.trim().is_empty()
            || command.auth.trim().is_empty()
            || command.daemon.trim().is_empty()
            || command.outputs.is_empty()
        {
            bail!("incomplete contract entry: {}", command.path);
        }
        if !command.outputs.iter().any(|output| output == "json")
            || !command.outputs.iter().any(|output| output == "toon")
        {
            bail!("command lacks structured output: {}", command.path);
        }
        let _ = (&command.agent, &command.errors);
    }
    let skill = fs::read_to_string(".agents/skills/envault/SKILL.md").context("read skill")?;
    for required in [
        "envault start",
        "envault context",
        "envault request",
        "Never reveal",
    ] {
        if !skill.contains(required) {
            bail!("skill is missing contract text: {required}");
        }
    }
    for path in [
        "docs/threat-model.md",
        "docs/adr/0001-crypto-key-hierarchy.md",
        "docs/adr/0002-explicit-daemon-lifecycle.md",
        "docs/adr/0003-authenticated-ipc.md",
        "docs/adr/0004-capability-tokens.md",
        "docs/adr/0005-encrypted-portability-packages.md",
        "docs/adr/0006-agent-blind-broker.md",
    ] {
        if !Path::new(path).is_file() {
            bail!("required architecture document is missing: {path}");
        }
    }
    println!("command and security contracts are consistent");
    Ok(())
}

fn run(program: &str, arguments: &[&str]) -> Result<()> {
    let status = Command::new(program)
        .args(arguments)
        .status()
        .with_context(|| format!("run {program}"))?;
    if !status.success() {
        bail!("{program} failed with {status}");
    }
    Ok(())
}
