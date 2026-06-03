// vaultpow — kubectx-style context switcher for HashiCorp Vault
//
// This file wires up the CLI with `clap` and dispatches to the command modules.
// All real work lives in src/commands/*.rs.

mod cli;
mod commands;
mod config;
mod shell;
mod vault;

use std::process::ExitCode;

use anyhow::Result;
use clap::Parser;

use crate::cli::{AuthCommand, Cli, Command, NsCommand};

fn main() -> ExitCode {
    let cli = Cli::parse();

    match run(cli) {
        Ok(code) => code,
        Err(err) => {
            // Format the full error chain. anyhow's Display walks `.context()` calls.
            eprintln!("vaultpow: {err:#}");
            ExitCode::from(1)
        }
    }
}

fn run(cli: Cli) -> Result<ExitCode> {
    match cli.command {
        // No subcommand → status (matches the bash UX)
        None => commands::status::run().map(|_| ExitCode::SUCCESS),

        Some(Command::Status) => commands::status::run().map(|_| ExitCode::SUCCESS),
        Some(Command::Ctx { name }) => commands::ctx::run(name).map(|_| ExitCode::SUCCESS),
        Some(Command::AddCluster {
            name,
            server,
            namespace,
            non_interactive,
        }) => commands::add_cluster::run(name, server, namespace, non_interactive)
            .map(|_| ExitCode::SUCCESS),
        Some(Command::RemoveCluster { name }) => {
            commands::remove_cluster::run(name).map(|_| ExitCode::SUCCESS)
        }
        Some(Command::Auth { action, method }) => match action {
            None => commands::auth::refresh(method).map(|_| ExitCode::SUCCESS),
            Some(AuthCommand::List) => commands::auth::list().map(|_| ExitCode::SUCCESS),
            Some(AuthCommand::Use { name }) => {
                commands::auth::use_auth(name).map(|_| ExitCode::SUCCESS)
            }
            Some(AuthCommand::Add {
                name,
                method,
                path,
                role,
                username,
                non_interactive,
            }) => commands::auth::add(name, method, path, role, username, non_interactive)
                .map(|_| ExitCode::SUCCESS),
            Some(AuthCommand::Rm { name }) => commands::auth::rm(name).map(|_| ExitCode::SUCCESS),
            Some(AuthCommand::Hint) => commands::auth::hint().map(|_| ExitCode::SUCCESS),
        },
        Some(Command::Renew) => commands::renew::run().map(|_| ExitCode::SUCCESS),
        Some(Command::CheckToken) => commands::check_token::run(),
        Some(Command::EnsureFresh) => commands::ensure_fresh::run(),
        Some(Command::Env) => commands::env::run().map(|_| ExitCode::SUCCESS),
        Some(Command::ShellInit { shell }) => {
            commands::shell_init::run(shell).map(|_| ExitCode::SUCCESS)
        }
        Some(Command::Completions { shell }) => {
            commands::completions::run(shell).map(|_| ExitCode::SUCCESS)
        }

        Some(Command::Ns { action }) => match action {
            None => commands::ns::show().map(|_| ExitCode::SUCCESS),
            Some(NsCommand::Show) => commands::ns::show().map(|_| ExitCode::SUCCESS),
            Some(NsCommand::List) => commands::ns::list().map(|_| ExitCode::SUCCESS),
            Some(NsCommand::Set { name }) => commands::ns::set(name).map(|_| ExitCode::SUCCESS),
            Some(NsCommand::Add { name }) => commands::ns::add(name).map(|_| ExitCode::SUCCESS),
            Some(NsCommand::Rm { name }) => commands::ns::rm(name).map(|_| ExitCode::SUCCESS),
            Some(NsCommand::SetShorthand(args)) => {
                // `vaultpow ns <name> [...]` — first arg is the namespace.
                let name = args
                    .into_iter()
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("ns: missing namespace name"))?;
                commands::ns::set(name).map(|_| ExitCode::SUCCESS)
            }
        },

        // Hidden internal subcommand used by the shell wrapper after `vault login`.
        Some(Command::InternalSetToken { cluster, token }) => {
            commands::internal::set_token(cluster, token).map(|_| ExitCode::SUCCESS)
        }

        // The catch-all forwards arbitrary args to `vault`.
        Some(Command::Forward(args)) => commands::forward::run(args),
    }
}
