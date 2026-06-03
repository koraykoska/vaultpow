// Catch-all: pass arbitrary args to `vault` with the current cluster's env.
//
// When the shell hook is installed, the wrapped `vault` function handles this
// flow more efficiently. This codepath is mainly for users who haven't
// installed the hook yet and run `vaultpow kv get secret/foo` directly.

use std::process::{Command, ExitCode};

use anyhow::{anyhow, Context, Result};

use crate::commands::resolve_current;
use crate::config;
use crate::vault::{self, TokenState};

pub fn run(args: Vec<String>) -> Result<ExitCode> {
    if args.is_empty() {
        return Err(anyhow!("missing subcommand. Run `vaultpow --help`."));
    }

    let mut cfg = config::load()?;
    let cluster_name = resolve_current(&mut cfg)?;

    // Attempt to ensure freshness, but don't fail the whole command if the
    // server is unreachable — the user's command might still work (e.g.
    // `vault status`, or a token operation that doesn't need our help).
    match vault::classify(cfg.cluster(&cluster_name).unwrap()) {
        TokenState::Ok | TokenState::Unreachable => {}
        TokenState::Renewable => {
            crate::commands::renew::run().or_else(|_| crate::commands::auth::refresh(None))?;
        }
        TokenState::Expiring | TokenState::Expired | TokenState::Absent => {
            crate::commands::auth::refresh(None)?;
        }
    }

    // Reload after potential auth
    let cfg = config::load()?;
    let c = cfg.cluster(&cluster_name).unwrap();

    // Friendly upfront check — better than the bare ENOENT from spawn().
    // Returns the resolved CLI (vault or bao) and its path.
    let (cli_name, cli_path) = crate::commands::ensure_vault_cli_installed()?;

    let mut cmd = Command::new(&cli_path);
    cmd.args(&args);
    // Set both VAULT_* and BAO_* — works for either CLI.
    cmd.env("VAULT_ADDR", &c.server);
    cmd.env("BAO_ADDR", &c.server);
    if let Some(ns) = c.namespace.as_deref().filter(|s| !s.is_empty()) {
        cmd.env("VAULT_NAMESPACE", ns);
        cmd.env("BAO_NAMESPACE", ns);
    } else {
        cmd.env_remove("VAULT_NAMESPACE");
        cmd.env_remove("BAO_NAMESPACE");
    }
    if let Some(t) = c
        .current_auth()
        .and_then(|a| a.token.as_deref())
        .filter(|s| !s.is_empty())
    {
        cmd.env("VAULT_TOKEN", t);
        cmd.env("BAO_TOKEN", t);
    } else {
        cmd.env_remove("VAULT_TOKEN");
        cmd.env_remove("BAO_TOKEN");
    }

    let status = cmd
        .status()
        .with_context(|| format!("running {cli_name} CLI (is it installed?)"))?;
    let code = status.code().unwrap_or(1);
    let exit = u8::try_from(code).unwrap_or(1);
    Ok(ExitCode::from(exit))
}
