// Namespace operations. Local-only for `set` (selects which namespace this
// cluster's commands target). Server-side for `list`, `add`, `rm` (Enterprise).

use anyhow::{anyhow, Context, Result};

use crate::commands::{info, resolve_current};
use crate::config;
use crate::vault::TokenState;

pub fn show() -> Result<()> {
    let mut cfg = config::load()?;
    let cluster_name = resolve_current(&mut cfg)?;
    let c = cfg.cluster(&cluster_name).unwrap();
    match c.namespace.as_deref() {
        Some(ns) if !ns.is_empty() => println!("{ns}"),
        _ => println!("(root)"),
    }
    Ok(())
}

pub fn set(name: String) -> Result<()> {
    let mut cfg = config::load()?;
    let cluster_name = resolve_current(&mut cfg)?;
    let c = cfg.cluster_mut(&cluster_name).unwrap();
    c.namespace = if name.is_empty() {
        None
    } else {
        Some(name.clone())
    };
    config::save(&cfg)?;
    if name.is_empty() {
        println!("namespace for '{cluster_name}' set to (root)");
    } else {
        println!("namespace for '{cluster_name}' set to '{name}'");
    }
    Ok(())
}

pub fn list() -> Result<()> {
    let mut cfg = config::load()?;
    let cluster_name = resolve_current(&mut cfg)?;

    ensure_authed(&mut cfg, &cluster_name)?;

    let c = cfg.cluster(&cluster_name).unwrap();
    forward_vault(c, &["namespace", "list"]).with_context(|| {
        "could not list namespaces (Vault OSS, missing permissions, or other server error)"
            .to_string()
    })
}

pub fn add(name: String) -> Result<()> {
    let mut cfg = config::load()?;
    let cluster_name = resolve_current(&mut cfg)?;
    ensure_authed(&mut cfg, &cluster_name)?;

    let c = cfg.cluster(&cluster_name).unwrap();
    forward_vault(c, &["namespace", "create", &name]).with_context(|| {
        format!("failed to create namespace '{name}' (Vault Enterprise feature)")
    })?;
    println!("created namespace '{name}' on '{cluster_name}'");
    Ok(())
}

pub fn rm(name: String) -> Result<()> {
    let mut cfg = config::load()?;
    let cluster_name = resolve_current(&mut cfg)?;
    ensure_authed(&mut cfg, &cluster_name)?;

    let c = cfg.cluster(&cluster_name).unwrap();
    forward_vault(c, &["namespace", "delete", &name])
        .with_context(|| format!("failed to delete namespace '{name}'"))?;

    // If the user just deleted the namespace they had selected, clear the
    // local selection so subsequent commands don't blow up against a missing ns.
    let should_clear = cfg
        .cluster(&cluster_name)
        .and_then(|c| c.namespace.as_deref())
        .map(|n| n == name.as_str())
        .unwrap_or(false);
    if should_clear {
        if let Some(c) = cfg.cluster_mut(&cluster_name) {
            c.namespace = None;
        }
        config::save(&cfg)?;
    }
    println!("deleted namespace '{name}'");
    Ok(())
}

/// Make sure we have a usable token before running a server-side namespace op.
fn ensure_authed(cfg: &mut config::Config, cluster_name: &str) -> Result<()> {
    let c = cfg.cluster(cluster_name).unwrap().clone();
    let state = crate::vault::classify(&c);
    match state {
        TokenState::Ok | TokenState::Renewable => Ok(()),
        TokenState::Expiring | TokenState::Expired | TokenState::Absent => {
            info(format!("authentication required for '{cluster_name}'"));
            crate::commands::auth::refresh(None)
        }
        TokenState::Unreachable => Err(anyhow!("vault server for '{cluster_name}' is unreachable")),
    }
}

fn forward_vault(cluster: &config::Cluster, args: &[&str]) -> Result<()> {
    use std::process::Command;
    // Friendly upfront check — better than the bare ENOENT from spawn().
    // Returns the resolved CLI (vault or bao) and its path.
    let (cli_name, cli_path) = crate::commands::ensure_vault_cli_installed()?;

    let mut cmd = Command::new(&cli_path);
    cmd.args(args);
    // Set both VAULT_* and BAO_* — works for either CLI.
    cmd.env("VAULT_ADDR", &cluster.server);
    cmd.env("BAO_ADDR", &cluster.server);
    if let Some(ns) = &cluster.namespace {
        if !ns.is_empty() {
            cmd.env("VAULT_NAMESPACE", ns);
            cmd.env("BAO_NAMESPACE", ns);
        }
    }
    if let Some(t) = cluster.current_auth().and_then(|a| a.token.as_deref()) {
        if !t.is_empty() {
            cmd.env("VAULT_TOKEN", t);
            cmd.env("BAO_TOKEN", t);
        }
    }
    let status = cmd
        .status()
        .with_context(|| format!("running {cli_name} CLI (is it installed?)"))?;
    if !status.success() {
        return Err(anyhow!(
            "vault command failed (exit {})",
            status.code().unwrap_or(-1)
        ));
    }
    Ok(())
}
