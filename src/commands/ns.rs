// Namespace operations. Local-only for `set` (selects which namespace this
// cluster's commands target). Server-side for `list`, `add`, `rm` (Enterprise).

use anyhow::{anyhow, Context, Result};
use dialoguer::Select;

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

/// Switch the cluster's selected namespace. If the cluster's currently
/// selected auth doesn't claim to support the new namespace (its
/// `namespaces` allowlist is non-empty and doesn't include this one),
/// we prompt the user to also switch to one of the auths that does
/// — atomically updating both pointers in one save.
///
/// `auth_override = Some(name)` bypasses the prompt for scripts. The
/// named auth must already support the requested namespace; we do NOT
/// auto-extend an auth's allowlist from here (run `vaultpow auth ns add
/// <ns>` explicitly to broaden an auth's scope).
pub fn set(name: String, auth_override: Option<String>) -> Result<()> {
    let mut cfg = config::load()?;
    let cluster_name = resolve_current(&mut cfg)?;
    let cluster = cfg.cluster(&cluster_name).unwrap();

    // Decide whether we also need to switch auth.
    let target_auth: Option<String> = match auth_override {
        Some(override_name) => {
            let a = cluster.auth(&override_name).ok_or_else(|| {
                anyhow!(
                    "--auth '{override_name}' not found on '{cluster_name}'.\n\nRun `vaultpow auth list` to see available auths."
                )
            })?;
            if !a.supports_namespace(&name) {
                return Err(anyhow!(
                    "auth '{override_name}' does not support namespace '{name}'.\n\nIts allowed namespaces: [{allowed}].\nRun `vaultpow auth use {override_name} && vaultpow auth ns add {name}` to broaden its scope explicitly.",
                    allowed = a.namespaces.join(", ")
                ));
            }
            Some(override_name)
        }
        None => {
            // Special case: a cluster with zero auths configured has no
            // scope to violate. Just set the namespace and move on —
            // this preserves the pre-multi-auth UX (`add-cluster` then
            // immediately `ns set X`) and keeps `vaultpow auth add`'s
            // own namespace prompt working when current_auth is unset.
            if cluster.auths.is_empty() {
                None
            } else {
                // No override: check if current auth already supports the
                // target namespace. If so, we leave current_auth alone.
                let current_ok = cluster
                    .current_auth()
                    .map(|a| a.supports_namespace(&name))
                    .unwrap_or(false);
                if current_ok {
                    None
                } else {
                    // Pick from candidates (always-prompt per project
                    // policy — see the AskUserQuestion answer in the
                    // v0.1.2 design).
                    let candidates = cluster.auths_supporting_namespace(&name);
                    if candidates.is_empty() {
                        let cur_msg = match cluster.current_auth() {
                            Some(a) => format!(
                                "current auth '{}' supports only: [{}].",
                                a.name,
                                a.namespaces.join(", ")
                            ),
                            None => "no auth is currently selected.".to_string(),
                        };
                        return Err(anyhow!(
                            "no auth on '{cluster_name}' supports namespace '{name}'.\n\n{cur_msg}\n\nEither:\n  - broaden an existing auth: vaultpow auth use <name> && vaultpow auth ns add {name}\n  - add a new auth scoped to it: vaultpow auth add --namespace {name} ..."
                        ));
                    }
                    // Build a stable display list and Select.
                    let labels: Vec<String> = candidates
                        .iter()
                        .map(|a| {
                            let mark = if a.name == cluster.current_auth {
                                " (current)"
                            } else {
                                ""
                            };
                            let scope = if a.namespaces.is_empty() {
                                " [unscoped]".to_string()
                            } else {
                                format!(" [{}]", a.namespaces.join(", "))
                            };
                            format!("{}{mark}{scope}", a.name)
                        })
                        .collect();
                    eprintln!(
                        "vaultpow: current auth doesn't support namespace '{name}'. Pick an auth that does:"
                    );
                    let idx = Select::new()
                        .items(&labels)
                        .default(0)
                        .interact()
                        .map_err(|e| {
                            anyhow!(
                                "prompt failed: {e}\n\nIn non-interactive contexts, pass --auth <name> to `vaultpow ns set <name>`."
                            )
                        })?;
                    Some(candidates[idx].name.clone())
                }
            }
        }
    };

    // Apply changes atomically.
    {
        let cluster_mut = cfg.cluster_mut(&cluster_name).unwrap();
        cluster_mut.namespace = if name.is_empty() {
            None
        } else {
            Some(name.clone())
        };
        if let Some(a) = target_auth.as_deref() {
            cluster_mut.current_auth = a.to_string();
        }
    }
    config::save(&cfg)?;

    // Confirm.
    let ns_display = if name.is_empty() {
        "(root)".to_string()
    } else {
        format!("'{name}'")
    };
    match target_auth {
        Some(a) => {
            println!("namespace for '{cluster_name}' set to {ns_display}, auth switched to '{a}'")
        }
        None => println!("namespace for '{cluster_name}' set to {ns_display}"),
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
