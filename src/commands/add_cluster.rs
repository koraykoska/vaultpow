use anyhow::{anyhow, Result};
use dialoguer::Input;

use crate::config::{self, Cluster};

pub fn run(
    name: Option<String>,
    server: Option<String>,
    namespace: Option<String>,
    non_interactive: bool,
) -> Result<()> {
    let mut cfg = config::load()?;

    let name = match name {
        Some(n) => n,
        None if non_interactive => {
            return Err(anyhow!("--name is required in non-interactive mode"))
        }
        None => Input::<String>::new()
            .with_prompt("Cluster name")
            .interact_text()
            .map_err(|e| anyhow!("prompt failed: {e}"))?,
    };

    if name.trim().is_empty() {
        return Err(anyhow!("cluster name cannot be empty"));
    }

    if cfg.cluster(&name).is_some() {
        return Err(anyhow!(
            "cluster '{name}' already exists.\n\nUse `vaultpow remove-cluster {name}` to replace it."
        ));
    }

    let server = match server {
        Some(s) => s,
        None if non_interactive => {
            return Err(anyhow!("--server is required in non-interactive mode"))
        }
        None => Input::<String>::new()
            .with_prompt("Vault server URL (e.g. https://vault.example.com:8200)")
            .interact_text()
            .map_err(|e| anyhow!("prompt failed: {e}"))?,
    };

    if !server.starts_with("http://") && !server.starts_with("https://") {
        return Err(anyhow!(
            "server URL must start with http:// or https:// (got '{server}')"
        ));
    }

    let namespace = match namespace {
        Some(n) if !n.is_empty() => Some(n),
        Some(_) => None,
        None if non_interactive => None,
        None => {
            let ns: String = Input::new()
                .with_prompt("Namespace (optional, blank = root)")
                .allow_empty(true)
                .interact_text()
                .map_err(|e| anyhow!("prompt failed: {e}"))?;
            if ns.is_empty() {
                None
            } else {
                Some(ns)
            }
        }
    };

    let became_current = cfg.clusters.is_empty();

    cfg.clusters.push(Cluster {
        name: name.clone(),
        server,
        namespace,
        // No auth profiles yet — `vaultpow auth add` (or the bare
        // `vaultpow auth` shortcut) creates the first one.
        ..Default::default()
    });

    if became_current {
        cfg.current_cluster = name.clone();
    }

    config::save(&cfg)?;

    if became_current {
        println!("added '{name}' (set as current)");
    } else {
        println!("added '{name}'");
    }
    Ok(())
}
