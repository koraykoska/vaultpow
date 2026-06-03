use std::process::ExitCode;

use anyhow::Result;

use crate::config;
use crate::vault::{self, TokenState};

/// Print the current token's state. Exit 0 unless we couldn't determine it
/// (in which case "absent" is printed and we still exit 0 — the shell hook
/// uses the printed value, not the exit code).
pub fn run() -> Result<ExitCode> {
    let cfg = config::load()?;
    let Some(cur) = cfg.current() else {
        println!("absent");
        return Ok(ExitCode::SUCCESS);
    };

    let state = vault::classify(cur);
    println!("{}", state.as_str());

    // Persist any metadata we may have learned during classification by
    // doing a fresh lookup if the cache was empty. Operates on the cluster's
    // currently selected auth — if there isn't one, classify already
    // returned Absent and we'd never get here.
    let needs_fresh = matches!(
        state,
        TokenState::Ok | TokenState::Renewable | TokenState::Expiring
    ) && cur
        .current_auth()
        .map(|a| a.expire_time.is_none())
        .unwrap_or(false);
    if needs_fresh {
        persist_lookup(&cfg, &cur.name);
    }
    Ok(ExitCode::SUCCESS)
}

fn persist_lookup(cfg: &config::Config, cluster_name: &str) {
    let Some(cluster) = cfg.cluster(cluster_name).cloned() else {
        return;
    };
    let Some(auth_name) = cluster.current_auth().map(|a| a.name.clone()) else {
        return;
    };
    if let Ok(Some(fresh)) = vault::token_lookup(&cluster) {
        let mut cfg = cfg.clone();
        if let Some(c) = cfg.cluster_mut(cluster_name) {
            if let Some(a) = c.auth_mut(&auth_name) {
                fresh.apply_to(a);
                let _ = config::save(&cfg);
            }
        }
    }
}
