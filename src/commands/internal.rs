use anyhow::{anyhow, Result};

use crate::config;
use crate::vault;

/// Called by the shell wrapper after `vault login` (or `bao login`) — store
/// the captured token onto the cluster's *currently selected* named auth.
///
/// If the cluster has no current_auth (e.g. user removed it but didn't pick
/// a replacement), we error out. The wrapper then surfaces this to the
/// user with a hint to `vaultpow auth use <name>` or `auth add`. We don't
/// silently create a "default" entry because that would mask the user's
/// intent — they should explicitly say which named auth this login refreshes.
pub fn set_token(cluster_name: String, token: String) -> Result<()> {
    let mut cfg = config::load()?;

    let cluster = cfg
        .cluster(&cluster_name)
        .ok_or_else(|| anyhow!("cluster '{cluster_name}' not found"))?;
    let auth_name = cluster.current_auth().map(|a| a.name.clone()).ok_or_else(|| {
        anyhow!(
            "cluster '{cluster_name}' has no current auth selected.\n\nThe shell wrapper captured a token but doesn't know which named\nauth to store it on. Run `vaultpow auth use <name>` to pick one,\nor `vaultpow auth add` to create one, then re-login."
        )
    })?;

    {
        let c = cfg.cluster_mut(&cluster_name).unwrap();
        let a = c.auth_mut(&auth_name).unwrap();
        a.token = Some(token);
    }
    config::save(&cfg)?;

    // Try to populate metadata. Best-effort: if it fails (e.g. server is now
    // unreachable, or token-lookup-self is denied) we just keep the token.
    let cluster = cfg.cluster(&cluster_name).unwrap().clone();
    if let Ok(Some(fresh)) = vault::token_lookup(&cluster) {
        if let Some(c) = cfg.cluster_mut(&cluster_name) {
            if let Some(a) = c.auth_mut(&auth_name) {
                fresh.apply_to(a);
            }
        }
        config::save(&cfg)?;
    }
    Ok(())
}
