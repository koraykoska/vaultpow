use anyhow::{anyhow, Result};

use crate::commands::resolve_current;
use crate::config;
use crate::vault;

pub fn run() -> Result<()> {
    let mut cfg = config::load()?;
    let cluster_name = resolve_current(&mut cfg)?;
    let cluster = cfg.cluster(&cluster_name).unwrap().clone();

    // Need a current auth to renew. Without one we surface a clear message
    // (rather than the bare "no token to renew" from vault.rs) and point
    // the user at the named-auth flow.
    let auth_name = cluster
        .current_auth()
        .map(|a| a.name.clone())
        .ok_or_else(|| {
            anyhow!(
                "no auth selected for '{cluster_name}'.\n\nRun `vaultpow auth list` to see available auths\nor `vaultpow auth use <name>` to switch."
            )
        })?;

    // Compute increment based on creation_ttl, capped by remaining time to
    // the hard deadline.
    let increment = cluster.current_auth().and_then(compute_increment);

    let lifecycle = vault::token_renew(&cluster, increment)
        .map_err(|e| anyhow!("renewal failed: {e}\n\nTry `vaultpow auth` for a fresh login."))?;

    let mc = cfg.cluster_mut(&cluster_name).unwrap();
    let auth = mc
        .auth_mut(&auth_name)
        .ok_or_else(|| anyhow!("internal: auth '{auth_name}' vanished mid-renew"))?;
    lifecycle.apply_to(auth);
    config::save(&cfg)?;

    let c = cfg.cluster(&cluster_name).unwrap();
    match c.current_auth().and_then(|a| a.expire_time.as_deref()) {
        Some(et) => {
            println!("renewed token for '{cluster_name}' (auth '{auth_name}', expires {et})")
        }
        None => println!("renewed token for '{cluster_name}' (auth '{auth_name}')"),
    }
    Ok(())
}

fn compute_increment(auth: &config::Auth) -> Option<i64> {
    let cttl = auth.creation_ttl?;
    if cttl == 0 {
        return None; // periodic token: no specific increment
    }
    let ct = auth.creation_time?;
    let now = chrono::Utc::now().timestamp();
    let hard_deadline = ct + cttl;
    let remaining = hard_deadline - now - 5; // 5s buffer
    if remaining <= 0 {
        return None;
    }
    Some(cttl.min(remaining))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Auth;

    fn auth(creation_time: Option<i64>, creation_ttl: Option<i64>) -> Auth {
        Auth {
            name: "t".into(),
            token: Some("hvs.x".into()),
            creation_time,
            creation_ttl,
            ..Default::default()
        }
    }

    #[test]
    fn compute_increment_none_for_missing_metadata() {
        assert!(compute_increment(&auth(None, None)).is_none());
        assert!(compute_increment(&auth(Some(0), None)).is_none());
        assert!(compute_increment(&auth(None, Some(3600))).is_none());
    }

    #[test]
    fn compute_increment_none_for_periodic_token() {
        let a = auth(Some(chrono::Utc::now().timestamp()), Some(0));
        assert!(compute_increment(&a).is_none());
    }

    #[test]
    fn compute_increment_caps_at_remaining_window() {
        // Token issued 30 minutes ago, max_ttl 1 hour → ~30 min remaining.
        let now = chrono::Utc::now().timestamp();
        let a = auth(Some(now - 1800), Some(3600));
        let inc = compute_increment(&a).expect("expected Some");
        // Remaining ≈ 1795 (3600 - 1800 - 5). Should cap there, not at cttl.
        assert!(inc > 0 && inc < 3600, "expected 0 < inc < 3600, got {inc}");
        assert!((1790..=1795).contains(&inc), "got {inc}");
    }

    #[test]
    fn compute_increment_returns_full_cttl_when_far_from_deadline() {
        let now = chrono::Utc::now().timestamp();
        // creation_time in the future would be silly, but we want remaining ≫ cttl.
        let a = auth(Some(now + 3600), Some(60));
        let inc = compute_increment(&a).unwrap();
        assert_eq!(inc, 60);
    }

    #[test]
    fn compute_increment_none_at_or_past_hard_deadline() {
        let now = chrono::Utc::now().timestamp();
        // Issued 2 hours ago, max_ttl 1 hour → already past deadline.
        let a = auth(Some(now - 7200), Some(3600));
        assert!(compute_increment(&a).is_none());
    }
}
