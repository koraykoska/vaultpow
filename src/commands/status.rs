use anyhow::Result;
use chrono::DateTime;

use crate::config;

pub fn run() -> Result<()> {
    let cfg = config::load()?;
    let Some(cur) = cfg.current() else {
        println!("current cluster: (none)");
        if cfg.clusters.is_empty() {
            println!("\nRun `vaultpow add-cluster` to add one.");
        } else {
            println!("\nRun `vaultpow ctx <name>` to select one.");
        }
        return Ok(());
    };

    println!("current cluster: {}", cur.name);
    println!("  server:    {}", cur.server);

    match cur.namespace.as_deref() {
        Some(ns) if !ns.is_empty() => println!("  namespace: {ns}"),
        _ => println!("  namespace: (root)"),
    }

    // Auth section. With multi-auth, status summarises all named auths and
    // marks the current one with `*`. Token detail is shown for the current
    // auth (since that's what `vault`/`bao` will actually use).
    if cur.auths.is_empty() {
        println!("  auths:     (none — run: vaultpow auth add)");
        return Ok(());
    }

    println!("  auths:");
    for a in &cur.auths {
        let marker = if a.name == cur.current_auth { "*" } else { " " };
        let method = a.method.as_deref().unwrap_or("?");
        let params = if a.params.is_empty() {
            String::new()
        } else {
            let pairs: Vec<String> = a.params.iter().map(|(k, v)| format!("{k}={v}")).collect();
            format!(" [{}]", pairs.join(", "))
        };
        let namespaces = if a.namespaces.is_empty() {
            " ns=(unscoped)".to_string()
        } else {
            format!(" ns=[{}]", a.namespaces.join(", "))
        };
        let token_marker = if a.token.as_deref().filter(|t| !t.is_empty()).is_some() {
            ""
        } else {
            " (no token yet)"
        };
        println!(
            "    {marker} {name}  method={method}{params}{namespaces}{token_marker}",
            name = a.name
        );
    }

    let Some(cur_auth) = cur.current_auth() else {
        println!("  current auth: (none — run: vaultpow auth use <name>)");
        return Ok(());
    };
    println!("  current auth: {}", cur_auth.name);

    if cur_auth
        .token
        .as_deref()
        .filter(|t| !t.is_empty())
        .is_some()
    {
        let renew_marker = if cur_auth.renewable == Some(true) {
            " renewable"
        } else {
            ""
        };
        match cur_auth.expire_time.as_deref() {
            Some(et) => println!("  token:     stored (expires {et}{renew_marker})"),
            None => println!("  token:     stored"),
        }

        if let (Some(ct), Some(cttl)) = (cur_auth.creation_time, cur_auth.creation_ttl) {
            if cttl > 0 {
                if let Some(hard) = DateTime::from_timestamp(ct + cttl, 0) {
                    println!("  max_ttl:   {}", hard.to_rfc3339());
                }
            } else {
                println!("  max_ttl:   (periodic)");
            }
        }
    } else {
        println!("  token:     (none — run: vaultpow auth)");
    }

    Ok(())
}
