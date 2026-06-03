use anyhow::Result;
use shell_escape::escape;
use std::borrow::Cow;

use crate::commands::resolve_current;
use crate::config;

pub fn run() -> Result<()> {
    let mut cfg = config::load()?;
    let cluster_name = resolve_current(&mut cfg)?;
    let c = cfg.cluster(&cluster_name).unwrap();

    // Emit both VAULT_* and BAO_* — tokens/addresses/namespaces are the same
    // wire concept in HashiCorp Vault and OpenBao, and exporting both means
    // the user can use either CLI without thinking about it. OpenBao
    // currently falls back to VAULT_* when BAO_* is unset, but emitting both
    // is future-proof and trivially cheap.
    let addr = q(&c.server);
    println!("export VAULT_ADDR={addr}");
    println!("export BAO_ADDR={addr}");

    match c.namespace.as_deref() {
        Some(ns) if !ns.is_empty() => {
            let ns = q(ns);
            println!("export VAULT_NAMESPACE={ns}");
            println!("export BAO_NAMESPACE={ns}");
        }
        _ => {
            println!("unset VAULT_NAMESPACE");
            println!("unset BAO_NAMESPACE");
        }
    }

    // Token comes from the *current* named auth on this cluster. If there
    // isn't one selected (or it has no token cached), unset both.
    match c.current_auth().and_then(|a| a.token.as_deref()) {
        Some(t) if !t.is_empty() => {
            let t = q(t);
            println!("export VAULT_TOKEN={t}");
            println!("export BAO_TOKEN={t}");
        }
        _ => {
            println!("unset VAULT_TOKEN");
            println!("unset BAO_TOKEN");
        }
    }

    Ok(())
}

fn q(s: &str) -> String {
    escape(Cow::from(s)).into_owned()
}
