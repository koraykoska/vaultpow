pub mod add_cluster;
pub mod auth;
pub mod check_token;
pub mod completions;
pub mod ctx;
pub mod ensure_fresh;
pub mod env;
pub mod forward;
pub mod internal;
pub mod ns;
pub mod remove_cluster;
pub mod renew;
pub mod shell_init;
pub mod status;

use anyhow::{anyhow, Result};
use dialoguer::Select;

use crate::config::{Cluster, Config};

/// Resolve the current cluster, prompting if unset. Persists the choice.
pub fn resolve_current(cfg: &mut Config) -> Result<String> {
    if let Some(c) = cfg.current() {
        return Ok(c.name.clone());
    }
    if cfg.clusters.is_empty() {
        return Err(anyhow!(
            "no clusters configured.\n\nRun `vaultpow add-cluster` to add one."
        ));
    }

    let names: Vec<String> = cfg.clusters.iter().map(|c| c.name.clone()).collect();
    let idx = Select::new()
        .with_prompt("Select a cluster")
        .items(&names)
        .default(0)
        .interact()
        .map_err(|e| anyhow!("interactive prompt failed: {e}"))?;

    let name = names[idx].clone();
    cfg.current_cluster = name.clone();
    crate::config::save(cfg)?;
    Ok(name)
}

/// Print to stderr — used for human-readable status messages that shouldn't
/// pollute stdout (which scripts may capture).
pub fn info(msg: impl AsRef<str>) {
    eprintln!("vaultpow: {}", msg.as_ref());
}

/// Like `info`, but semantically a warning. Same destination for now; kept
/// distinct so we can add color/prefix later without changing call sites.
pub fn warn(msg: impl AsRef<str>) {
    eprintln!("vaultpow: warning: {}", msg.as_ref());
}

/// Get a cluster by name from a Config or error.
pub fn cluster_or_error<'a>(cfg: &'a Config, name: &str) -> Result<&'a Cluster> {
    cfg.cluster(name).ok_or_else(|| {
        anyhow!("cluster '{name}' not found.\n\nRun `vaultpow ctx` to see configured clusters.")
    })
}

/// Names of CLIs vaultpow can shell out to, in preference order. `vault` is
/// tried first because most users still have HashiCorp Vault installed and
/// expect that behaviour; `bao` is the OpenBao fork and is wire-compatible.
/// Override the choice with `VAULTPOW_VAULT_BIN`.
const VAULT_CLI_CANDIDATES: &[&str] = &["vault", "bao"];

/// Look up a `vault`-compatible binary in PATH. Tries `$VAULTPOW_VAULT_BIN`
/// first if set, then `vault`, then `bao`. Returns the binary's name and
/// resolved path, or `None` if nothing is installed.
///
/// Implemented inline (no `which` crate) — PATH lookup is trivial.
pub fn find_vault_cli() -> Option<(String, std::path::PathBuf)> {
    if let Ok(name) = std::env::var("VAULTPOW_VAULT_BIN") {
        let trimmed = name.trim();
        if !trimmed.is_empty() {
            // Honour the override even if the user set it to something we
            // wouldn't pick on our own. If it doesn't exist, that's their
            // problem and they get a clear error from ensure_*.
            if let Some(p) = which(trimmed) {
                return Some((trimmed.to_string(), p));
            }
            // Don't silently fall through — if the override doesn't resolve,
            // the user almost certainly has a typo. Surface that.
            return None;
        }
    }
    for &name in VAULT_CLI_CANDIDATES {
        if let Some(p) = which(name) {
            return Some((name.to_string(), p));
        }
    }
    None
}

/// PATH lookup for one binary name. Empty PATH entries are normalised to
/// `.` per POSIX.
fn which(name: &str) -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let dir = if dir.as_os_str().is_empty() {
            std::path::PathBuf::from(".")
        } else {
            dir
        };
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// Bail with an actionable message if neither `vault` nor `bao` is on PATH.
///
/// Called only from commands that actually shell out to one of them (auth,
/// forward, ns add/list/rm). The hot-path commands (check-token,
/// ensure-fresh, env, status) don't pay the PATH walk on every shell-hook
/// invocation — they don't need either CLI.
///
/// Returns the resolved (name, path) so callers can use it directly.
pub fn ensure_vault_cli_installed() -> Result<(String, std::path::PathBuf)> {
    if let Some(found) = find_vault_cli() {
        return Ok(found);
    }
    if let Ok(name) = std::env::var("VAULTPOW_VAULT_BIN") {
        if !name.trim().is_empty() {
            return Err(anyhow!(
                "VAULTPOW_VAULT_BIN is set to '{name}' but that binary was\n\
                 not found on your PATH. Unset VAULTPOW_VAULT_BIN to fall\n\
                 back to auto-detection of `vault`/`bao`."
            ));
        }
    }
    Err(anyhow!(
        "neither the `vault` nor `bao` CLI is on your PATH.\n\n\
         vaultpow shells out to one of them for interactive logins (OIDC,\n\
         userpass) and for namespace management. Install one from\n\
           - https://developer.hashicorp.com/vault/install\n\
           - https://openbao.org/docs/install/\n\
         and try again. Tokens are interchangeable between the two."
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests that mutate PATH (or VAULTPOW_VAULT_BIN) need a Mutex to avoid
    /// stomping each other when cargo runs them in parallel.
    use std::sync::Mutex;
    static PATH_LOCK: Mutex<()> = Mutex::new(());

    fn make_executable(path: &std::path::Path) {
        std::fs::write(path, "#!/bin/sh\nexit 0\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut p = std::fs::metadata(path).unwrap().permissions();
            p.set_mode(0o755);
            std::fs::set_permissions(path, p).unwrap();
        }
    }

    /// Run `f` with PATH set to `dir` and `VAULTPOW_VAULT_BIN` cleared.
    fn with_only_path<F: FnOnce()>(dir: &std::path::Path, f: F) {
        let _g = PATH_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let prev_path = std::env::var_os("PATH");
        let prev_override = std::env::var_os("VAULTPOW_VAULT_BIN");
        unsafe { std::env::set_var("PATH", dir) };
        unsafe { std::env::remove_var("VAULTPOW_VAULT_BIN") };
        f();
        if let Some(p) = prev_path {
            unsafe { std::env::set_var("PATH", p) };
        } else {
            unsafe { std::env::remove_var("PATH") };
        }
        if let Some(v) = prev_override {
            unsafe { std::env::set_var("VAULTPOW_VAULT_BIN", v) };
        }
    }

    #[test]
    fn find_vault_cli_prefers_vault_over_bao() {
        let dir = tempfile::tempdir().unwrap();
        make_executable(&dir.path().join("vault"));
        make_executable(&dir.path().join("bao"));
        with_only_path(dir.path(), || {
            let (name, _) = find_vault_cli().expect("expected to find one");
            assert_eq!(name, "vault");
        });
    }

    #[test]
    fn find_vault_cli_falls_back_to_bao() {
        let dir = tempfile::tempdir().unwrap();
        make_executable(&dir.path().join("bao"));
        with_only_path(dir.path(), || {
            let (name, p) = find_vault_cli().expect("expected to find bao");
            assert_eq!(name, "bao");
            assert!(p.ends_with("bao"));
        });
    }

    #[test]
    fn find_vault_cli_returns_none_when_neither_present() {
        let dir = tempfile::tempdir().unwrap();
        with_only_path(dir.path(), || {
            assert!(find_vault_cli().is_none());
        });
    }

    #[test]
    fn vaultpow_vault_bin_override_is_honoured() {
        let dir = tempfile::tempdir().unwrap();
        make_executable(&dir.path().join("vault"));
        make_executable(&dir.path().join("bao"));
        let _g = PATH_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let prev_path = std::env::var_os("PATH");
        let prev_override = std::env::var_os("VAULTPOW_VAULT_BIN");

        unsafe { std::env::set_var("PATH", dir.path()) };
        unsafe { std::env::set_var("VAULTPOW_VAULT_BIN", "bao") };
        let found = find_vault_cli();

        if let Some(p) = prev_path {
            unsafe { std::env::set_var("PATH", p) };
        } else {
            unsafe { std::env::remove_var("PATH") };
        }
        if let Some(v) = prev_override {
            unsafe { std::env::set_var("VAULTPOW_VAULT_BIN", v) };
        } else {
            unsafe { std::env::remove_var("VAULTPOW_VAULT_BIN") };
        }

        let (name, _) = found.expect("override should resolve");
        assert_eq!(name, "bao");
    }

    #[test]
    fn vaultpow_vault_bin_typo_does_not_silently_fallback() {
        // If the user sets VAULTPOW_VAULT_BIN to something that doesn't
        // exist, we surface that rather than picking up `vault` and
        // confusing them.
        let dir = tempfile::tempdir().unwrap();
        make_executable(&dir.path().join("vault"));
        let _g = PATH_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let prev_path = std::env::var_os("PATH");
        let prev_override = std::env::var_os("VAULTPOW_VAULT_BIN");

        unsafe { std::env::set_var("PATH", dir.path()) };
        unsafe { std::env::set_var("VAULTPOW_VAULT_BIN", "vualt") };
        let found = find_vault_cli();

        if let Some(p) = prev_path {
            unsafe { std::env::set_var("PATH", p) };
        } else {
            unsafe { std::env::remove_var("PATH") };
        }
        if let Some(v) = prev_override {
            unsafe { std::env::set_var("VAULTPOW_VAULT_BIN", v) };
        } else {
            unsafe { std::env::remove_var("VAULTPOW_VAULT_BIN") };
        }

        assert!(
            found.is_none(),
            "typo'd VAULTPOW_VAULT_BIN should not silently resolve"
        );
    }
}
