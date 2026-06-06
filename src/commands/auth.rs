// Multi-auth management for the current cluster.
//
// Subcommands (wired in main.rs):
//   - refresh(method)       — re-auth the cluster's current named auth
//   - list()                — list named auths for current cluster
//   - use_auth(name)        — switch current_auth (no re-auth)
//   - add(name, method, path, role, username, non_interactive)
//                           — create + auth a new named entry; `path` overrides
//                             the default Vault mount path for OIDC/userpass
//                             when the operator mounted them at a custom name
//   - rm(name)              — delete a named auth (never auto-pick a replacement)
//
// Why named auths: a single Vault/OpenBao cluster commonly hosts several
// roles or namespaces a user needs different identities for — e.g. an
// admin OIDC role for `admin/team-a` and a read-only userpass account.
// Named auths let the user keep both tokens cached and switch between them
// instantly with `vaultpow auth use <name>`, instead of re-running the
// browser OIDC flow every time they cross a permission boundary.

use std::process::Command;

use anyhow::{anyhow, Context, Result};
use dialoguer::{Input, Select};

use crate::commands::resolve_current;
use crate::config::{self, Auth, Cluster};
use crate::vault;

/// Default behaviour of `vaultpow auth` (no subcommand): refresh the token
/// for the cluster's currently selected named auth. If no current_auth is
/// set, route the user to `auth add` rather than silently picking one.
pub fn refresh(method_override: Option<String>) -> Result<()> {
    let mut cfg = config::load()?;
    let cluster_name = resolve_current(&mut cfg)?;
    let cluster = cfg.cluster(&cluster_name).unwrap().clone();

    let Some(auth) = cluster.current_auth().cloned() else {
        // No current auth → there's nothing to refresh. If the cluster has
        // no auths at all, fall through to `add` interactively. Otherwise
        // tell the user to pick one explicitly.
        if cluster.auths.is_empty() {
            crate::commands::info(format!(
                "no auths configured for '{cluster_name}' — adding one now"
            ));
            return add(None, method_override, None, None, None, vec![], false);
        }
        return Err(anyhow!(
            "no current auth selected for '{cluster_name}'.\n\nAvailable: {}\nPick one with `vaultpow auth use <name>` or add a new one with\n`vaultpow auth add`.",
            cluster.auths.iter().map(|a| a.name.as_str()).collect::<Vec<_>>().join(", ")
        ));
    };

    let auth_name = auth.name.clone();
    // Resolve the method to use: explicit override wins, then the stored one,
    // then prompt.
    let effective_method = method_override
        .clone()
        .or(auth.method.clone())
        .map(Ok)
        .unwrap_or_else(prompt_method)?;

    let new_token = run_method(
        &effective_method,
        &cluster,
        &auth, // pass stored params (role, username, ...)
    )?;

    persist_token_and_metadata(
        &mut cfg,
        &cluster_name,
        &auth_name,
        &effective_method,
        new_token,
    )?;

    let c = cfg.cluster(&cluster_name).unwrap();
    let a = c.auth(&auth_name).unwrap();
    print_auth_stored(&cluster_name, a);
    Ok(())
}

/// `vaultpow auth list` — show every named auth on the current cluster.
pub fn list() -> Result<()> {
    let mut cfg = config::load()?;
    let cluster_name = resolve_current(&mut cfg)?;
    let cluster = cfg.cluster(&cluster_name).unwrap();

    if cluster.auths.is_empty() {
        println!("no auths configured for '{cluster_name}'");
        println!("\nRun `vaultpow auth add` to create one.");
        return Ok(());
    }

    println!("auths for '{cluster_name}':");
    for a in &cluster.auths {
        let marker = if a.name == cluster.current_auth {
            "*"
        } else {
            " "
        };
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
        let token_marker = match a.token.as_deref().filter(|t| !t.is_empty()) {
            Some(_) => match a.expire_time.as_deref() {
                Some(et) => format!("  (token, expires {et})"),
                None => "  (token cached)".into(),
            },
            None => "  (no token)".into(),
        };
        println!(
            "  {marker} {name}  method={method}{params}{namespaces}{token_marker}",
            name = a.name
        );
    }
    if cluster.current_auth.is_empty() {
        println!("\nNo current auth selected. Pick one with `vaultpow auth use <name>`.");
    }
    Ok(())
}

/// `vaultpow auth use <name>` — switch current_auth (pure config change).
pub fn use_auth(name: String) -> Result<()> {
    let mut cfg = config::load()?;
    let cluster_name = resolve_current(&mut cfg)?;
    let cluster = cfg.cluster_mut(&cluster_name).unwrap();
    if cluster.auth(&name).is_none() {
        let avail = cluster
            .auths
            .iter()
            .map(|a| a.name.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        return Err(anyhow!(
            "auth '{name}' not found on '{cluster_name}'.\n\nAvailable: {avail}\nAdd a new one with `vaultpow auth add`."
        ));
    }
    cluster.current_auth = name.clone();
    config::save(&cfg)?;
    println!("switched to auth '{name}' on '{cluster_name}'");
    Ok(())
}

/// `vaultpow auth add` — create a new named auth and authenticate.
///
/// Interactive by default; pass `--non-interactive` plus the relevant flags
/// to skip prompts. Always sets the new auth as `current_auth`.
#[allow(clippy::too_many_arguments)]
pub fn add(
    name: Option<String>,
    method: Option<String>,
    path: Option<String>,
    role: Option<String>,
    username: Option<String>,
    namespaces: Vec<String>,
    non_interactive: bool,
) -> Result<()> {
    let mut cfg = config::load()?;
    let cluster_name = resolve_current(&mut cfg)?;
    let cluster_snap = cfg.cluster(&cluster_name).unwrap().clone();

    // Pick method first — `name` defaults to it if the user didn't specify.
    let method = match method {
        Some(m) => m,
        None if non_interactive => {
            return Err(anyhow!("--method is required in non-interactive mode"))
        }
        None => prompt_method()?,
    };

    let name = match name {
        Some(n) => n,
        None if non_interactive => method.clone(),
        None => Input::<String>::new()
            .with_prompt("Auth name")
            .default(method.clone())
            .interact_text()
            .map_err(|e| anyhow!("prompt failed: {e}"))?,
    };
    if name.trim().is_empty() {
        return Err(anyhow!("auth name cannot be empty"));
    }
    if cluster_snap.auth(&name).is_some() {
        return Err(anyhow!(
            "auth '{name}' already exists on '{cluster_name}'.\n\nUse `vaultpow auth rm {name}` to replace it."
        ));
    }

    // Build a stub Auth carrying the params the user passed; run_method
    // reads `path`/`role`/`username` out of params for OIDC/userpass.
    let mut stub = Auth {
        name: name.clone(),
        method: Some(method.clone()),
        // De-dup, drop blanks, preserve insertion order. Repeated --namespace
        // flags or interactive comma-input both flow through here.
        namespaces: dedup_namespaces(namespaces),
        ..Default::default()
    };
    if let Some(p) = path.clone().filter(|p| !p.is_empty()) {
        stub.params.insert("path".into(), p);
    }
    if let Some(r) = role.clone().filter(|r| !r.is_empty()) {
        stub.params.insert("role".into(), r);
    }
    if let Some(u) = username.clone().filter(|u| !u.is_empty()) {
        stub.params.insert("username".into(), u);
    }

    // Interactive: prompt for OIDC/userpass-specific params the user didn't
    // pass via flags. Path is the only one truly needed when the operator
    // mounted the method at a non-default location (e.g. -path=google for a
    // Google OIDC integration). Role/username can be left blank to use
    // server-side defaults.
    if !non_interactive {
        prompt_method_params(&method, &mut stub.params)?;
        // Also prompt for the namespaces allowlist if the user didn't pass
        // any --namespace flags. Default suggestion = the cluster's current
        // namespace (since that's almost always what they want), or blank
        // (= unscoped) for clusters that haven't picked one yet.
        if stub.namespaces.is_empty() {
            prompt_namespaces(&cluster_snap, &mut stub.namespaces)?;
        }
    }

    if matches!(method.as_str(), "oidc" | "userpass") && non_interactive {
        // Sanity-check method-specific args at the boundary so the user gets
        // a clear error before we shell out and waste their time.
        if method == "oidc" && !stub.params.contains_key("role") {
            return Err(anyhow!(
                "--role is required when --method=oidc and --non-interactive"
            ));
        }
        if method == "userpass" && !stub.params.contains_key("username") {
            return Err(anyhow!(
                "--username is required when --method=userpass and --non-interactive"
            ));
        }
    }

    let token = run_method(&method, &cluster_snap, &stub)?;

    // Persist: insert the new auth and make it current.
    {
        let cluster_mut = cfg.cluster_mut(&cluster_name).unwrap();
        cluster_mut.add_auth(stub.clone())?;
        cluster_mut.current_auth = name.clone();
    }
    persist_token_and_metadata(&mut cfg, &cluster_name, &name, &method, token)?;

    let c = cfg.cluster(&cluster_name).unwrap();
    let a = c.auth(&name).unwrap();
    print_auth_stored(&cluster_name, a);
    println!("'{name}' set as current auth for '{cluster_name}'");
    Ok(())
}

/// `vaultpow auth hint` — internal, called by the shell wrapper after a
/// wrapped command fails with `ok` token state. Prints a one-line hint
/// listing the *other* (non-current) auths if there are any, plus the
/// switch incantation. Silent (exit 0, no output) when there's at most
/// one auth on the cluster, since there's nothing useful to suggest.
///
/// Designed to be cheap: doesn't probe the network, doesn't load the
/// config more than once, doesn't print anything in the common case
/// (single-auth setup) so it doesn't clutter the user's terminal.
pub fn hint() -> Result<()> {
    let cfg = config::load()?;
    let Some(cluster) = cfg.current() else {
        return Ok(());
    };
    if cluster.auths.len() < 2 {
        return Ok(());
    }
    let others: Vec<&str> = cluster
        .auths
        .iter()
        .filter(|a| a.name != cluster.current_auth)
        .map(|a| a.name.as_str())
        .collect();
    if others.is_empty() {
        return Ok(());
    }
    eprintln!(
        "vaultpow: tip: other auths on '{}': {}. Try `vaultpow auth use <name>` if this is a permissions issue.",
        cluster.name,
        others.join(", ")
    );
    Ok(())
}

/// `vaultpow auth rm <name>` — remove a named auth. Never auto-picks a
/// replacement when the removed one was current; the user must explicitly
/// `auth use <name>` (so they're never surprised by a silent identity switch).
pub fn rm(name: String) -> Result<()> {
    let mut cfg = config::load()?;
    let cluster_name = resolve_current(&mut cfg)?;

    let outcome = {
        let cluster = cfg.cluster_mut(&cluster_name).unwrap();
        cluster.remove_auth(&name)?
    };
    config::save(&cfg)?;

    println!("removed auth '{name}' from '{cluster_name}'");
    if outcome.was_current {
        if outcome.remaining == 0 {
            println!(
                "\nNo auths remain on '{cluster_name}'. Run `vaultpow auth add` to create one."
            );
        } else {
            // Per spec: never auto-pick, even when only one remains. Print the
            // available names + the explicit switch command.
            let cluster = cfg.cluster(&cluster_name).unwrap();
            let names: Vec<&str> = cluster.auths.iter().map(|a| a.name.as_str()).collect();
            println!(
                "\nThat was the current auth. Pick a replacement explicitly:\n  vaultpow auth use <name>\n\nAvailable: {}",
                names.join(", ")
            );
        }
    }
    Ok(())
}

// ── Internals ───────────────────────────────────────────────────────────

/// Decide which namespace to authenticate against. Vault/OpenBao OIDC and
/// userpass roles live *inside* a namespace, so the namespace sent at login
/// time has to be the one where the role is defined — which isn't always the
/// cluster's currently-selected working namespace.
///
/// Resolution order:
///   1. Scoped auth (non-empty `namespaces`): if the cluster's selected
///      namespace is one this auth covers, use it (honours the user's current
///      context, e.g. a child namespace). Otherwise use the auth's first
///      listed namespace — the one it was created for.
///   2. Unscoped auth (empty `namespaces`): fall back to the cluster's
///      selected namespace, preserving pre-0.1.4 behaviour exactly.
///
/// A blank namespace string is treated as "no namespace" (root).
fn login_namespace<'a>(cluster: &'a Cluster, auth: &'a Auth) -> Option<&'a str> {
    let selected = cluster.namespace.as_deref().filter(|n| !n.is_empty());
    if auth.namespaces.is_empty() {
        return selected;
    }
    match selected {
        Some(ns) if auth.namespaces.iter().any(|n| n == ns) => Some(ns),
        _ => auth.namespaces.first().map(String::as_str),
    }
}

/// Turn Vault/OpenBao's terse "role could not be found" login failure into a
/// message that names the namespace we authenticated against and points at
/// the fix. This error almost always means a namespace mismatch — the role
/// exists, just not in the namespace we logged in to — so the raw error is
/// actively misleading without this context.
fn hint_role_namespace(err: anyhow::Error, used: Option<&str>, auth: &Auth) -> anyhow::Error {
    if !err.to_string().contains("could not be found") {
        return err;
    }
    let where_ = match used {
        Some(ns) => format!("namespace '{ns}'"),
        None => "the root namespace".to_string(),
    };
    let mut hint = format!(
        "\n\nhint: authenticated against {where_}, but the role/mount isn't defined there — \
         Vault/OpenBao roles live inside a specific namespace."
    );
    if auth.namespaces.is_empty() {
        hint.push_str(
            " This auth isn't scoped to a namespace, so login used the cluster's selected one \
             (or root). Tag it with `vaultpow auth ns add <namespace>`, or select the right \
             namespace first with `vaultpow ns <namespace>`, then retry.",
        );
    } else {
        hint.push_str(&format!(
            " This auth is scoped to [{}] — confirm the role exists in one of those, or fix the \
             list with `vaultpow auth ns add/rm <namespace>`.",
            auth.namespaces.join(", ")
        ));
    }
    anyhow!("{err}{hint}")
}

/// Drive the chosen auth method end-to-end (interactive prompts as needed)
/// and return the captured token. Reads `auth.params` for method-specific
/// parameters (role, username, args).
fn run_method(method: &str, cluster: &Cluster, auth: &Auth) -> Result<String> {
    let server = cluster.server.as_str();
    // Authenticate against the namespace where this auth's role actually
    // lives — not necessarily the cluster's selected working namespace. See
    // `login_namespace` for the rule.
    let namespace = login_namespace(cluster, auth);

    match method {
        "token" => {
            let t = rpassword::prompt_password("Vault/OpenBao token: ")
                .context("reading token from prompt")?;
            if t.is_empty() {
                return Err(anyhow!("token cannot be empty"));
            }
            // Validate against the server before storing.
            let probe_cluster = make_probe_cluster(cluster, &t);
            vault::token_lookup(&probe_cluster).context("validating token against server")?;
            Ok(t)
        }
        "userpass" => {
            let user = match auth.params.get("username") {
                Some(u) if !u.is_empty() => u.clone(),
                _ => Input::<String>::new()
                    .with_prompt("Username")
                    .interact_text()
                    .map_err(|e| anyhow!("prompt failed: {e}"))?,
            };
            let pass = rpassword::prompt_password("Password: ").context("reading password")?;
            let mut args: Vec<String> = vec!["-method=userpass".into(), "-token-only".into()];
            if let Some(p) = auth.params.get("path").filter(|p| !p.is_empty()) {
                args.push(format!("-path={p}"));
            }
            args.push(format!("username={user}"));
            args.push(format!("password={pass}"));
            let argv: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
            run_vault_login(server, namespace, &argv)
                .map_err(|e| hint_role_namespace(e, namespace, auth))
        }
        "oidc" => {
            let mut args: Vec<String> = vec!["-method=oidc".into(), "-token-only".into()];
            // Custom mount path (e.g. `-path=google` when OIDC is mounted at
            // `auth/google/` instead of `auth/oidc/`). Vault's `bao login`
            // expects this *before* any method-specific kv pairs.
            if let Some(p) = auth.params.get("path").filter(|p| !p.is_empty()) {
                args.push(format!("-path={p}"));
            }
            if let Some(role) = auth.params.get("role").filter(|r| !r.is_empty()) {
                args.push(format!("role={role}"));
            }
            let argv: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
            run_vault_login(server, namespace, &argv)
                .map_err(|e| hint_role_namespace(e, namespace, auth))
        }
        "other" => {
            let raw = match auth.params.get("args") {
                Some(a) if !a.is_empty() => a.clone(),
                _ => Input::<String>::new()
                    .with_prompt("args for `vault login` (will append -token-only)")
                    .allow_empty(false)
                    .interact_text()
                    .map_err(|e| anyhow!("prompt failed: {e}"))?,
            };
            // Split naively on whitespace; the limitation is documented in
            // `--help` for the auth subcommand.
            let mut args: Vec<&str> = raw.split_whitespace().collect();
            args.push("-token-only");
            run_vault_login(server, namespace, &args)
                .map_err(|e| hint_role_namespace(e, namespace, auth))
        }
        other => Err(anyhow!(
            "unknown auth method '{other}' (valid: token, userpass, oidc, other)"
        )),
    }
}

/// Prompt for one optional param, skipping if it's already set (e.g. the
/// user passed it via flag). Trims whitespace; a blank response leaves the
/// key absent. Factored out of `prompt_method_params` so each match arm
/// stays a flat sequence of helper calls — also dodges the
/// `clippy::collapsible_match` lint that fires on single-`if` arms.
fn prompt_optional_param(
    params: &mut std::collections::BTreeMap<String, String>,
    key: &str,
    prompt: &str,
) -> Result<()> {
    if params.contains_key(key) {
        return Ok(());
    }
    let val: String = Input::new()
        .with_prompt(prompt)
        .allow_empty(true)
        .interact_text()
        .map_err(|e| anyhow!("prompt failed: {e}"))?;
    let trimmed = val.trim();
    if !trimmed.is_empty() {
        params.insert(key.into(), trimmed.to_string());
    }
    Ok(())
}

/// Interactive prompts for method-specific params that haven't been provided
/// via flags. Only prompts for things that meaningfully differ between
/// installs (custom mount path, OIDC role); username is left to run_method
/// because it pairs naturally with the password prompt.
fn prompt_method_params(
    method: &str,
    params: &mut std::collections::BTreeMap<String, String>,
) -> Result<()> {
    match method {
        "oidc" => {
            prompt_optional_param(params, "path", "OIDC mount path (blank = default `oidc`)")?;
            prompt_optional_param(params, "role", "OIDC role (blank = server default)")?;
        }
        "userpass" => {
            prompt_optional_param(
                params,
                "path",
                "userpass mount path (blank = default `userpass`)",
            )?;
            // Username + password are prompted together inside `run_method`
            // since they pair naturally and the password isn't stored anyway.
        }
        _ => {}
    }
    Ok(())
}

fn make_probe_cluster(cluster: &Cluster, token: &str) -> Cluster {
    let probe_auth = Auth {
        name: "__probe__".into(),
        token: Some(token.to_string()),
        ..Default::default()
    };
    Cluster {
        name: cluster.name.clone(),
        server: cluster.server.clone(),
        namespace: cluster.namespace.clone(),
        auths: vec![probe_auth],
        current_auth: "__probe__".into(),
        ..Default::default()
    }
}

fn prompt_method() -> Result<String> {
    let methods = ["token", "userpass", "oidc", "other"];
    let labels = [
        "token (paste an existing token)",
        "userpass (username/password)",
        "oidc (browser login)",
        "other (raw `vault login` args)",
    ];
    let idx = Select::new()
        .with_prompt("Authentication method")
        .items(&labels)
        .default(2)
        .interact()
        .map_err(|e| anyhow!("prompt failed: {e}"))?;
    Ok(methods[idx].to_string())
}

/// Save `token` onto the named auth, then probe the server to fill in
/// expire_time / creation_ttl / renewable. Best-effort on the probe.
fn persist_token_and_metadata(
    cfg: &mut config::Config,
    cluster_name: &str,
    auth_name: &str,
    method: &str,
    token: String,
) -> Result<()> {
    {
        let c = cfg.cluster_mut(cluster_name).unwrap();
        let a = c.auth_mut(auth_name).unwrap();
        a.token = Some(token);
        a.method = Some(method.to_string());
    }
    config::save(cfg)?;

    // Look up to populate lifecycle. We need a Cluster snapshot whose
    // current_auth points at the auth we just stored, so token_lookup
    // picks the right token.
    let cluster_snap = {
        let mut snap = cfg.cluster(cluster_name).unwrap().clone();
        snap.current_auth = auth_name.to_string();
        snap
    };
    match vault::token_lookup(&cluster_snap) {
        Ok(Some(fresh)) => {
            let c = cfg.cluster_mut(cluster_name).unwrap();
            let a = c.auth_mut(auth_name).unwrap();
            fresh.apply_to(a);
            config::save(cfg)?;
        }
        Ok(None) => {} // shouldn't happen — we just set the token
        Err(e) => {
            crate::commands::warn(format!("stored token, but couldn't look up metadata: {e}"))
        }
    }
    Ok(())
}

fn print_auth_stored(cluster_name: &str, a: &Auth) {
    let renew = if a.renewable == Some(true) {
        ", renewable"
    } else {
        ""
    };
    let auth_name = a.name.as_str();
    match a.expire_time.as_deref() {
        Some(et) => {
            println!("stored token for '{cluster_name}' auth '{auth_name}' (expires {et}{renew})")
        }
        None => println!("stored token for '{cluster_name}' auth '{auth_name}'"),
    }
}

// ── Per-auth namespace management (auth ns ...) ─────────────────────────

/// `vaultpow auth ns` / `auth ns list` — show the current auth's allowlist.
pub fn ns_list() -> Result<()> {
    let mut cfg = config::load()?;
    let cluster_name = resolve_current(&mut cfg)?;
    let cluster = cfg.cluster(&cluster_name).unwrap();
    let auth = current_auth_or_error(cluster, &cluster_name)?;

    println!("auth '{}' (on cluster '{cluster_name}'):", auth.name);
    if auth.namespaces.is_empty() {
        println!("  (unscoped — matches any namespace)");
        println!("\nAdd a namespace with `vaultpow auth ns add <name>` to constrain this auth.");
    } else {
        for ns in &auth.namespaces {
            println!("  {ns}");
        }
    }
    Ok(())
}

/// `vaultpow auth ns add <name>` — append `<name>` to the current auth's
/// allowlist. No-op (still succeeds) if it's already present, so the call
/// is idempotent. If the auth was previously *unscoped* (empty list), this
/// flips it into scoped mode — subsequent `vaultpow ns` calls will start
/// enforcing the allowlist for it.
pub fn ns_add(name: String) -> Result<()> {
    let trimmed = name.trim().to_string();
    if trimmed.is_empty() {
        return Err(anyhow!("namespace name cannot be empty"));
    }
    let mut cfg = config::load()?;
    let cluster_name = resolve_current(&mut cfg)?;
    let auth_name = current_auth_name_or_error(cfg.cluster(&cluster_name).unwrap(), &cluster_name)?;

    let was_unscoped;
    let already_present;
    {
        let auth = cfg
            .cluster_mut(&cluster_name)
            .unwrap()
            .auth_mut(&auth_name)
            .unwrap();
        was_unscoped = auth.namespaces.is_empty();
        already_present = auth.namespaces.iter().any(|n| n == &trimmed);
        if !already_present {
            auth.namespaces.push(trimmed.clone());
        }
    }
    config::save(&cfg)?;

    if already_present {
        println!("auth '{auth_name}' already supports '{trimmed}' — no change");
    } else if was_unscoped {
        println!(
            "auth '{auth_name}' is now scoped to only '{trimmed}'.\n\nAdd more with further `vaultpow auth ns add <name>` calls, or\nremove this one with `vaultpow auth ns rm {trimmed}` to revert to unscoped."
        );
    } else {
        println!("added '{trimmed}' to auth '{auth_name}'");
    }
    Ok(())
}

/// `vaultpow auth ns rm <name>` — remove `<name>` from the current auth's
/// allowlist. If the resulting list is empty, the auth flips back to
/// *unscoped* (matches any namespace) — message that out so the user
/// isn't surprised.
pub fn ns_rm(name: String) -> Result<()> {
    let mut cfg = config::load()?;
    let cluster_name = resolve_current(&mut cfg)?;
    let auth_name = current_auth_name_or_error(cfg.cluster(&cluster_name).unwrap(), &cluster_name)?;

    let now_unscoped;
    let removed;
    {
        let auth = cfg
            .cluster_mut(&cluster_name)
            .unwrap()
            .auth_mut(&auth_name)
            .unwrap();
        let before = auth.namespaces.len();
        auth.namespaces.retain(|n| n != &name);
        removed = auth.namespaces.len() < before;
        now_unscoped = auth.namespaces.is_empty();
    }
    if !removed {
        return Err(anyhow!(
            "auth '{auth_name}' does not list '{name}' — nothing to remove"
        ));
    }
    config::save(&cfg)?;

    println!("removed '{name}' from auth '{auth_name}'");
    if now_unscoped {
        println!(
            "\nauth '{auth_name}' is now *unscoped* again — it will match any namespace.\nUse `vaultpow auth ns add <name>` to constrain it."
        );
    }
    Ok(())
}

fn current_auth_or_error<'a>(cluster: &'a config::Cluster, cluster_name: &str) -> Result<&'a Auth> {
    cluster.current_auth().ok_or_else(|| {
        anyhow!(
            "no current auth on '{cluster_name}'.\n\nRun `vaultpow auth use <name>` or `vaultpow auth add`."
        )
    })
}

fn current_auth_name_or_error(cluster: &config::Cluster, cluster_name: &str) -> Result<String> {
    current_auth_or_error(cluster, cluster_name).map(|a| a.name.clone())
}

/// Normalise a `Vec<String>` of namespaces: drop blanks, trim whitespace,
/// deduplicate (case-sensitive — Vault treats namespace names as
/// case-sensitive paths). Order is preserved on first occurrence.
fn dedup_namespaces(input: Vec<String>) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::with_capacity(input.len());
    for raw in input {
        let s = raw.trim().to_string();
        if s.is_empty() {
            continue;
        }
        if seen.insert(s.clone()) {
            out.push(s);
        }
    }
    out
}

/// Interactive prompt for the namespaces allowlist. Accepts a comma- or
/// whitespace-separated list. Default suggestion is the cluster's current
/// namespace (most common case: "the auth I'm creating is for the
/// namespace I'm in"). Blank input keeps the auth unscoped.
fn prompt_namespaces(cluster: &config::Cluster, out: &mut Vec<String>) -> Result<()> {
    let default = cluster.namespace.as_deref().unwrap_or("").to_string();
    let prompt = if default.is_empty() {
        "Allowed namespaces (comma-separated, blank = unscoped)".to_string()
    } else {
        format!("Allowed namespaces (comma-separated, blank = unscoped) [{default}]")
    };
    let raw: String = Input::new()
        .with_prompt(prompt)
        .allow_empty(true)
        .interact_text()
        .map_err(|e| anyhow!("prompt failed: {e}"))?;
    let raw = raw.trim();
    let chosen = if raw.is_empty() {
        // Use the default cluster namespace if the user just hit enter and
        // one is set; otherwise leave the auth unscoped.
        if default.is_empty() {
            vec![]
        } else {
            vec![default]
        }
    } else {
        raw.split([',', ' ', '\t'])
            .map(|s| s.trim().to_string())
            .collect()
    };
    *out = dedup_namespaces(chosen);
    Ok(())
}

/// Shell out to `vault login` (or `bao login` if that's what's installed).
/// We use the real CLI for these since OIDC needs the browser flow and
/// userpass is least-surprise via the official client.
fn run_vault_login(server: &str, namespace: Option<&str>, args: &[&str]) -> Result<String> {
    // Friendly upfront check before we try to spawn — gives a better message
    // than the bare ENOENT that `Command::output()` would. Returns the
    // resolved binary path so we don't re-walk PATH inside Command::new.
    let (cli_name, cli_path) = crate::commands::ensure_vault_cli_installed()?;

    let mut cmd = Command::new(&cli_path);
    cmd.arg("login");
    cmd.args(args);
    // Set both VAULT_* and BAO_* — bao currently falls back to VAULT_* but
    // setting both is future-proof and works for either CLI.
    cmd.env("VAULT_ADDR", server);
    cmd.env("BAO_ADDR", server);
    if let Some(ns) = namespace {
        if !ns.is_empty() {
            cmd.env("VAULT_NAMESPACE", ns);
            cmd.env("BAO_NAMESPACE", ns);
        }
    } else {
        cmd.env_remove("VAULT_NAMESPACE");
        cmd.env_remove("BAO_NAMESPACE");
    }
    // Don't inherit a stale token that could shortcut the login.
    cmd.env_remove("VAULT_TOKEN");
    cmd.env_remove("BAO_TOKEN");

    let out = cmd.output().with_context(|| {
        format!("running `{cli_name} login` (is the {cli_name} CLI installed?)")
    })?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(anyhow!("{cli_name} login failed:\n{}", stderr.trim()));
    }
    let token = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if token.is_empty() {
        return Err(anyhow!("{cli_name} login returned an empty token"));
    }
    Ok(token)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cluster_with_ns(ns: Option<&str>) -> Cluster {
        Cluster {
            name: "c".into(),
            server: "https://v".into(),
            namespace: ns.map(String::from),
            ..Default::default()
        }
    }

    fn auth_with_ns(list: &[&str]) -> Auth {
        Auth {
            name: "a".into(),
            namespaces: list.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn login_namespace_unscoped_auth_uses_cluster_namespace() {
        let a = auth_with_ns(&[]);
        assert_eq!(
            login_namespace(&cluster_with_ns(Some("admin/team-a")), &a),
            Some("admin/team-a")
        );
        // No selected namespace, and a blank one, both mean root.
        assert_eq!(login_namespace(&cluster_with_ns(None), &a), None);
        assert_eq!(login_namespace(&cluster_with_ns(Some("")), &a), None);
    }

    #[test]
    fn login_namespace_scoped_auth_uses_first_when_cluster_unset() {
        // The bug this fixes: cluster has no namespace selected, but the OIDC
        // role lives in the auth's namespace. Log in there, not at root.
        let a = auth_with_ns(&["ethena-pay-production", "ethena-pay-staging"]);
        assert_eq!(
            login_namespace(&cluster_with_ns(None), &a),
            Some("ethena-pay-production")
        );
    }

    #[test]
    fn login_namespace_scoped_auth_honours_selected_when_covered() {
        let a = auth_with_ns(&["ethena-pay-production", "ethena-pay-staging"]);
        assert_eq!(
            login_namespace(&cluster_with_ns(Some("ethena-pay-staging")), &a),
            Some("ethena-pay-staging")
        );
    }

    #[test]
    fn login_namespace_scoped_auth_ignores_selected_when_not_covered() {
        // Selected namespace the auth doesn't cover → use the auth's own first
        // namespace rather than logging in somewhere the role can't be found.
        let a = auth_with_ns(&["ethena-pay-production"]);
        assert_eq!(
            login_namespace(&cluster_with_ns(Some("some/other")), &a),
            Some("ethena-pay-production")
        );
    }

    #[test]
    fn hint_role_namespace_only_fires_on_role_not_found() {
        let a = auth_with_ns(&["ethena-pay-production"]);
        let unrelated = anyhow!("bao login failed:\nconnection refused");
        assert!(!hint_role_namespace(unrelated, None, &a)
            .to_string()
            .contains("hint:"));
    }

    #[test]
    fn hint_role_namespace_names_root_and_scope() {
        let a = auth_with_ns(&["ethena-pay-production"]);
        let err = anyhow!("bao login failed:\nrole \"secrets-admin\" could not be found");
        let out = hint_role_namespace(err, None, &a).to_string();
        assert!(out.contains("hint:"));
        assert!(out.contains("root namespace"));
        assert!(out.contains("ethena-pay-production"));
        // Original error text is preserved, not replaced.
        assert!(out.contains("could not be found"));
    }

    #[test]
    fn hint_role_namespace_names_used_namespace_for_unscoped_auth() {
        let a = auth_with_ns(&[]);
        let err = anyhow!("role \"x\" could not be found");
        let out = hint_role_namespace(err, Some("ethena-pay-staging"), &a).to_string();
        assert!(out.contains("namespace 'ethena-pay-staging'"));
        assert!(out.contains("vaultpow auth ns add"));
    }
}
