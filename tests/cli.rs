// CLI integration tests: spawn the binary against a tempfile-backed config
// and exercise the user-visible flows.

mod common;

use common::CliFixture;
use predicates::prelude::*;
use std::process::Command;

fn assert_success(cmd: &mut Command) -> std::process::Output {
    let out = cmd.output().expect("spawn vaultpow");
    assert!(
        out.status.success(),
        "command failed: {:?}\nstdout: {}\nstderr: {}",
        cmd,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    out
}

#[test]
fn version_subcommand_prints_version() {
    let f = CliFixture::new();
    let out = assert_success(f.cmd().arg("--version"));
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("vaultpow"), "got {s}");
    assert!(s.contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn status_with_no_clusters_is_helpful() {
    let f = CliFixture::new();
    let out = assert_success(f.cmd().arg("status"));
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("(none)"));
    assert!(s.contains("vaultpow add-cluster"));
}

#[test]
fn status_is_default_subcommand() {
    let f = CliFixture::new();
    // No subcommand should behave like `status`.
    let out_default = assert_success(&mut f.cmd());
    let out_status = assert_success(f.cmd().arg("status"));
    assert_eq!(out_default.stdout, out_status.stdout);
}

#[test]
fn add_cluster_non_interactive_round_trips() {
    let f = CliFixture::new();
    assert_success(f.cmd().args([
        "add-cluster",
        "--name",
        "prod",
        "--server",
        "https://vault.example.com:8200",
        "--namespace",
        "admin/foo",
        "--non-interactive",
    ]));

    let yaml = std::fs::read_to_string(&f.config_path).unwrap();
    assert!(yaml.contains("name: prod"));
    assert!(yaml.contains("server: https://vault.example.com:8200"));
    assert!(yaml.contains("namespace: admin/foo"));
    assert!(yaml.contains("current_cluster: prod"));
}

#[test]
fn add_cluster_requires_name_in_non_interactive_mode() {
    let f = CliFixture::new();
    let out = f
        .cmd()
        .args(["add-cluster", "--non-interactive"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("--name is required"), "stderr: {stderr}");
}

#[test]
fn add_cluster_rejects_invalid_server_url() {
    let f = CliFixture::new();
    let out = f
        .cmd()
        .args([
            "add-cluster",
            "--name",
            "x",
            "--server",
            "not-a-url",
            "--non-interactive",
        ])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("must start with http"), "stderr: {stderr}");
}

#[test]
fn add_cluster_rejects_duplicate_name() {
    let f = CliFixture::new();
    assert_success(f.cmd().args([
        "add-cluster",
        "--name",
        "x",
        "--server",
        "http://x",
        "--non-interactive",
    ]));
    let out = f
        .cmd()
        .args([
            "add-cluster",
            "--name",
            "x",
            "--server",
            "http://y",
            "--non-interactive",
        ])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("already exists"));
}

#[test]
fn ctx_lists_and_marks_current() {
    let f = CliFixture::new();
    for n in ["a", "b", "c"] {
        assert_success(f.cmd().args([
            "add-cluster",
            "--name",
            n,
            "--server",
            "http://x",
            "--non-interactive",
        ]));
    }
    let out = assert_success(f.cmd().arg("ctx"));
    let s = String::from_utf8_lossy(&out.stdout);
    // First-added cluster becomes current.
    assert!(s.lines().any(|l| l.starts_with("* a")), "got: {s}");
    assert!(s.lines().any(|l| l.trim_start().starts_with("b")));
    assert!(s.lines().any(|l| l.trim_start().starts_with("c")));
}

#[test]
fn ctx_switches_current() {
    let f = CliFixture::new();
    for n in ["a", "b"] {
        assert_success(f.cmd().args([
            "add-cluster",
            "--name",
            n,
            "--server",
            "http://x",
            "--non-interactive",
        ]));
    }
    assert_success(f.cmd().args(["ctx", "b"]));
    let out = assert_success(f.cmd().arg("ctx"));
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.lines().any(|l| l.starts_with("* b")), "got: {s}");
}

#[test]
fn ctx_unknown_cluster_errors_helpfully() {
    let f = CliFixture::new();
    assert_success(f.cmd().args([
        "add-cluster",
        "--name",
        "a",
        "--server",
        "http://x",
        "--non-interactive",
    ]));
    let out = f.cmd().args(["ctx", "missing"]).output().unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("not found"));
    assert!(stderr.contains("vaultpow ctx"));
}

#[test]
fn ns_show_set_and_shorthand() {
    let f = CliFixture::new();
    assert_success(f.cmd().args([
        "add-cluster",
        "--name",
        "a",
        "--server",
        "http://x",
        "--namespace",
        "admin/one",
        "--non-interactive",
    ]));

    // ns (no args) shows the current.
    let out = assert_success(f.cmd().arg("ns"));
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "admin/one");

    // ns set <name>
    assert_success(f.cmd().args(["ns", "set", "admin/two"]));
    let out = assert_success(f.cmd().arg("ns"));
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "admin/two");

    // ns <name> shorthand
    assert_success(f.cmd().args(["ns", "admin/three"]));
    let out = assert_success(f.cmd().arg("ns"));
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "admin/three");

    // empty string clears to root
    assert_success(f.cmd().args(["ns", "set", ""]));
    let out = assert_success(f.cmd().arg("ns"));
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "(root)");
}

#[test]
fn check_token_returns_absent_with_no_token() {
    let f = CliFixture::new();
    // No clusters → also "absent" per check_token.rs behaviour.
    let out = assert_success(f.cmd().arg("check-token"));
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "absent");

    // With a cluster but no token, still absent.
    assert_success(f.cmd().args([
        "add-cluster",
        "--name",
        "a",
        "--server",
        "http://x",
        "--non-interactive",
    ]));
    let out = assert_success(f.cmd().arg("check-token"));
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "absent");
}

#[test]
fn env_emits_eval_friendly_output() {
    let f = CliFixture::new();
    assert_success(f.cmd().args([
        "add-cluster",
        "--name",
        "a",
        "--server",
        "https://v.example/",
        "--namespace",
        "admin/x",
        "--non-interactive",
    ]));
    let out = assert_success(f.cmd().arg("env"));
    let s = String::from_utf8_lossy(&out.stdout);
    // `shell-escape` quotes liberally (colons in URLs trigger it), so accept
    // either quoted or unquoted forms — the value is what matters.
    for var in ["VAULT_ADDR", "BAO_ADDR"] {
        let ok = s.contains(&format!("export {var}='https://v.example/'"))
            || s.contains(&format!("export {var}=https://v.example/"));
        assert!(ok, "missing {var} export, got: {s}");
    }
    for var in ["VAULT_NAMESPACE", "BAO_NAMESPACE"] {
        let ok = s.contains(&format!("export {var}='admin/x'"))
            || s.contains(&format!("export {var}=admin/x"));
        assert!(ok, "missing {var} export, got: {s}");
    }
    // No token stored → both VAULT_TOKEN and BAO_TOKEN should be unset.
    assert!(s.contains("unset VAULT_TOKEN"), "got: {s}");
    assert!(s.contains("unset BAO_TOKEN"), "got: {s}");
}

#[test]
fn env_emits_bao_alongside_vault_when_token_present() {
    // Regression: when a token is stored, both VAULT_TOKEN and BAO_TOKEN
    // must be exported. Tokens are interchangeable between vault and bao.
    let f = CliFixture::new();
    let yaml = r#"clusters:
- name: a
  server: http://x
  namespace: admin/y
  auth:
    token: hvs.test_token
current_cluster: a
"#;
    std::fs::write(&f.config_path, yaml).unwrap();
    let out = assert_success(f.cmd().arg("env"));
    let s = String::from_utf8_lossy(&out.stdout);
    for var in [
        "VAULT_ADDR",
        "BAO_ADDR",
        "VAULT_NAMESPACE",
        "BAO_NAMESPACE",
        "VAULT_TOKEN",
        "BAO_TOKEN",
    ] {
        assert!(
            s.contains(&format!("export {var}=")),
            "missing export for {var}, got: {s}"
        );
    }
    // The same token value should appear in both lines.
    let count = s.matches("hvs.test_token").count();
    assert_eq!(count, 2, "token should appear once for each CLI: {s}");
}

#[test]
fn env_quotes_values_safely() {
    // shell-escape should defend against spaces / single quotes in strings.
    let f = CliFixture::new();
    assert_success(f.cmd().args([
        "add-cluster",
        "--name",
        "a",
        "--server",
        "https://v.example/",
        "--non-interactive",
    ]));
    // Set a namespace with characters that need escaping (single quote).
    assert_success(f.cmd().args(["ns", "set", "weird'ns"]));
    let out = assert_success(f.cmd().arg("env"));
    let s = String::from_utf8_lossy(&out.stdout);
    let line = s
        .lines()
        .find(|l| l.starts_with("export VAULT_NAMESPACE="))
        .expect("VAULT_NAMESPACE line");
    // Single-quote inside single-quoted string must be escaped as: '\''
    assert!(
        line.contains("'\\''"),
        "expected escaped quote, got: {line}"
    );
}

#[test]
fn shell_init_zsh_outputs_wrapper() {
    let f = CliFixture::new();
    let out = assert_success(f.cmd().args(["shell-init", "zsh"]));
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("vault()"));
    assert!(s.contains("vaultpow ensure-fresh"));
    assert!(s.contains("vaultpow check-token"));
}

#[test]
fn shell_init_bash_outputs_wrapper() {
    let f = CliFixture::new();
    let out = assert_success(f.cmd().args(["shell-init", "bash"]));
    assert!(String::from_utf8_lossy(&out.stdout).contains("vault()"));
}

#[test]
fn shell_init_unknown_shell_errors() {
    let f = CliFixture::new();
    let out = f.cmd().args(["shell-init", "fish"]).output().unwrap();
    assert!(!out.status.success());
    // clap value_parser produces its own message — be lenient.
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("fish"), "stderr: {stderr}");
}

#[test]
fn completions_emits_zsh_script() {
    let f = CliFixture::new();
    let out = assert_success(f.cmd().args(["completions", "zsh"]));
    let s = String::from_utf8_lossy(&out.stdout);
    // clap_complete tags zsh output with `#compdef <bin>` at the top.
    assert!(s.starts_with("#compdef vaultpow"), "got: {s}");
    // Spot-check that subcommands appear in the completion script.
    assert!(s.contains("add-cluster"));
    assert!(s.contains("ensure-fresh"));
}

#[test]
fn completions_emits_bash_script() {
    let f = CliFixture::new();
    let out = assert_success(f.cmd().args(["completions", "bash"]));
    let s = String::from_utf8_lossy(&out.stdout);
    // bash completions register via `complete -F`.
    assert!(s.contains("complete -F"), "got: {s}");
    assert!(s.contains("vaultpow"));
}

#[test]
fn completions_unknown_shell_errors() {
    let f = CliFixture::new();
    let out = f.cmd().args(["completions", "tcsh"]).output().unwrap();
    assert!(!out.status.success());
    // clap value_parser rejects with its own message.
    assert!(String::from_utf8_lossy(&out.stderr).contains("tcsh"));
}

#[test]
fn remove_cluster_drops_and_clears_current() {
    let f = CliFixture::new();
    assert_success(f.cmd().args([
        "add-cluster",
        "--name",
        "a",
        "--server",
        "http://x",
        "--non-interactive",
    ]));
    assert_success(f.cmd().args(["remove-cluster", "a"]));
    let yaml = std::fs::read_to_string(&f.config_path).unwrap();
    // Empty current_cluster is omitted entirely from serialised YAML.
    assert!(!yaml.contains("name: a"), "got: {yaml}");
    assert!(!yaml.contains("current_cluster:"), "got: {yaml}");
}

#[test]
fn remove_cluster_unknown_errors() {
    let f = CliFixture::new();
    assert_success(f.cmd().args([
        "add-cluster",
        "--name",
        "a",
        "--server",
        "http://x",
        "--non-interactive",
    ]));
    let out = f
        .cmd()
        .args(["remove-cluster", "missing"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("not found"));
}

#[test]
fn help_includes_every_subcommand() {
    let f = CliFixture::new();
    let out = assert_success(f.cmd().arg("--help"));
    let s = String::from_utf8_lossy(&out.stdout);
    for sub in [
        "status",
        "ctx",
        "add-cluster",
        "remove-cluster",
        "ns",
        "auth",
        "renew",
        "check-token",
        "ensure-fresh",
        "env",
        "shell-init",
        "completions",
    ] {
        assert!(predicates::str::contains(sub).eval(&s), "missing: {sub}");
    }
}

// ── Multi-auth flows ────────────────────────────────────────────────────
//
// These tests pre-seed the YAML config directly (the auth-add interactive
// flow requires a TTY for prompts; the non-interactive flag-driven path
// shells out to `vault login` which we can't sanely mock from a test
// binary). Direct YAML covers the data-model semantics that actually
// matter — list/use/rm flows, current_auth pointer behaviour, env/status
// reading the right auth, and the never-auto-pick guarantee.

fn write_multi_auth_config(f: &CliFixture, current: &str) {
    let yaml = format!(
        r#"clusters:
- name: prod
  server: http://127.0.0.1:8200
  namespace: admin/foo
  auths:
    - name: admin
      method: oidc
      params:
        role: admin
      token: hvs.admin
      expire_time: "2099-01-01T00:00:00Z"
      renewable: true
    - name: ro
      method: userpass
      params:
        username: alice
      token: hvs.ro
  current_auth: {current}
current_cluster: prod
"#
    );
    std::fs::write(&f.config_path, yaml).unwrap();
}

#[test]
fn auth_list_marks_current_and_shows_method_params() {
    let f = CliFixture::new();
    write_multi_auth_config(&f, "admin");
    let out = assert_success(f.cmd().args(["auth", "list"]));
    let s = String::from_utf8_lossy(&out.stdout);
    // Current auth marked with `*`, other with leading space.
    assert!(s.contains("* admin"), "current auth should be marked: {s}");
    assert!(s.contains("ro"), "non-current auth should be listed: {s}");
    // Method + params are surfaced.
    assert!(s.contains("method=oidc"), "got: {s}");
    assert!(s.contains("method=userpass"), "got: {s}");
    assert!(s.contains("role=admin"), "got: {s}");
    assert!(s.contains("username=alice"), "got: {s}");
}

#[test]
fn auth_list_when_no_auths_points_to_add() {
    let f = CliFixture::new();
    let yaml = r#"clusters:
- name: empty
  server: http://127.0.0.1:8200
current_cluster: empty
"#;
    std::fs::write(&f.config_path, yaml).unwrap();
    let out = assert_success(f.cmd().args(["auth", "list"]));
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("no auths configured"), "got: {s}");
    assert!(s.contains("vaultpow auth add"), "got: {s}");
}

#[test]
fn auth_use_switches_current_auth() {
    let f = CliFixture::new();
    write_multi_auth_config(&f, "admin");
    assert_success(f.cmd().args(["auth", "use", "ro"]));
    let yaml = std::fs::read_to_string(&f.config_path).unwrap();
    assert!(yaml.contains("current_auth: ro"), "got: {yaml}");

    // env should now emit the ro token.
    let out = assert_success(f.cmd().arg("env"));
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("hvs.ro"), "got: {s}");
    assert!(!s.contains("hvs.admin"), "stale token leaked: {s}");
}

#[test]
fn auth_use_unknown_errors_with_available_list() {
    let f = CliFixture::new();
    write_multi_auth_config(&f, "admin");
    let out = f.cmd().args(["auth", "use", "ghost"]).output().unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("not found"), "stderr: {stderr}");
    // Helpful: list what IS available.
    assert!(stderr.contains("admin"), "stderr: {stderr}");
    assert!(stderr.contains("ro"), "stderr: {stderr}");
}

#[test]
fn auth_rm_non_current_preserves_current_auth() {
    let f = CliFixture::new();
    write_multi_auth_config(&f, "admin");
    assert_success(f.cmd().args(["auth", "rm", "ro"]));
    let yaml = std::fs::read_to_string(&f.config_path).unwrap();
    assert!(
        yaml.contains("current_auth: admin"),
        "current_auth should be untouched: {yaml}"
    );
    assert!(!yaml.contains("name: ro"), "ro should be gone: {yaml}");
}

#[test]
fn auth_rm_current_never_auto_picks_and_prints_explicit_hint() {
    // Spec: even with one auth remaining, removal of the current one
    // clears current_auth — the user must pick a replacement explicitly.
    let f = CliFixture::new();
    write_multi_auth_config(&f, "admin");
    let out = assert_success(f.cmd().args(["auth", "rm", "admin"]));
    let stdout = String::from_utf8_lossy(&out.stdout);
    // Output guides the user to the next step.
    assert!(
        stdout.contains("Pick a replacement explicitly") || stdout.contains("vaultpow auth use"),
        "stdout should explain how to recover: {stdout}"
    );
    // Available auths surfaced.
    assert!(stdout.contains("ro"), "stdout: {stdout}");

    // current_auth has been cleared.
    let yaml = std::fs::read_to_string(&f.config_path).unwrap();
    assert!(
        !yaml.contains("current_auth: ro") && !yaml.contains("current_auth: admin"),
        "current_auth should be cleared, got: {yaml}"
    );

    // And env reflects that — token must be unset.
    let env_out = assert_success(f.cmd().arg("env"));
    let env_s = String::from_utf8_lossy(&env_out.stdout);
    assert!(env_s.contains("unset VAULT_TOKEN"), "got: {env_s}");
    assert!(env_s.contains("unset BAO_TOKEN"), "got: {env_s}");
}

#[test]
fn auth_rm_last_auth_tells_user_to_add_one() {
    let f = CliFixture::new();
    let yaml = r#"clusters:
- name: prod
  server: http://x
  auths:
    - name: only
      token: hvs.x
  current_auth: only
current_cluster: prod
"#;
    std::fs::write(&f.config_path, yaml).unwrap();
    let out = assert_success(f.cmd().args(["auth", "rm", "only"]));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("No auths remain"), "got: {stdout}");
    assert!(stdout.contains("vaultpow auth add"), "got: {stdout}");
}

#[test]
fn auth_hint_silent_when_one_or_zero_auths() {
    let f = CliFixture::new();
    // Zero auths
    let yaml = r#"clusters:
- name: prod
  server: http://x
current_cluster: prod
"#;
    std::fs::write(&f.config_path, yaml).unwrap();
    let out = assert_success(f.cmd().args(["auth", "hint"]));
    assert!(out.stdout.is_empty(), "stdout: {:?}", out.stdout);
    assert!(out.stderr.is_empty(), "stderr: {:?}", out.stderr);

    // One auth
    let yaml = r#"clusters:
- name: prod
  server: http://x
  auths:
    - name: only
      token: hvs.x
  current_auth: only
current_cluster: prod
"#;
    std::fs::write(&f.config_path, yaml).unwrap();
    let out = assert_success(f.cmd().args(["auth", "hint"]));
    assert!(out.stdout.is_empty(), "stdout: {:?}", out.stdout);
    assert!(out.stderr.is_empty(), "stderr: {:?}", out.stderr);
}

#[test]
fn auth_add_non_interactive_oidc_requires_role() {
    // --non-interactive must error before shelling out if a required
    // method-specific param is missing. This is a boundary check on the
    // CLI surface; we don't actually try to authenticate.
    let f = CliFixture::new();
    assert_success(f.cmd().args([
        "add-cluster",
        "--name",
        "p",
        "--server",
        "http://127.0.0.1:8200",
        "--non-interactive",
    ]));
    let out = f
        .cmd()
        .args([
            "auth",
            "add",
            "--name",
            "x",
            "--method",
            "oidc",
            "--non-interactive",
        ])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("--role is required"), "stderr: {stderr}");
}

#[test]
fn auth_add_non_interactive_passing_path_role_works_and_persists_params() {
    // We can't actually authenticate (no real `bao`/`vault` on PATH in
    // CI), but we can verify the CLI surface accepts --path and would
    // pass through the boundary checks. We then short-circuit before
    // the network/shell-out by exploiting that --method=oidc with --role
    // set passes the upfront validation. The call will fail on the
    // shell-out step, but we only assert that the failure is from the
    // `bao`/`vault` invocation, not from arg validation.
    let f = CliFixture::new();
    assert_success(f.cmd().args([
        "add-cluster",
        "--name",
        "p",
        "--server",
        "http://127.0.0.1:8200",
        "--non-interactive",
    ]));
    let out = f
        .cmd()
        // PATH=empty so vault/bao aren't found — we expect the friendly
        // "neither the `vault` nor `bao` CLI is on your PATH" error,
        // which proves arg validation passed.
        .env("PATH", "")
        .args([
            "auth",
            "add",
            "--name",
            "google",
            "--method",
            "oidc",
            "--path",
            "google",
            "--role",
            "admin",
            "--non-interactive",
        ])
        .output()
        .unwrap();
    assert!(!out.status.success(), "should fail with no CLI installed");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("vault` nor `bao` CLI"),
        "expected CLI-missing error, got: {stderr}"
    );
    // Critically, NOT a --path validation error.
    assert!(
        !stderr.contains("--path is required"),
        "--path should be optional, got: {stderr}"
    );
}

// ── Per-auth namespaces (v0.1.2) ────────────────────────────────────────

fn write_auths_with_namespaces(f: &CliFixture) {
    // Cluster with two auths: 'admin' scoped to admin/team-a + admin/shared,
    // 'ro' scoped to admin/public, 'wild' unscoped (matches anything).
    let yaml = r#"clusters:
- name: prod
  server: http://127.0.0.1:8200
  auths:
    - name: admin
      method: oidc
      namespaces:
        - admin/team-a
        - admin/shared
      token: hvs.admin
    - name: ro
      method: userpass
      namespaces:
        - admin/public
      token: hvs.ro
    - name: wild
      method: token
      token: hvs.wild
  current_auth: admin
  namespace: admin/team-a
current_cluster: prod
"#;
    std::fs::write(&f.config_path, yaml).unwrap();
}

#[test]
fn ns_set_to_already_supported_namespace_does_not_switch_auth() {
    let f = CliFixture::new();
    write_auths_with_namespaces(&f);
    // admin/shared is in admin's allowlist → no auth change.
    let out = assert_success(f.cmd().args(["ns", "set", "admin/shared"]));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("set to 'admin/shared'"), "stdout: {stdout}");
    assert!(
        !stdout.contains("auth switched"),
        "auth should not have switched: {stdout}"
    );
    let yaml = std::fs::read_to_string(&f.config_path).unwrap();
    assert!(yaml.contains("current_auth: admin"), "got: {yaml}");
}

#[test]
fn ns_set_with_auth_flag_switches_both() {
    let f = CliFixture::new();
    write_auths_with_namespaces(&f);
    // Explicit --auth to switch to 'ro' for admin/public.
    let out = assert_success(f.cmd().args(["ns", "set", "admin/public", "--auth", "ro"]));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("auth switched to 'ro'"), "stdout: {stdout}");
    let yaml = std::fs::read_to_string(&f.config_path).unwrap();
    assert!(yaml.contains("current_auth: ro"), "got: {yaml}");
    assert!(yaml.contains("namespace: admin/public"), "got: {yaml}");
}

#[test]
fn ns_set_with_auth_flag_errors_when_auth_lacks_namespace() {
    // --auth must NOT auto-extend the auth's allowlist; surface the
    // mismatch clearly so the user can decide whether to broaden the
    // auth (`auth ns add`) or pick a different one.
    let f = CliFixture::new();
    write_auths_with_namespaces(&f);
    let out = f
        .cmd()
        .args(["ns", "set", "admin/team-b", "--auth", "ro"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("does not support namespace"),
        "stderr: {stderr}"
    );
    assert!(stderr.contains("auth ns add"), "should hint: {stderr}");
}

#[test]
fn ns_set_with_unknown_auth_errors_with_helpful_message() {
    let f = CliFixture::new();
    write_auths_with_namespaces(&f);
    let out = f
        .cmd()
        .args(["ns", "set", "admin/team-a", "--auth", "ghost"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("not found"), "stderr: {stderr}");
}

#[test]
fn ns_set_errors_when_no_auth_supports_namespace() {
    // None of the configured auths claim admin/team-b — the user has
    // to either broaden one (`auth ns add`) or add a new one. Surface
    // both options.
    let f = CliFixture::new();
    write_auths_with_namespaces(&f);
    // Switch wild → still unscoped → supports anything. So we must
    // remove 'wild' first to set up the failing case.
    assert_success(f.cmd().args(["auth", "rm", "wild"]));
    let out = f
        .cmd()
        .args(["ns", "set", "admin/team-b"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("no auth"), "stderr: {stderr}");
    assert!(stderr.contains("auth ns add"), "should hint: {stderr}");
    assert!(
        stderr.contains("auth add --namespace"),
        "should hint: {stderr}"
    );
}

#[test]
fn ns_set_with_no_auths_configured_just_sets_namespace() {
    // Pre-multi-auth UX preserved: a fresh cluster with no auths
    // shouldn't refuse `ns set`. There's no scope to violate.
    let f = CliFixture::new();
    assert_success(f.cmd().args([
        "add-cluster",
        "--name",
        "fresh",
        "--server",
        "http://x",
        "--non-interactive",
    ]));
    assert_success(f.cmd().args(["ns", "set", "admin/whatever"]));
    let yaml = std::fs::read_to_string(&f.config_path).unwrap();
    assert!(yaml.contains("namespace: admin/whatever"), "got: {yaml}");
}

#[test]
fn auth_ns_list_shows_unscoped_or_namespaces() {
    let f = CliFixture::new();
    write_auths_with_namespaces(&f);
    let out = assert_success(f.cmd().args(["auth", "ns", "list"]));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("admin/team-a"), "got: {stdout}");
    assert!(stdout.contains("admin/shared"), "got: {stdout}");

    // Switch to wild → unscoped → list should say so explicitly.
    assert_success(f.cmd().args(["auth", "use", "wild"]));
    let out = assert_success(f.cmd().args(["auth", "ns", "list"]));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("unscoped"), "got: {stdout}");
}

#[test]
fn auth_ns_add_then_rm_round_trips() {
    let f = CliFixture::new();
    write_auths_with_namespaces(&f);
    // Add admin/team-b to current auth (admin)
    assert_success(f.cmd().args(["auth", "ns", "add", "admin/team-b"]));
    let yaml = std::fs::read_to_string(&f.config_path).unwrap();
    assert!(yaml.contains("admin/team-b"), "got: {yaml}");
    // Now ns set should be a no-auth-switch:
    let out = assert_success(f.cmd().args(["ns", "set", "admin/team-b"]));
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(!s.contains("auth switched"), "got: {s}");

    // Remove it again. Note that `ns set admin/team-b` above also set
    // the *cluster*'s namespace pointer to admin/team-b, so the string
    // still appears under `namespace:`. What we care about here is that
    // it's gone from admin's *allowlist*.
    assert_success(f.cmd().args(["auth", "ns", "rm", "admin/team-b"]));
    let out = assert_success(f.cmd().args(["auth", "ns", "list"]));
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(
        !s.contains("admin/team-b"),
        "auth's allowlist should no longer contain it: {s}"
    );
}

#[test]
fn auth_ns_add_idempotent_on_duplicate() {
    let f = CliFixture::new();
    write_auths_with_namespaces(&f);
    let out = assert_success(f.cmd().args(["auth", "ns", "add", "admin/team-a"]));
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("already supports"), "got: {s}");
}

#[test]
fn auth_ns_rm_to_empty_reverts_to_unscoped() {
    // Removing the last namespace flips the auth back to unscoped.
    // Surface that so the user knows their security posture changed.
    let f = CliFixture::new();
    let yaml = r#"clusters:
- name: c
  server: http://x
  auths:
    - name: only-a
      namespaces:
        - admin/a
      token: hvs.x
  current_auth: only-a
current_cluster: c
"#;
    std::fs::write(&f.config_path, yaml).unwrap();
    let out = assert_success(f.cmd().args(["auth", "ns", "rm", "admin/a"]));
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(
        s.contains("unscoped"),
        "should warn about scope change: {s}"
    );
}

#[test]
fn auth_ns_rm_unknown_errors() {
    let f = CliFixture::new();
    write_auths_with_namespaces(&f);
    let out = f
        .cmd()
        .args(["auth", "ns", "rm", "admin/never"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("does not list"), "stderr: {stderr}");
}

#[test]
fn auth_add_namespace_flag_appears_in_help() {
    let f = CliFixture::new();
    let out = assert_success(f.cmd().args(["auth", "add", "--help"]));
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("--namespace"), "got: {s}");
    assert!(s.contains("unscoped"), "got: {s}");
}

#[test]
fn auth_add_path_appears_in_help() {
    // Smoke check that --path is exposed on the CLI surface.
    let f = CliFixture::new();
    let out = assert_success(f.cmd().args(["auth", "add", "--help"]));
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("--path"), "got: {s}");
    assert!(s.contains("mount path"), "got: {s}");
}

#[test]
fn auth_hint_lists_others_when_multiple_auths_configured() {
    let f = CliFixture::new();
    write_multi_auth_config(&f, "admin");
    let out = assert_success(f.cmd().args(["auth", "hint"]));
    // Hint goes to stderr (it's advisory, not data).
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("tip:"), "stderr: {stderr}");
    assert!(stderr.contains("ro"), "stderr: {stderr}");
    // Current auth is NOT mentioned in the "others" list.
    assert!(
        !stderr.contains(" admin"),
        "current auth should not appear: {stderr}"
    );
    assert!(stderr.contains("vaultpow auth use"), "stderr: {stderr}");
}

#[test]
fn auth_refresh_with_no_current_auth_lists_available() {
    let f = CliFixture::new();
    // Multi-auth setup but current_auth empty (e.g. just after `auth rm` of current).
    let yaml = r#"clusters:
- name: prod
  server: http://x
  auths:
    - name: a
      token: hvs.a
    - name: b
      token: hvs.b
current_cluster: prod
"#;
    std::fs::write(&f.config_path, yaml).unwrap();
    let out = f.cmd().arg("auth").output().unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("no current auth"), "stderr: {stderr}");
    // Surfaces both available auths so the user can pick.
    assert!(stderr.contains("a"), "stderr: {stderr}");
    assert!(stderr.contains("b"), "stderr: {stderr}");
    assert!(stderr.contains("vaultpow auth use"), "stderr: {stderr}");
}

// ── Legacy migration (CLI surface) ──────────────────────────────────────

#[test]
fn legacy_v01_singular_auth_is_read_transparently() {
    // A user upgrading from v0.1 should not have to touch their config.
    // The first `vaultpow status` (or any read) should surface the legacy
    // token under the auto-created "default" auth.
    let f = CliFixture::new();
    let yaml = r#"clusters:
- name: legacy
  server: http://127.0.0.1:8200
  auth:
    token: hvs.LEGACY
    expire_time: "2099-01-01T00:00:00Z"
    renewable: true
current_cluster: legacy
"#;
    std::fs::write(&f.config_path, yaml).unwrap();
    let out = assert_success(f.cmd().arg("status"));
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("legacy"));
    assert!(
        s.contains("default"),
        "migration should create 'default' auth: {s}"
    );
    assert!(s.contains("token:     stored"), "got: {s}");
}

#[test]
fn legacy_v01_is_rewritten_in_new_form_on_next_save() {
    let f = CliFixture::new();
    let yaml = r#"clusters:
- name: legacy
  server: http://127.0.0.1:8200
  auth:
    token: hvs.LEGACY
current_cluster: legacy
"#;
    std::fs::write(&f.config_path, yaml).unwrap();
    // Triggering any save path (e.g. `ctx <name>`) should rewrite to new schema.
    assert_success(f.cmd().args(["ctx", "legacy"]));
    let after = std::fs::read_to_string(&f.config_path).unwrap();
    assert!(after.contains("auths:"), "expected new schema: {after}");
    assert!(after.contains("current_auth: default"), "got: {after}");
    // Legacy singular `auth:` block should be gone from cluster level.
    assert!(
        !after.lines().any(|l| l.trim() == "auth:"),
        "legacy `auth:` should have been removed: {after}"
    );
}
