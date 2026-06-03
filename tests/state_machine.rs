// State-machine integration tests for the token classifier.
//
// We exercise classify() (via `vaultpow check-token`) with combinations of:
//   - token present? expire_time cached?
//   - within grace? renewable? past max_ttl? server reachable?
//
// The cached-expiry fast path is covered by the unit tests in src/vault.rs
// without needing network. These tests cover the *probe* fall-through where
// expire_time is None and we have to ask the server.

mod common;

use chrono::Utc;
use common::{CannedResponse, CliFixture, MockVault};

/// Write a config.yaml directly so we can pre-seed an Auth blob without
/// needing to invoke `vaultpow auth` (which prompts).
fn write_config(f: &CliFixture, server: &str, auth_yaml: &str) {
    let yaml = format!(
        r#"clusters:
- name: t
  server: {server}
  auth:
{auth_yaml}
current_cluster: t
"#
    );
    std::fs::write(&f.config_path, yaml).unwrap();
}

fn check_token(f: &CliFixture) -> String {
    let out = f.cmd().arg("check-token").output().unwrap();
    assert!(
        out.status.success(),
        "check-token failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

#[test]
fn check_token_ok_when_server_accepts_lookup() {
    let server = MockVault::start();
    server.route_health_ok();
    server.route(
        "GET",
        "/v1/auth/token/lookup-self",
        CannedResponse::ok(format!(
            r#"{{"data":{{"expire_time":"{}","creation_time":{},"creation_ttl":3600,"renewable":true}}}}"#,
            (Utc::now() + chrono::Duration::seconds(3600)).to_rfc3339(),
            Utc::now().timestamp(),
        )),
    );

    let f = CliFixture::new();
    write_config(&f, &server.addr, "    token: hvs.alive");
    assert_eq!(check_token(&f), "ok");
}

#[test]
fn check_token_expired_when_lookup_rejected_and_health_ok() {
    let server = MockVault::start();
    server.route_health_ok();
    server.route(
        "GET",
        "/v1/auth/token/lookup-self",
        CannedResponse::forbidden(),
    );

    let f = CliFixture::new();
    write_config(&f, &server.addr, "    token: hvs.dead");
    assert_eq!(check_token(&f), "expired");
}

#[test]
fn check_token_unreachable_when_no_server() {
    // Bind a port and immediately drop the listener so connections are
    // refused. (Can't just point at a nonsense address — DNS would fail
    // before we get to the connection refused path.)
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);

    let f = CliFixture::new();
    write_config(&f, &format!("http://127.0.0.1:{port}"), "    token: hvs.x");
    assert_eq!(check_token(&f), "unreachable");
}

#[test]
fn check_token_absent_when_no_token_in_config() {
    let f = CliFixture::new();
    write_config(&f, "http://127.0.0.1:1", "");
    assert_eq!(check_token(&f), "absent");
}

#[test]
fn check_token_uses_cached_expire_time_without_network() {
    // No mock server: if the binary tries to make a network call we fail.
    // (Localhost port 1 is closed — connection refused is fast on Unix.)
    let f = CliFixture::new();
    let future = (Utc::now() + chrono::Duration::seconds(3600)).to_rfc3339();
    write_config(
        &f,
        "http://127.0.0.1:1",
        &format!(
            "    token: hvs.x
    expire_time: \"{future}\"
    creation_time: {}
    creation_ttl: 7200
    renewable: true",
            Utc::now().timestamp()
        ),
    );
    assert_eq!(check_token(&f), "ok");
}

#[test]
fn check_token_cached_renewable_within_grace_returns_renewable() {
    let f = CliFixture::new();
    let near = (Utc::now() + chrono::Duration::seconds(30)).to_rfc3339();
    write_config(
        &f,
        "http://127.0.0.1:1",
        &format!(
            "    token: hvs.x
    expire_time: \"{near}\"
    creation_time: {}
    creation_ttl: 7200
    renewable: true",
            Utc::now().timestamp()
        ),
    );
    assert_eq!(check_token(&f), "renewable");
}

#[test]
fn check_token_cached_non_renewable_within_grace_returns_expiring() {
    let f = CliFixture::new();
    let near = (Utc::now() + chrono::Duration::seconds(30)).to_rfc3339();
    write_config(
        &f,
        "http://127.0.0.1:1",
        &format!(
            "    token: hvs.x
    expire_time: \"{near}\"
    renewable: false"
        ),
    );
    assert_eq!(check_token(&f), "expiring");
}

#[test]
fn check_token_cached_past_expiry_returns_expired() {
    let f = CliFixture::new();
    let past = (Utc::now() - chrono::Duration::seconds(10)).to_rfc3339();
    write_config(
        &f,
        "http://127.0.0.1:1",
        &format!(
            "    token: hvs.x
    expire_time: \"{past}\""
        ),
    );
    assert_eq!(check_token(&f), "expired");
}

#[test]
fn check_token_cached_renewable_past_max_ttl_returns_expiring() {
    // Renewable=true but creation_time + creation_ttl is in the past →
    // renewing the token won't actually buy us more time. classify() should
    // recognise this and return Expiring (forces full re-auth).
    let f = CliFixture::new();
    let near = (Utc::now() + chrono::Duration::seconds(30)).to_rfc3339();
    let now = Utc::now().timestamp();
    write_config(
        &f,
        "http://127.0.0.1:1",
        &format!(
            "    token: hvs.x
    expire_time: \"{near}\"
    creation_time: {}
    creation_ttl: 3600
    renewable: true",
            now - 7200
        ),
    );
    assert_eq!(check_token(&f), "expiring");
}

#[test]
fn mock_vault_records_namespace_and_token_headers() {
    let server = MockVault::start();
    server.route_health_ok();
    server.route(
        "GET",
        "/v1/auth/token/lookup-self",
        CannedResponse::ok(
            r#"{"data":{"expire_time":null,"creation_time":null,"creation_ttl":null,"renewable":false}}"#,
        ),
    );

    let f = CliFixture::new();
    write_config(
        &f,
        &server.addr,
        "    token: hvs.x
  namespace: admin/foo",
    );
    // Whoops — write_config indents auth fields under `auth:`; the
    // namespace key needs to be at cluster level, not auth level. Rewrite
    // explicitly to keep this test honest.
    let yaml = format!(
        r#"clusters:
- name: t
  server: {}
  namespace: admin/foo
  auth:
    token: hvs.x
current_cluster: t
"#,
        server.addr
    );
    std::fs::write(&f.config_path, yaml).unwrap();

    let _ = check_token(&f);

    let reqs = server.requests();
    let lookup = reqs
        .iter()
        .find(|r| r.path == "/v1/auth/token/lookup-self")
        .expect("lookup-self request");
    assert_eq!(
        lookup.headers.get("x-vault-token").map(|s| s.as_str()),
        Some("hvs.x")
    );
    assert_eq!(
        lookup.headers.get("x-vault-namespace").map(|s| s.as_str()),
        Some("admin/foo")
    );
}
