// Vault HTTP client + token state machine.
//
// Why direct HTTP instead of shelling out to `vault` for every probe?
// - Faster (no process spawn per check)
// - We can build a real state machine with real errors
// - Doesn't require the `vault` CLI for read-only ops like token lookup
//
// Interactive auth methods (oidc browser flow, userpass with prompts) still
// shell out to `vault login`, since reimplementing OIDC's PKCE+browser dance
// is out of scope.

use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Utc};
use serde::Deserialize;

use crate::config::{Auth, Cluster};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// Just the lifecycle metadata Vault returns from `auth/token/lookup-self`
/// or `auth/token/renew-self`. Decoupled from `Auth` (which also carries
/// name/method/params) so HTTP code never accidentally clobbers those.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TokenLifecycle {
    pub expire_time: Option<String>,
    pub creation_time: Option<i64>,
    pub creation_ttl: Option<i64>,
    pub renewable: Option<bool>,
}

impl TokenLifecycle {
    /// Patch this lifecycle onto a stored `Auth`. Used when persisting the
    /// result of a server probe back to ~/.vaultctx.
    pub fn apply_to(&self, auth: &mut Auth) {
        auth.expire_time = self.expire_time.clone();
        auth.creation_time = self.creation_time;
        auth.creation_ttl = self.creation_ttl;
        auth.renewable = self.renewable;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenState {
    /// Token is valid with comfortable TTL remaining.
    Ok,
    /// Token is near expiry but renewable and within max_ttl.
    Renewable,
    /// Token is near expiry but not renewable, or at/past max_ttl.
    Expiring,
    /// Token has expired or been revoked (server rejects it).
    Expired,
    /// No token stored.
    Absent,
    /// Server is unreachable; can't determine real state. Don't loop into auth.
    Unreachable,
}

impl TokenState {
    pub fn as_str(&self) -> &'static str {
        match self {
            TokenState::Ok => "ok",
            TokenState::Renewable => "renewable",
            TokenState::Expiring => "expiring",
            TokenState::Expired => "expired",
            TokenState::Absent => "absent",
            TokenState::Unreachable => "unreachable",
        }
    }
}

/// Default grace window in seconds: re-auth/renew if token expires within this.
pub fn expiry_grace_secs() -> i64 {
    std::env::var("VAULTPOW_EXPIRY_GRACE")
        .ok()
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(60)
}

#[derive(Debug, Deserialize)]
struct TokenLookupResp {
    data: TokenData,
}

#[derive(Debug, Deserialize)]
struct TokenData {
    #[serde(default)]
    expire_time: Option<String>,
    #[serde(default)]
    creation_time: Option<i64>,
    #[serde(default)]
    creation_ttl: Option<i64>,
    #[serde(default)]
    renewable: Option<bool>,
}

/// Vault's token-renew response wraps the new info under `auth`.
#[derive(Debug, Deserialize)]
struct TokenRenewResp {
    auth: RenewAuth,
}

#[derive(Debug, Deserialize)]
struct RenewAuth {
    #[serde(default)]
    lease_duration: Option<i64>,
    #[serde(default)]
    renewable: Option<bool>,
}

fn http_client(server: &str) -> Result<reqwest::blocking::Client> {
    // Tolerate self-signed certs only when explicitly opted in. Most enterprise
    // Vault deployments terminate TLS with a corp CA already on the user's
    // machine; if not, set VAULT_SKIP_VERIFY=1.
    let skip = std::env::var("VAULT_SKIP_VERIFY")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    let _ = url::Url::parse(server).with_context(|| format!("invalid server URL: {server}"))?;

    let mut builder = reqwest::blocking::Client::builder()
        .timeout(DEFAULT_TIMEOUT)
        .user_agent(concat!("vaultpow/", env!("CARGO_PKG_VERSION")));

    if skip {
        builder = builder.danger_accept_invalid_certs(true);
    }

    builder.build().context("building HTTP client")
}

/// Look up the cluster's *current* token via Vault's `auth/token/lookup-self`.
/// Returns just the lifecycle metadata (the caller patches it onto the
/// stored `Auth` so name/method/params aren't clobbered).
///
/// `Ok(None)` when the cluster has no current auth, or the current auth has
/// no token. `Err(...)` on transport failure or rejected token.
pub fn token_lookup(cluster: &Cluster) -> Result<Option<TokenLifecycle>> {
    let token = match cluster.current_auth().and_then(|a| a.token.as_deref()) {
        Some(t) if !t.is_empty() => t,
        _ => return Ok(None),
    };

    let client = http_client(&cluster.server)?;
    let url = format!(
        "{}/v1/auth/token/lookup-self",
        cluster.server.trim_end_matches('/')
    );

    let mut req = client.get(&url).header("X-Vault-Token", token);
    if let Some(ns) = &cluster.namespace {
        if !ns.is_empty() {
            req = req.header("X-Vault-Namespace", ns);
        }
    }

    let resp = req.send().context("sending token lookup request")?;
    let status = resp.status();
    if !status.is_success() {
        // 403 Forbidden / 401 Unauthorized → token is bad. Other failures
        // bubble up to the caller via the state machine's reachability check.
        if status.as_u16() == 403 || status.as_u16() == 401 {
            return Err(anyhow!("token rejected ({})", status));
        }
        return Err(anyhow!("token lookup failed: HTTP {}", status));
    }

    let parsed: TokenLookupResp = resp.json().context("parsing token lookup response")?;
    Ok(Some(TokenLifecycle {
        expire_time: parsed.data.expire_time,
        creation_time: parsed.data.creation_time,
        creation_ttl: parsed.data.creation_ttl,
        renewable: parsed.data.renewable,
    }))
}

/// Cheap probe: is the server reachable at all? Doesn't require a token.
pub fn server_reachable(cluster: &Cluster) -> bool {
    let Ok(client) = http_client(&cluster.server) else {
        return false;
    };
    let url = format!("{}/v1/sys/health", cluster.server.trim_end_matches('/'));
    // sys/health returns 200/429/472/473/501/503 depending on cluster state.
    // Any of these means the server is alive. Connection errors mean it's not.
    client.get(&url).send().is_ok()
}

/// Renew the cluster's current token via `auth/token/renew-self`. Returns
/// the partial lifecycle (expire_time + renewable) the caller should merge
/// onto the stored Auth. Errors if the cluster has no current auth, the
/// current auth has no token, or the server rejects the renew.
pub fn token_renew(cluster: &Cluster, increment_secs: Option<i64>) -> Result<TokenLifecycle> {
    let token = cluster
        .current_auth()
        .and_then(|a| a.token.as_deref())
        .filter(|t| !t.is_empty())
        .ok_or_else(|| anyhow!("no token to renew"))?;

    let client = http_client(&cluster.server)?;
    let url = format!(
        "{}/v1/auth/token/renew-self",
        cluster.server.trim_end_matches('/')
    );

    let mut body = serde_json::Map::new();
    if let Some(inc) = increment_secs {
        body.insert(
            "increment".into(),
            serde_json::Value::String(format!("{inc}s")),
        );
    }

    let mut req = client.post(&url).header("X-Vault-Token", token).json(&body);
    if let Some(ns) = &cluster.namespace {
        if !ns.is_empty() {
            req = req.header("X-Vault-Namespace", ns);
        }
    }

    let resp = req.send().context("sending token renew request")?;
    let status = resp.status();
    if !status.is_success() {
        return Err(anyhow!("token renew failed: HTTP {}", status));
    }

    let parsed: TokenRenewResp = resp.json().context("parsing token renew response")?;

    // Compute new expire_time from lease_duration.
    let new_expire = parsed.auth.lease_duration.map(|secs| {
        let now: DateTime<Utc> = Utc::now();
        let new = now + chrono::Duration::seconds(secs);
        new.to_rfc3339()
    });

    // Renew doesn't return creation_time/ttl — those are set at issue time.
    // We carry them over from the stored auth so the hard-deadline math
    // continues to work after renewal.
    let stored = cluster.current_auth();
    Ok(TokenLifecycle {
        expire_time: new_expire,
        creation_time: stored.and_then(|a| a.creation_time),
        creation_ttl: stored.and_then(|a| a.creation_ttl),
        renewable: parsed
            .auth
            .renewable
            .or_else(|| stored.and_then(|a| a.renewable)),
    })
}

/// Classify the cluster's current token. Inspects `cluster.current_auth()`
/// — if there isn't one, or it has no token, returns `Absent`.
///
/// Caller may want to persist the lifecycle returned by `token_lookup` if
/// state was determined by a server probe — that path is taken in
/// `commands::ensure_fresh` and `commands::check_token`.
pub fn classify(cluster: &Cluster) -> TokenState {
    let Some(auth) = cluster.current_auth() else {
        return TokenState::Absent;
    };
    if auth.token.as_deref().is_none_or(|t| t.is_empty()) {
        return TokenState::Absent;
    }

    let now = Utc::now();
    let grace = chrono::Duration::seconds(expiry_grace_secs());

    // Fast path: cached expire_time
    if let Some(et) = auth.expire_time.as_deref() {
        if let Ok(parsed) = DateTime::parse_from_rfc3339(et) {
            let parsed = parsed.with_timezone(&Utc);
            if parsed <= now {
                return TokenState::Expired;
            }
            if parsed <= now + grace {
                // Within grace. Renewable?
                let renewable = auth.renewable.unwrap_or(false);
                let hard_deadline = hard_deadline_for(auth);
                let can_renew = renewable
                    && match hard_deadline {
                        Some(hd) => now + grace < hd,
                        None => true, // periodic / unknown — try anyway
                    };
                return if can_renew {
                    TokenState::Renewable
                } else {
                    TokenState::Expiring
                };
            }
            return TokenState::Ok;
        }
    }

    // No cache — probe the server.
    match token_lookup(cluster) {
        Ok(Some(_)) => TokenState::Ok,
        Ok(None) => TokenState::Absent,
        Err(_) => {
            if server_reachable(cluster) {
                TokenState::Expired
            } else {
                TokenState::Unreachable
            }
        }
    }
}

/// Compute the hard deadline (creation_time + creation_ttl) for one auth.
/// Returns `None` for periodic tokens (creation_ttl == 0) and when the
/// metadata is incomplete.
fn hard_deadline_for(auth: &Auth) -> Option<DateTime<Utc>> {
    let ct = auth.creation_time?;
    let cttl = auth.creation_ttl?;
    if cttl == 0 {
        return None; // periodic
    }
    DateTime::from_timestamp(ct + cttl, 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Auth, Cluster};

    /// Build a test cluster that owns a single named auth and selects it.
    /// Most tests only care about the lifecycle of the current auth, so this
    /// keeps the boilerplate down to a minimum.
    fn cluster(mut auth: Auth) -> Cluster {
        if auth.name.is_empty() {
            auth.name = "default".into();
        }
        let name = auth.name.clone();
        Cluster {
            name: "t".into(),
            server: "http://127.0.0.1:1".into(),
            namespace: None,
            auths: vec![auth],
            current_auth: name,
            ..Default::default()
        }
    }

    fn rfc3339_in(secs_from_now: i64) -> String {
        (Utc::now() + chrono::Duration::seconds(secs_from_now)).to_rfc3339()
    }

    #[test]
    fn token_state_as_str_covers_every_variant() {
        // Sanity that the string mapping is stable — it's part of the
        // shell-hook contract (`vaultpow check-token` output).
        assert_eq!(TokenState::Ok.as_str(), "ok");
        assert_eq!(TokenState::Renewable.as_str(), "renewable");
        assert_eq!(TokenState::Expiring.as_str(), "expiring");
        assert_eq!(TokenState::Expired.as_str(), "expired");
        assert_eq!(TokenState::Absent.as_str(), "absent");
        assert_eq!(TokenState::Unreachable.as_str(), "unreachable");
    }

    #[test]
    fn classify_absent_when_cluster_has_no_current_auth() {
        // Cluster with auths configured but current_auth empty → Absent.
        let c = Cluster {
            name: "t".into(),
            server: "http://127.0.0.1:1".into(),
            auths: vec![Auth {
                name: "a".into(),
                token: Some("hvs.x".into()),
                expire_time: Some(rfc3339_in(3600)),
                ..Default::default()
            }],
            current_auth: String::new(),
            ..Default::default()
        };
        assert_eq!(classify(&c), TokenState::Absent);
    }

    #[test]
    fn classify_absent_when_current_auth_has_no_token() {
        assert_eq!(
            classify(&cluster(Auth {
                name: "a".into(),
                ..Default::default()
            })),
            TokenState::Absent
        );
        assert_eq!(
            classify(&cluster(Auth {
                name: "a".into(),
                token: Some(String::new()),
                ..Default::default()
            })),
            TokenState::Absent
        );
    }

    #[test]
    fn classify_ok_when_well_within_ttl() {
        let auth = Auth {
            name: "a".into(),
            token: Some("hvs.x".into()),
            // 1 hour from now — well past the 60s grace window.
            expire_time: Some(rfc3339_in(3600)),
            ..Default::default()
        };
        assert_eq!(classify(&cluster(auth)), TokenState::Ok);
    }

    #[test]
    fn classify_expired_when_past_expiry() {
        let auth = Auth {
            name: "a".into(),
            token: Some("hvs.x".into()),
            expire_time: Some(rfc3339_in(-1)),
            ..Default::default()
        };
        assert_eq!(classify(&cluster(auth)), TokenState::Expired);
    }

    #[test]
    fn classify_renewable_when_within_grace_and_renewable_and_before_max_ttl() {
        let now = Utc::now().timestamp();
        let auth = Auth {
            name: "a".into(),
            token: Some("hvs.x".into()),
            // 30s from now: inside the 60s grace.
            expire_time: Some(rfc3339_in(30)),
            renewable: Some(true),
            // Hard deadline 1 hour out → renewing now is fine.
            creation_time: Some(now - 60),
            creation_ttl: Some(3600),
            ..Default::default()
        };
        assert_eq!(classify(&cluster(auth)), TokenState::Renewable);
    }

    #[test]
    fn classify_expiring_when_within_grace_but_not_renewable() {
        let auth = Auth {
            name: "a".into(),
            token: Some("hvs.x".into()),
            expire_time: Some(rfc3339_in(30)),
            renewable: Some(false),
            ..Default::default()
        };
        assert_eq!(classify(&cluster(auth)), TokenState::Expiring);
    }

    #[test]
    fn classify_expiring_when_renewable_but_past_max_ttl() {
        let now = Utc::now().timestamp();
        let auth = Auth {
            name: "a".into(),
            token: Some("hvs.x".into()),
            // 30s out: inside grace.
            expire_time: Some(rfc3339_in(30)),
            renewable: Some(true),
            // Hard deadline already in the past → renewing won't extend us.
            creation_time: Some(now - 7200),
            creation_ttl: Some(3600),
            ..Default::default()
        };
        assert_eq!(classify(&cluster(auth)), TokenState::Expiring);
    }

    #[test]
    fn classify_renewable_for_periodic_token_inside_grace() {
        // Periodic tokens (creation_ttl == 0) have no hard deadline.
        let auth = Auth {
            name: "a".into(),
            token: Some("hvs.x".into()),
            expire_time: Some(rfc3339_in(30)),
            renewable: Some(true),
            creation_time: Some(Utc::now().timestamp()),
            creation_ttl: Some(0),
            ..Default::default()
        };
        assert_eq!(classify(&cluster(auth)), TokenState::Renewable);
    }

    #[test]
    fn classify_renewable_when_creation_metadata_unknown() {
        // Without creation_time/ttl we can't compute a hard deadline; we
        // optimistically allow the renewal attempt.
        let auth = Auth {
            name: "a".into(),
            token: Some("hvs.x".into()),
            expire_time: Some(rfc3339_in(30)),
            renewable: Some(true),
            creation_time: None,
            creation_ttl: None,
            ..Default::default()
        };
        assert_eq!(classify(&cluster(auth)), TokenState::Renewable);
    }

    #[test]
    fn classify_unparseable_expire_time_falls_through_to_probe() {
        // Garbage in expire_time → classify falls through to a server probe,
        // which fails because 127.0.0.1:1 is unreachable → Unreachable.
        let auth = Auth {
            name: "a".into(),
            token: Some("hvs.x".into()),
            expire_time: Some("not a date".into()),
            ..Default::default()
        };
        let s = classify(&cluster(auth));
        assert!(matches!(s, TokenState::Unreachable | TokenState::Expired));
    }

    #[test]
    fn hard_deadline_returns_none_for_periodic() {
        let auth = Auth {
            name: "a".into(),
            token: Some("x".into()),
            creation_time: Some(1_700_000_000),
            creation_ttl: Some(0),
            ..Default::default()
        };
        assert!(hard_deadline_for(&auth).is_none());
    }

    #[test]
    fn hard_deadline_computes_creation_plus_ttl() {
        let auth = Auth {
            name: "a".into(),
            token: Some("x".into()),
            creation_time: Some(1_700_000_000),
            creation_ttl: Some(3600),
            ..Default::default()
        };
        let d = hard_deadline_for(&auth).unwrap();
        assert_eq!(d.timestamp(), 1_700_003_600);
    }

    #[test]
    fn hard_deadline_none_when_metadata_missing() {
        let mut a = Auth {
            name: "a".into(),
            token: Some("x".into()),
            creation_time: None,
            creation_ttl: Some(3600),
            ..Default::default()
        };
        assert!(hard_deadline_for(&a).is_none());
        a.creation_time = Some(1);
        a.creation_ttl = None;
        assert!(hard_deadline_for(&a).is_none());
    }

    #[test]
    fn expiry_grace_secs_default_and_env_override() {
        // Combined into one test because cargo's parallel test runner makes
        // splitting env-var tests racy without an explicit Mutex. Simpler to
        // serialise the cases here.
        unsafe { std::env::remove_var("VAULTPOW_EXPIRY_GRACE") };
        assert_eq!(expiry_grace_secs(), 60);

        unsafe { std::env::set_var("VAULTPOW_EXPIRY_GRACE", "120") };
        assert_eq!(expiry_grace_secs(), 120);

        // Bogus values fall back to the default.
        unsafe { std::env::set_var("VAULTPOW_EXPIRY_GRACE", "junk") };
        assert_eq!(expiry_grace_secs(), 60);

        unsafe { std::env::remove_var("VAULTPOW_EXPIRY_GRACE") };
    }

    #[test]
    fn http_client_rejects_invalid_url() {
        let err = http_client("not-a-url").unwrap_err();
        let s = format!("{err:#}");
        assert!(s.contains("invalid server URL"), "got: {s}");
    }
}
