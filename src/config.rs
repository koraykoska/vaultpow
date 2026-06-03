// ~/.vaultctx config: serde-backed YAML with atomic writes and tight permissions.
//
// Schema (v0.2 — multi-auth):
//
//     clusters:
//       - name: prod
//         server: https://vault-prod.example.com:8200
//         namespace: admin/team-a
//         auths:
//           - name: oidc-admin
//             method: oidc
//             params:
//               role: admin
//             token: hvs.xxx
//             expire_time: "2026-05-09T18:34:56Z"
//             creation_time: 1715269200
//             creation_ttl: 28800
//             renewable: true
//           - name: read-only
//             method: userpass
//             params:
//               username: alice
//             token: hvs.yyy
//         current_auth: oidc-admin
//     current_cluster: prod
//
// Schema (v0.1 — legacy, single auth per cluster) is read transparently and
// migrated in-memory on load. The migrated form is then written on the next
// `save()`. Legacy:
//
//     clusters:
//       - name: prod
//         server: ...
//         namespace: ...
//         auth:                       # singular
//           token: hvs.xxx
//           expire_time: ...
//           creation_time: ...
//           creation_ttl: ...
//           renewable: ...
//
// Migration rule: legacy `auth` becomes one entry in `auths` named "default",
// and `current_auth` is set to "default". method/params are left empty (we
// don't know what the user originally used).

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct Config {
    #[serde(default)]
    pub clusters: Vec<Cluster>,

    /// Name of the current cluster, or empty if unset.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub current_cluster: String,
}

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct Cluster {
    pub name: String,
    pub server: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,

    /// Named auth profiles. Each entry has its own method, params, and token.
    /// Tokens for OIDC vs userpass vs token methods can coexist; the user
    /// switches between them with `vaultpow auth use <name>`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub auths: Vec<Auth>,

    /// Name of the currently selected auth, or empty if none. Empty means
    /// the user must `vaultpow auth use <name>` (or `auth add`) before any
    /// command that needs a token will work.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub current_auth: String,

    /// Legacy single-auth field (v0.1 schema). Read for migration only —
    /// `#[serde(skip_serializing)]` ensures we never write it back. Migration
    /// is performed by `migrate_legacy()` (called from `load()`).
    ///
    /// `pub(crate)` (not `pub`) so call-sites can still use the
    /// `..Default::default()` struct-update syntax without naming this
    /// field, while keeping it out of the binary crate's external API
    /// surface (such as it is).
    #[serde(default, skip_serializing, rename = "auth")]
    pub(crate) legacy_auth: Option<LegacyAuth>,
}

/// One named auth profile. Holds the method (so re-auth doesn't re-prompt
/// for it), method-specific params (e.g. OIDC role), and the cached token
/// lifecycle metadata.
#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct Auth {
    /// Unique-within-cluster identifier. Used by `vaultpow auth use <name>`.
    pub name: String,

    /// Auth method: "token" | "userpass" | "oidc" | "other". Optional so
    /// migrated entries (which don't know the method) still load cleanly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,

    /// Method-specific parameters. Conventional keys:
    ///   - oidc:     `path` (mount path; default `oidc`), `role`
    ///   - userpass: `path` (mount path; default `userpass`), `username`
    ///   - other:    `args` (the literal whitespace-separated extra args)
    ///
    /// New methods can add keys without a schema migration.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub params: BTreeMap<String, String>,

    /// The Vault/OpenBao token. Stored in plaintext at rest (file is mode 0600).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,

    /// RFC3339 timestamp at which this token expires. None for periodic
    /// tokens or when not yet probed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expire_time: Option<String>,

    /// Unix epoch seconds. Combined with creation_ttl gives the hard deadline.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub creation_time: Option<i64>,

    /// Original TTL granted at issue time, in seconds (a.k.a. max_ttl).
    /// 0 means periodic / no max.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub creation_ttl: Option<i64>,

    /// Whether this token can be renewed via `vault token renew`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub renewable: Option<bool>,
}

/// Legacy single-auth blob from v0.1 configs. Same lifecycle fields as
/// `Auth` but no name/method/params — those weren't tracked back then.
///
/// `pub(crate)` to match the visibility of `Cluster::legacy_auth` (the only
/// place this type is referenced); avoids the `private_interfaces` lint.
#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub(crate) struct LegacyAuth {
    #[serde(default)]
    token: Option<String>,
    #[serde(default)]
    expire_time: Option<String>,
    #[serde(default)]
    creation_time: Option<i64>,
    #[serde(default)]
    creation_ttl: Option<i64>,
    #[serde(default)]
    renewable: Option<bool>,
}

impl LegacyAuth {
    fn is_empty(&self) -> bool {
        self.token.is_none()
            && self.expire_time.is_none()
            && self.creation_time.is_none()
            && self.creation_ttl.is_none()
            && self.renewable.is_none()
    }
}

/// Outcome of `Cluster::remove_auth`. Tells the caller whether the removed
/// auth was the currently selected one and how many auths are left, so they
/// can craft an actionable user message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoveAuthOutcome {
    /// True if the removed auth was the cluster's current_auth.
    pub was_current: bool,
    /// Number of named auths remaining on this cluster after removal.
    pub remaining: usize,
}

pub fn config_path() -> PathBuf {
    if let Ok(p) = std::env::var("VAULTCTX_FILE") {
        return PathBuf::from(p);
    }
    if let Some(home) = std::env::var_os("HOME") {
        return PathBuf::from(home).join(".vaultctx");
    }
    // Last-resort: current dir. Shouldn't realistically happen.
    PathBuf::from(".vaultctx")
}

pub fn load() -> Result<Config> {
    let path = config_path();
    if !path.exists() {
        return Ok(Config::default());
    }
    let content =
        fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    if content.trim().is_empty() {
        return Ok(Config::default());
    }
    let mut cfg: Config = serde_yaml::from_str(&content)
        .with_context(|| format!("parsing YAML in {}", path.display()))?;
    // Walk every cluster and migrate legacy `auth:` → `auths:` + `current_auth`.
    // Done in load() (not save()) so that read-only commands still see the
    // migrated form; we just don't write the file back unless something else
    // mutates it.
    for cluster in &mut cfg.clusters {
        cluster.migrate_legacy();
    }
    Ok(cfg)
}

pub fn save(cfg: &Config) -> Result<()> {
    let path = config_path();
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("config path has no parent"))?;
    if !parent.exists() {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }

    let yaml = serde_yaml::to_string(cfg).context("serializing config")?;

    // Atomic write: tmp file in the same dir, then rename.
    let tmp = path.with_extension("tmp");
    {
        let mut f =
            fs::File::create(&tmp).with_context(|| format!("creating {}", tmp.display()))?;
        f.write_all(yaml.as_bytes())
            .with_context(|| format!("writing {}", tmp.display()))?;
        f.sync_all().ok();
    }

    set_mode_600(&tmp)?;
    fs::rename(&tmp, &path)
        .with_context(|| format!("renaming {} → {}", tmp.display(), path.display()))?;
    set_mode_600(&path)?;
    Ok(())
}

#[cfg(unix)]
fn set_mode_600(path: &std::path::Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = fs::metadata(path)
        .with_context(|| format!("stat {}", path.display()))?
        .permissions();
    perms.set_mode(0o600);
    fs::set_permissions(path, perms).with_context(|| format!("chmod 600 {}", path.display()))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_mode_600(_path: &std::path::Path) -> Result<()> {
    Ok(())
}

impl Config {
    pub fn cluster(&self, name: &str) -> Option<&Cluster> {
        self.clusters.iter().find(|c| c.name == name)
    }

    pub fn cluster_mut(&mut self, name: &str) -> Option<&mut Cluster> {
        self.clusters.iter_mut().find(|c| c.name == name)
    }

    pub fn current(&self) -> Option<&Cluster> {
        if self.current_cluster.is_empty() {
            None
        } else {
            self.cluster(&self.current_cluster)
        }
    }
}

impl Cluster {
    /// Look up a named auth on this cluster.
    pub fn auth(&self, name: &str) -> Option<&Auth> {
        self.auths.iter().find(|a| a.name == name)
    }

    pub fn auth_mut(&mut self, name: &str) -> Option<&mut Auth> {
        self.auths.iter_mut().find(|a| a.name == name)
    }

    /// The currently selected auth profile, or `None` if `current_auth` is
    /// empty or doesn't resolve. Callers that need a token must handle the
    /// `None` case (typically: prompt the user to `auth use <name>` or
    /// `auth add`).
    pub fn current_auth(&self) -> Option<&Auth> {
        if self.current_auth.is_empty() {
            return None;
        }
        self.auth(&self.current_auth)
    }

    /// Mut variant of [`Self::current_auth`]. Useful when patching the
    /// current auth in place (renewal, post-login persist).
    #[allow(dead_code)] // Reserved API; not yet wired into a caller.
    pub fn current_auth_mut(&mut self) -> Option<&mut Auth> {
        if self.current_auth.is_empty() {
            return None;
        }
        let name = self.current_auth.clone();
        self.auth_mut(&name)
    }

    /// Add a named auth. Errors if the name is empty or already exists.
    pub fn add_auth(&mut self, auth: Auth) -> Result<()> {
        if auth.name.trim().is_empty() {
            return Err(anyhow!("auth name cannot be empty"));
        }
        if self.auth(&auth.name).is_some() {
            return Err(anyhow!(
                "auth '{}' already exists on cluster '{}'",
                auth.name,
                self.name
            ));
        }
        self.auths.push(auth);
        Ok(())
    }

    /// Remove a named auth. Always clears `current_auth` if the removed one
    /// was selected — *never* auto-picks a replacement, even when only one
    /// auth remains. This is deliberate: the user must explicitly pick the
    /// next active auth so they're never surprised by a silent switch.
    ///
    /// Returns `RemoveAuthOutcome` describing what happened, so the caller
    /// can craft a useful message ("auth was current; no replacement chosen
    /// — pick one with `vaultpow auth use <name>` or add a new one").
    ///
    /// Errors if the named auth doesn't exist.
    pub fn remove_auth(&mut self, name: &str) -> Result<RemoveAuthOutcome> {
        let pos = self
            .auths
            .iter()
            .position(|a| a.name == name)
            .ok_or_else(|| anyhow!("auth '{name}' not found on cluster '{}'", self.name))?;
        self.auths.remove(pos);
        let was_current = self.current_auth == name;
        if was_current {
            self.current_auth.clear();
        }
        Ok(RemoveAuthOutcome {
            was_current,
            remaining: self.auths.len(),
        })
    }

    /// Migrate a legacy v0.1 `auth:` blob into the v0.2 `auths` + `current_auth`
    /// shape. No-op if there's no legacy field, if it's empty, or if `auths`
    /// already has entries (in which case the legacy field is dropped without
    /// migration to avoid double-counting). Called from `load()`.
    pub(crate) fn migrate_legacy(&mut self) {
        let Some(legacy) = self.legacy_auth.take() else {
            return;
        };
        if legacy.is_empty() || !self.auths.is_empty() {
            return;
        }
        self.auths.push(Auth {
            name: "default".into(),
            method: None,
            params: BTreeMap::new(),
            token: legacy.token,
            expire_time: legacy.expire_time,
            creation_time: legacy.creation_time,
            creation_ttl: legacy.creation_ttl,
            renewable: legacy.renewable,
        });
        if self.current_auth.is_empty() {
            self.current_auth = "default".into();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each test mutates the global VAULTCTX_FILE env var, so they must run
    /// serially. We use a Mutex for that and a tempfile per test.
    use std::sync::Mutex;
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn with_temp_config<F: FnOnce(&std::path::Path)>(f: F) {
        let _g = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("vaultctx.yaml");
        // SAFETY: tests are serialised by TEST_LOCK; no concurrent env access.
        unsafe { std::env::set_var("VAULTCTX_FILE", &path) };
        let prev_home = std::env::var_os("HOME");
        unsafe { std::env::set_var("HOME", dir.path()) };
        f(&path);
        unsafe { std::env::remove_var("VAULTCTX_FILE") };
        if let Some(h) = prev_home {
            unsafe { std::env::set_var("HOME", h) };
        }
    }

    fn make_auth(name: &str, token: &str) -> Auth {
        Auth {
            name: name.into(),
            method: Some("token".into()),
            token: Some(token.into()),
            ..Default::default()
        }
    }

    #[test]
    fn load_returns_default_when_file_missing() {
        with_temp_config(|path| {
            assert!(!path.exists());
            let cfg = load().expect("load default");
            assert!(cfg.clusters.is_empty());
            assert!(cfg.current_cluster.is_empty());
        });
    }

    #[test]
    fn load_returns_default_for_empty_file() {
        with_temp_config(|path| {
            fs::write(path, "").unwrap();
            let cfg = load().expect("load empty");
            assert!(cfg.clusters.is_empty());
        });
    }

    #[test]
    fn auth_params_round_trip_path_role_and_username() {
        // Regression: when the user uses a custom OIDC mount path or stores
        // a userpass username, those must survive a save/load cycle so
        // refreshes don't re-prompt.
        with_temp_config(|_| {
            let mut cfg = Config::default();
            let mut cluster = Cluster {
                name: "c".into(),
                server: "http://x".into(),
                ..Default::default()
            };
            cluster
                .add_auth(Auth {
                    name: "google".into(),
                    method: Some("oidc".into()),
                    params: BTreeMap::from([
                        ("path".into(), "google".into()),
                        ("role".into(), "admin".into()),
                    ]),
                    token: Some("hvs.x".into()),
                    ..Default::default()
                })
                .unwrap();
            cluster
                .add_auth(Auth {
                    name: "ro".into(),
                    method: Some("userpass".into()),
                    params: BTreeMap::from([
                        ("path".into(), "corp-ldap".into()),
                        ("username".into(), "alice".into()),
                    ]),
                    ..Default::default()
                })
                .unwrap();
            cluster.current_auth = "google".into();
            cfg.clusters.push(cluster);
            cfg.current_cluster = "c".into();
            save(&cfg).unwrap();

            let loaded = load().unwrap();
            let oidc = loaded.cluster("c").unwrap().auth("google").unwrap();
            assert_eq!(oidc.params.get("path").map(|s| s.as_str()), Some("google"));
            assert_eq!(oidc.params.get("role").map(|s| s.as_str()), Some("admin"));

            let up = loaded.cluster("c").unwrap().auth("ro").unwrap();
            assert_eq!(up.params.get("path").map(|s| s.as_str()), Some("corp-ldap"));
            assert_eq!(up.params.get("username").map(|s| s.as_str()), Some("alice"));
        });
    }

    #[test]
    fn save_then_load_round_trips_multi_auth() {
        with_temp_config(|_path| {
            let mut cfg = Config::default();
            let mut cluster = Cluster {
                name: "prod".into(),
                server: "https://vault.example.com:8200".into(),
                namespace: Some("admin/foo".into()),
                ..Default::default()
            };
            cluster
                .add_auth(Auth {
                    name: "admin".into(),
                    method: Some("oidc".into()),
                    params: BTreeMap::from([("role".into(), "admin".into())]),
                    token: Some("hvs.AAAA".into()),
                    expire_time: Some("2030-01-01T00:00:00Z".into()),
                    creation_time: Some(1_700_000_000),
                    creation_ttl: Some(3600),
                    renewable: Some(true),
                })
                .unwrap();
            cluster
                .add_auth(Auth {
                    name: "ro".into(),
                    method: Some("userpass".into()),
                    params: BTreeMap::from([("username".into(), "alice".into())]),
                    token: Some("hvs.BBBB".into()),
                    ..Default::default()
                })
                .unwrap();
            cluster.current_auth = "admin".into();
            cfg.clusters.push(cluster);
            cfg.current_cluster = "prod".into();
            save(&cfg).expect("save");

            let loaded = load().expect("load");
            assert_eq!(loaded.clusters.len(), 1);
            let prod = loaded.cluster("prod").unwrap();
            assert_eq!(prod.auths.len(), 2);
            assert_eq!(prod.current_auth, "admin");

            let admin = prod.auth("admin").unwrap();
            assert_eq!(admin.method.as_deref(), Some("oidc"));
            assert_eq!(admin.params.get("role").map(|s| s.as_str()), Some("admin"));
            assert_eq!(admin.token.as_deref(), Some("hvs.AAAA"));

            let ro = prod.auth("ro").unwrap();
            assert_eq!(ro.params.get("username").map(|s| s.as_str()), Some("alice"));
            assert_eq!(ro.token.as_deref(), Some("hvs.BBBB"));
        });
    }

    #[test]
    fn add_auth_rejects_empty_name_and_duplicates() {
        let mut cluster = Cluster {
            name: "x".into(),
            server: "http://x".into(),
            ..Default::default()
        };
        assert!(cluster
            .add_auth(Auth {
                name: "".into(),
                ..Default::default()
            })
            .is_err());
        cluster.add_auth(make_auth("a", "tok")).unwrap();
        let dup = cluster.add_auth(make_auth("a", "tok2"));
        let err = dup.unwrap_err();
        assert!(format!("{err:#}").contains("already exists"));
    }

    #[test]
    fn remove_auth_clears_current_and_never_auto_picks() {
        // Deliberate-by-design: removal of the current auth always clears
        // current_auth, even if exactly one auth remains. The user must
        // explicitly switch — never silently get a different identity.
        let mut cluster = Cluster {
            name: "x".into(),
            server: "http://x".into(),
            ..Default::default()
        };
        cluster.add_auth(make_auth("a", "tok-a")).unwrap();
        cluster.add_auth(make_auth("b", "tok-b")).unwrap();
        cluster.current_auth = "a".into();

        let outcome = cluster.remove_auth("a").unwrap();
        assert_eq!(
            outcome,
            RemoveAuthOutcome {
                was_current: true,
                remaining: 1
            }
        );
        assert_eq!(cluster.current_auth, "");
        assert_eq!(cluster.auths.len(), 1);
        assert!(cluster.current_auth().is_none());
    }

    #[test]
    fn remove_auth_leaves_current_alone_when_removing_a_different_one() {
        let mut cluster = Cluster {
            name: "x".into(),
            server: "http://x".into(),
            ..Default::default()
        };
        cluster.add_auth(make_auth("a", "tok-a")).unwrap();
        cluster.add_auth(make_auth("b", "tok-b")).unwrap();
        cluster.current_auth = "a".into();

        let outcome = cluster.remove_auth("b").unwrap();
        assert_eq!(
            outcome,
            RemoveAuthOutcome {
                was_current: false,
                remaining: 1
            }
        );
        assert_eq!(cluster.current_auth, "a");
    }

    #[test]
    fn remove_auth_unknown_errors() {
        let mut cluster = Cluster {
            name: "x".into(),
            server: "http://x".into(),
            ..Default::default()
        };
        cluster.add_auth(make_auth("a", "tok")).unwrap();
        let err = cluster.remove_auth("missing").unwrap_err();
        assert!(format!("{err:#}").contains("not found"));
    }

    #[test]
    fn current_auth_returns_none_when_unset_or_dangling() {
        let mut cluster = Cluster {
            name: "x".into(),
            server: "http://x".into(),
            ..Default::default()
        };
        assert!(cluster.current_auth().is_none());

        cluster.add_auth(make_auth("a", "tok")).unwrap();
        // current_auth still empty:
        assert!(cluster.current_auth().is_none());

        // Dangling pointer:
        cluster.current_auth = "ghost".into();
        assert!(cluster.current_auth().is_none());

        cluster.current_auth = "a".into();
        assert_eq!(cluster.current_auth().map(|a| a.name.as_str()), Some("a"));
    }

    // ── Legacy migration ────────────────────────────────────────────────

    #[test]
    fn loads_v01_legacy_singular_auth_and_migrates() {
        with_temp_config(|path| {
            let yaml = r#"clusters:
- name: prod
  server: https://vault.example.com:8200
  namespace: admin/foo
  auth:
    token: hvs.LEGACY
    expire_time: "2030-01-01T00:00:00Z"
    creation_time: 1700000000
    creation_ttl: 3600
    renewable: true
current_cluster: prod
"#;
            fs::write(path, yaml).unwrap();
            let cfg = load().expect("load + migrate");
            let prod = cfg.cluster("prod").unwrap();
            assert_eq!(prod.auths.len(), 1, "legacy auth should become one entry");
            assert_eq!(prod.current_auth, "default");
            let a = prod.auth("default").unwrap();
            assert_eq!(a.token.as_deref(), Some("hvs.LEGACY"));
            assert_eq!(a.expire_time.as_deref(), Some("2030-01-01T00:00:00Z"));
            assert_eq!(a.creation_time, Some(1_700_000_000));
            assert_eq!(a.creation_ttl, Some(3600));
            assert_eq!(a.renewable, Some(true));
            // Migration metadata defaults: no method/params recorded since the
            // legacy schema didn't track them.
            assert!(a.method.is_none());
            assert!(a.params.is_empty());
        });
    }

    #[test]
    fn legacy_auth_with_no_token_does_not_create_default_entry() {
        // A cluster that was added but never authed — the v0.1 schema would
        // serialise an empty `auth:` block. Migration shouldn't create a
        // bogus "default" auth from that.
        with_temp_config(|path| {
            let yaml = r#"clusters:
- name: dev
  server: http://x
  auth: {}
current_cluster: dev
"#;
            fs::write(path, yaml).unwrap();
            let cfg = load().unwrap();
            let dev = cfg.cluster("dev").unwrap();
            assert!(dev.auths.is_empty());
            assert_eq!(dev.current_auth, "");
        });
    }

    #[test]
    fn legacy_field_never_appears_in_serialised_output() {
        // After migration, save() must write the new schema only — no
        // singular `auth:` key, even though the in-memory Cluster's
        // legacy_auth field has been (re)taken to None.
        with_temp_config(|path| {
            let yaml = r#"clusters:
- name: prod
  server: http://x
  auth:
    token: hvs.LEGACY
current_cluster: prod
"#;
            fs::write(path, yaml).unwrap();
            let cfg = load().unwrap();
            save(&cfg).unwrap();
            let raw = fs::read_to_string(path).unwrap();
            // No legacy `auth:` block at cluster level.
            assert!(
                !raw.lines().any(|l| l.trim() == "auth:"),
                "legacy `auth:` should not be written: {raw}"
            );
            // New schema fields should be present.
            assert!(raw.contains("auths:"), "got: {raw}");
            assert!(raw.contains("current_auth: default"), "got: {raw}");
        });
    }

    #[test]
    fn legacy_skipped_when_new_auths_already_present() {
        // Defensive: if a (broken) config had both legacy `auth:` AND new
        // `auths:`, prefer the new and drop the legacy without merging.
        with_temp_config(|path| {
            let yaml = r#"clusters:
- name: prod
  server: http://x
  auth:
    token: hvs.OLD
  auths:
    - name: new
      token: hvs.NEW
  current_auth: new
current_cluster: prod
"#;
            fs::write(path, yaml).unwrap();
            let cfg = load().unwrap();
            let prod = cfg.cluster("prod").unwrap();
            assert_eq!(prod.auths.len(), 1);
            assert_eq!(prod.auths[0].token.as_deref(), Some("hvs.NEW"));
        });
    }

    // ── Invariants on serialised output ─────────────────────────────────

    #[test]
    fn empty_current_cluster_is_omitted() {
        with_temp_config(|path| {
            let cfg = Config::default();
            save(&cfg).unwrap();
            let raw = fs::read_to_string(path).unwrap();
            assert!(!raw.contains("current_cluster"), "got: {raw}");
        });
    }

    #[test]
    fn cluster_lookup_helpers() {
        let mut cfg = Config::default();
        cfg.clusters.push(Cluster {
            name: "a".into(),
            server: "http://a".into(),
            ..Default::default()
        });
        cfg.current_cluster = "a".into();

        assert!(cfg.cluster("a").is_some());
        assert!(cfg.cluster("missing").is_none());
        assert_eq!(cfg.current().map(|c| c.name.as_str()), Some("a"));

        cfg.cluster_mut("a").unwrap().server = "http://changed".into();
        assert_eq!(cfg.cluster("a").unwrap().server, "http://changed");

        cfg.current_cluster.clear();
        assert!(cfg.current().is_none());
    }

    #[cfg(unix)]
    #[test]
    fn save_sets_mode_600() {
        use std::os::unix::fs::PermissionsExt;
        with_temp_config(|path| {
            let cfg = Config::default();
            save(&cfg).unwrap();
            let mode = fs::metadata(path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "expected 0o600, got {mode:o}");
        });
    }

    #[test]
    fn load_propagates_yaml_parse_errors() {
        with_temp_config(|path| {
            fs::write(path, "this: is: not valid: yaml: at: all").unwrap();
            let err = load().unwrap_err();
            let s = format!("{err:#}");
            assert!(s.contains("parsing YAML"), "got: {s}");
        });
    }

    #[test]
    fn config_path_respects_env() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        unsafe { std::env::set_var("VAULTCTX_FILE", "/tmp/vp-test-config-path") };
        assert_eq!(
            config_path(),
            std::path::PathBuf::from("/tmp/vp-test-config-path")
        );
        unsafe { std::env::remove_var("VAULTCTX_FILE") };
    }
}
