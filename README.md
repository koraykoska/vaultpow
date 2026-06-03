# vaultpow

> kubectx-style context switcher for HashiCorp Vault and OpenBao — multiple clusters, namespace switching, and transparent token renewal/re-auth.

```
$ vault kv get secret/foo
vaultpow: token for 'prod' is near expiry — attempting renewal
Key                Value
---                -----
created_time       2026-05-09T12:34:56Z
deletion_time      n/a
destroyed          false
version            3
```

You type `vault` (or `bao`). Behind the scenes vaultpow picks the right cluster, namespace, and token, renews the token if it's about to expire, and re-authenticates if it's already gone.

---

## Features

- **Multiple clusters** in one config file (`~/.vaultctx`) with one-command switching
- **Named auths per cluster** — keep multiple identities (e.g. an `admin` OIDC role and a `readonly` userpass) on the same cluster and switch between them with `vaultpow auth use <name>`; tokens stay cached per-auth
- **Namespace switching** per cluster (Vault Enterprise namespaces and OSS root)
- **Transparent token lifecycle**: caches `expire_time`, `creation_ttl`, and `renewable`; renews when possible, re-auths when not
- **Shell hook** wraps both `vault` AND `bao` (OpenBao) so you don't have to type `vaultpow` for everyday calls — same UX as `kubectx`/`kubens`. Tokens are interchangeable between the two CLIs
- **Multiple auth methods**: token, userpass, OIDC (browser), or pass-through to `vault login` / `bao login` for anything else
- **Helpful failure hints**: when a wrapped command fails with a valid token, vaultpow suggests trying another configured auth — common case for "this role can't read that secret"
- **Single static binary**, no runtime dependencies (the `vault`/`bao` CLI is only needed for interactive logins, not for token probes/renewals)

## Install

### Homebrew (macOS Apple Silicon, Linux x86_64/arm64)

vaultpow ships its own [tap](https://docs.brew.sh/Taps) from this repository:

```bash
brew tap koraykoska/vaultpow https://github.com/koraykoska/vaultpow
brew install vaultpow
```

(After the tap is added, the formula is also available as the fully qualified name `koraykoska/vaultpow/vaultpow`.)

`brew upgrade vaultpow` will pick up new releases automatically — the formula is auto-bumped on each tag. Shell completions for bash, zsh, and fish are installed by brew into the standard locations; the `vault`/`bao` shell hook is **not** auto-installed (brew doesn't modify your rc files), so you still need the [shell hook step](#shell-hook-the-kubectx-style-magic) below.

### Manual (Linux & macOS)

Grab a binary from the [latest release](https://github.com/koraykoska/vaultpow/releases/latest). The asset names follow `vaultpow-<os>-<arch>.tar.gz`:

```bash
# Pick the matching tarball for your platform
ASSET=vaultpow-linux-amd64       # or: vaultpow-linux-arm64, vaultpow-macos-arm64

# Download + verify
curl -fsSLO "https://github.com/koraykoska/vaultpow/releases/latest/download/${ASSET}.tar.gz"
curl -fsSLO "https://github.com/koraykoska/vaultpow/releases/latest/download/${ASSET}.tar.gz.sha256"
shasum -a 256 -c "${ASSET}.tar.gz.sha256"

# Extract; install the binary somewhere on PATH
tar -xzf "${ASSET}.tar.gz"
sudo install -m 0755 vaultpow /usr/local/bin/vaultpow

# Wire up the shell hook (one-time)
echo 'eval "$(vaultpow shell-init zsh)"'  >> ~/.zshrc      # or:
echo 'eval "$(vaultpow shell-init bash)"' >> ~/.bashrc

# (Optional) Install completions
vaultpow completions zsh  > "${fpath[1]}/_vaultpow"
vaultpow completions bash > /etc/bash_completion.d/vaultpow
vaultpow completions fish > ~/.config/fish/completions/vaultpow.fish
```

The tarball also contains the `shell/` directory and `README.md`/`LICENSE` for inspection — but the snippets are embedded in the binary, so `vaultpow shell-init` is the canonical source.

### From source

```bash
git clone https://github.com/koraykoska/vaultpow
cd vaultpow
cargo install --path .
```

## Shell hook (the kubectx-style magic)

Add this to your shell init:

```bash
# zsh — append to ~/.zshrc
eval "$(vaultpow shell-init zsh)"

# bash — append to ~/.bashrc
eval "$(vaultpow shell-init bash)"
```

Reload your shell. Now every `vault` AND `bao` call automatically picks up `VAULT_ADDR`/`BAO_ADDR`, `VAULT_NAMESPACE`/`BAO_NAMESPACE`, and `VAULT_TOKEN`/`BAO_TOKEN` for the current cluster, renews the token if it's near expiry, and re-authenticates if expired. Tokens are interchangeable between the two CLIs — auth via `vault login` and then use `bao` (or the reverse).

> **Use `eval`, not `source <(…)`.** Bash 3.2 (the macOS default) silently drops function definitions loaded via process substitution, so `source <(vaultpow shell-init bash)` defines no `vault`/`bao` functions and the wrapper does nothing. `eval "$(vaultpow shell-init bash)"` works on every shell.

To bypass the hook for one invocation: `VAULTPOW_BYPASS=1 vault status`.

## Quick start

```bash
# Add a cluster (interactive)
vaultpow add-cluster

# Or non-interactive
vaultpow add-cluster --name prod \
  --server https://vault-prod.example.com:8200 \
  --namespace admin/team-a

# Add a named auth profile (menu: token / userpass / oidc / other)
vaultpow auth add

# Or non-interactive — useful in scripts / one-shot OIDC roles
vaultpow auth add --name admin --method oidc --role admin --non-interactive

# Show what's loaded
vaultpow status
# current cluster: prod
#   server:    https://vault-prod.example.com:8200
#   namespace: admin/team-a
#   auths:
#     * admin  method=oidc [role=admin]
#       ro     method=userpass [username=alice]
#   current auth: admin
#   token:     stored (expires 2026-05-09T18:34:56Z renewable)
#   max_ttl:   2026-05-10T08:00:00Z

# Now just use vault (or bao) — the hook handles everything
vault kv get secret/foo
bao   kv list secret/        # the OpenBao CLI works the same way

# Need different perms? Switch auth profile without re-running OIDC:
vaultpow auth use ro
vault kv get secret/public

# Switch clusters / namespaces
vaultpow ctx staging                 # switch cluster
vaultpow ns admin/other-team         # switch namespace (no `set` keyword needed)
vaultpow ctx                         # list clusters (* = current)
```

## Commands

```
Cluster management
  vaultpow                            show status
  vaultpow status                     show current cluster + namespace + token info
  vaultpow ctx                        list clusters (* = current)
  vaultpow ctx <name>                 switch current cluster
  vaultpow add-cluster                interactively add a cluster
  vaultpow add-cluster --name N --server URL [--namespace NS]
                                      non-interactive add
  vaultpow remove-cluster [name]      remove a cluster (interactive if no name)

Namespaces
  vaultpow ns                         show selected namespace of current cluster
  vaultpow ns list                    list namespaces from server (Enterprise)
  vaultpow ns <name>                  select namespace for current cluster
  vaultpow ns set <name>              same as above (explicit form)
  vaultpow ns add <name>              create namespace on server (Enterprise)
  vaultpow ns rm <name>               delete namespace on server (Enterprise)

Auth & token lifecycle
  vaultpow auth                       refresh the current cluster's selected auth
  vaultpow auth --method oidc         refresh, overriding the method
  vaultpow auth list                  list named auths (* = current)
  vaultpow auth use <name>            switch current auth (no re-auth)
  vaultpow auth add                   add a new named auth (interactive)
  vaultpow auth add --name admin --method oidc --role admin --non-interactive
                                      add a new named auth (scripted)
  vaultpow auth rm <name>             remove a named auth (never auto-picks
                                      a replacement — you choose explicitly)
  vaultpow renew                      manually renew the current auth's token
  vaultpow check-token                ok|renewable|expiring|expired|absent|unreachable

Shell integration
  vaultpow env                        print eval-able export statements
                                      (sets both VAULT_* and BAO_*)
  vaultpow shell-init zsh|bash        print the shell wrapper for `vault` and `bao`
  vaultpow completions <shell>        print tab-completion script for vaultpow
                                      (bash, zsh, fish, elvish, powershell)

Anything else is forwarded to `vault` (or `bao`, see VAULTPOW_VAULT_BIN below)
with the current cluster's env. For example: `vaultpow kv get secret/foo` works
without the shell hook installed.
```

Run `vaultpow <command> --help` for full help on any command.

## Named auths (multiple identities per cluster)

A single Vault/OpenBao cluster often hosts several identities you want to keep handy — for example an `admin` OIDC role for `admin/team-a` and a `readonly` userpass account for spot-checking secrets. vaultpow gives each cluster an array of *named* auth profiles; the cluster's `current_auth` pointer picks which one `vault`/`bao` calls actually use.

```bash
# Create two auths on the current cluster
vaultpow auth add --name admin --method oidc --role admin --non-interactive
vaultpow auth add --name ro    --method userpass --username alice --non-interactive

# Switch between them — no re-auth, just changes the pointer
vaultpow auth use ro
vault kv get secret/public          # uses the ro token
vaultpow auth use admin
vault kv put secret/team-a/key=val  # uses the admin token

# See what's configured
vaultpow auth list
# auths for 'prod':
#   * admin  method=oidc [role=admin]  (token, expires 2026-05-09T18:34:56Z)
#     ro     method=userpass [username=alice]  (token cached)

# Remove one. vaultpow NEVER auto-picks a replacement when you remove the
# current one — even if exactly one auth remains. You always choose:
vaultpow auth rm admin
# That was the current auth. Pick a replacement explicitly:
#   vaultpow auth use <name>
# Available: ro
```

Each auth caches its own token, expiry, and renewability separately, so switching is instant. Method-specific parameters (OIDC role, userpass username, …) are stored alongside the auth so refreshes (`vaultpow auth`) don't re-prompt.

### Failure hint

If a wrapped `vault`/`bao` command fails *with a valid token* and the cluster has more than one auth configured, the shell hook prints a short tip pointing at the alternatives:

```
$ vault kv get secret/admin-only
Error: 403 Forbidden — permission denied
vaultpow: tip: other auths on 'prod': ro, oncall. Try `vaultpow auth use <name>` if this is a permissions issue.
```

The tip is silent in single-auth setups, so it doesn't clutter the common case.

### Migrating from vaultpow ≤ 0.1.x

vaultpow ≤ 0.1.x kept one unnamed auth per cluster under an `auth:` key. The new schema is fully backward-compatible: on first read, the legacy block is converted in-memory to a named `default` auth (`current_auth: default`). The next time anything writes the config (e.g. `vaultpow ctx <name>`), it's persisted in the new shape. No manual editing required.

## How token renewal works

Each named auth caches its own lifecycle metadata (`expire_time`, `creation_time`, `creation_ttl`, `renewable`) in `~/.vaultctx`. Before forwarding to `vault`/`bao`, the shell hook calls `vaultpow ensure-fresh`, which classifies the cluster's currently selected auth into one of six states:

| State | Trigger | Action |
|-------|---------|--------|
| `ok` | TTL > grace window | run command |
| `renewable` | Within grace, `renewable: true`, before `max_ttl` | `vault token renew` |
| `expiring` | Within grace, NOT renewable or past `max_ttl` | full re-auth |
| `expired` | Server rejected the token | full re-auth |
| `absent` | No token stored | full re-auth |
| `unreachable` | Can't reach the server | run anyway, don't loop into auth |

Renewal is silent on the happy path. You'll only see vaultpow messages when something actually requires your input (full re-auth, OIDC browser flow, etc.).

## Configuration file

`~/.vaultctx` is a YAML file with mode `0600`:

```yaml
clusters:
  - name: prod
    server: https://vault-prod.example.com:8200
    namespace: admin/team-a
    auths:
      - name: admin
        method: oidc
        params:
          role: admin
        token: hvs.xxxxxxxxxxxxxxxx
        expire_time: "2026-05-09T18:34:56Z"
        creation_time: 1715269200
        creation_ttl: 28800
        renewable: true
      - name: ro
        method: userpass
        params:
          username: alice
        token: hvs.yyyyyyyyyyyyyyyy
    current_auth: admin
  - name: staging
    server: https://vault-staging.example.com:8200
current_cluster: prod
```

Configs from vaultpow ≤ 0.1.x (singular `auth:` per cluster) are read transparently and rewritten in this shape on the next save — see [Migrating from vaultpow ≤ 0.1.x](#migrating-from-vaultpow--01x).

You can edit it by hand, but the `vaultpow` CLI is the supported interface.

## Environment variables

| Variable | Purpose |
|----------|---------|
| `VAULTPOW_BYPASS=1` | Skip the shell hook for one invocation |
| `VAULTPOW_EXPIRY_GRACE` | Seconds before expiry to renew/re-auth (default `60`) |
| `VAULTPOW_VAULT_BIN` | Pin which CLI vaultpow shells out to for auth/ns ops. Set to `vault` or `bao`; default is `vault` if installed, else `bao` |
| `VAULTCTX_FILE` | Override config path (default `~/.vaultctx`) |
| `VAULT_SKIP_VERIFY=1` | Accept self-signed certs on the Vault/OpenBao server (use only when needed) |

## Security notes

- `~/.vaultctx` stores tokens in plaintext, mode `0600`. This is the same trust model as Vault's own `~/.vault-token`.
- For higher security, run vaultpow inside a container or VM whose disk is encrypted at rest, and prefer short-TTL tokens with renewal over long-lived tokens.
- Setting `VAULT_SKIP_VERIFY=1` disables TLS verification for vaultpow's own probes (token lookup/renew). Don't use this in production unless you have to.

## Comparison to alternatives

- **Vault's `~/.vault-token`**: stores one token. vaultpow stores many, scoped by cluster.
- **direnv `.envrc`**: project-bound; works great alongside vaultpow if you prefer per-repo overrides.
- **Manually setting `VAULT_ADDR`/`VAULT_TOKEN`**: tedious; doesn't handle renewal or expiry.
- **Hashicorp's token helpers**: keyring-backed but still single-cluster.

## License

MIT — see [LICENSE](LICENSE).

## Contributing

PRs welcome. To set up a dev environment:

```bash
git clone https://github.com/koraykoska/vaultpow
cd vaultpow
cargo build              # first build will generate Cargo.lock
cargo test
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
```

Commit `Cargo.lock` along with any dependency changes — it's a binary, so reproducible builds matter.
