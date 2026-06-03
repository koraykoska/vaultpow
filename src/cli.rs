use clap::{Parser, Subcommand};

/// vaultpow — kubectx-style context switcher for HashiCorp Vault and OpenBao.
///
/// Manage multiple clusters and their namespaces from one config file
/// (~/.vaultctx). Install the shell hook so the `vault` AND `bao` binaries
/// pick up the current cluster, namespace, and token automatically —
/// including transparent renewal when a token's TTL is near expiry.
///
/// QUICK START
///
///     vaultpow add-cluster
///     vaultpow auth
///     # one-time install of the shell hook (zsh):
///     #   echo 'eval "$(vaultpow shell-init zsh)"' >> ~/.zshrc
///     vault kv get secret/foo      # uses the current cluster transparently
///     bao   kv get secret/foo      # same, with the OpenBao CLI
///
/// CONFIG FILE
///
/// Stored at ~/.vaultctx (mode 0600). Override with $VAULTCTX_FILE.
///
/// SHELL HOOK
///
/// `eval "$(vaultpow shell-init zsh)"` (or bash) wraps both `vault` and `bao`
/// so every call transparently sets VAULT_ADDR/BAO_ADDR, VAULT_NAMESPACE/
/// BAO_NAMESPACE, and VAULT_TOKEN/BAO_TOKEN from the current cluster, renews
/// tokens that are near expiry (when renewable), and re-authenticates when a
/// token has expired or been revoked. Tokens are interchangeable between the
/// two CLIs — auth via `vault login`, then use `bao` (or the reverse).
///
/// TOKEN LIFECYCLE
///
/// vaultpow caches each token's `expire_time`, `creation_time`,
/// `creation_ttl`, and `renewable` flag. Before forwarding to `vault`/`bao`,
/// it classifies the token as: ok / renewable / expiring / expired / absent
/// / unreachable, and renews or re-auths as needed.
///
/// CLI SELECTION (for vaultpow's own shell-outs)
///
/// For interactive auth (OIDC, userpass) and namespace management, vaultpow
/// shells out to whichever of `vault`/`bao` is on PATH (preferring `vault`).
/// Override with $VAULTPOW_VAULT_BIN.
#[derive(Parser, Debug)]
#[command(
    name = "vaultpow",
    version,
    about = "kubectx-style context switcher for HashiCorp Vault",
    long_about = None,
    propagate_version = true,
    arg_required_else_help = false,
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Show the current cluster, namespace, and token info (default action).
    Status,

    /// List clusters or switch to one.
    ///
    /// With no argument, prints all configured clusters and marks the current
    /// one with `*`. With a name, switches the current cluster.
    #[command(visible_alias = "context")]
    Ctx {
        /// Name of the cluster to switch to. Omit to list.
        name: Option<String>,
    },

    /// Add a new cluster to ~/.vaultctx.
    ///
    /// Run with no flags for an interactive prompt. Pass --name and --server
    /// for a non-interactive add (useful in scripts).
    AddCluster {
        /// Cluster name (e.g. "prod", "staging").
        #[arg(long)]
        name: Option<String>,

        /// Vault server URL (e.g. https://vault.example.com:8200).
        #[arg(long)]
        server: Option<String>,

        /// Initial namespace (optional; blank = root).
        #[arg(long)]
        namespace: Option<String>,

        /// Skip interactive prompts even when fields are missing (errors out instead).
        #[arg(long, default_value_t = false)]
        non_interactive: bool,
    },

    /// Remove a cluster from ~/.vaultctx.
    RemoveCluster {
        /// Cluster name. Omit to choose interactively.
        name: Option<String>,
    },

    /// Manage namespaces for the current cluster.
    ///
    /// With no subcommand, prints the currently selected namespace.
    /// Subcommands: list, set, add, rm.
    Ns {
        #[command(subcommand)]
        action: Option<NsCommand>,
    },

    /// Manage and refresh per-cluster auth profiles.
    ///
    /// Every cluster can have multiple *named* auths (e.g. an `admin` OIDC
    /// role and a `readonly` userpass) which share the cluster's address
    /// but each carry their own token + lifecycle metadata. The `current_auth`
    /// pointer picks which one `vault`/`bao` calls actually use.
    ///
    /// With no subcommand, refreshes the token for the cluster's currently
    /// selected auth (or, if there isn't one, prompts to add a new one).
    ///
    /// METHODS
    ///
    /// - `token`:    paste an existing Vault token; vaultpow validates it.
    /// - `userpass`: prompts for username/password, runs `vault login`.
    /// - `oidc`:     opens a browser via `vault login -method=oidc`.
    /// - `other`:    prompts for raw `vault login` args, appends `-token-only`.
    ///
    /// `other`'s args are split on whitespace only — quoted values
    /// containing spaces aren't supported. For complex flag combinations,
    /// run `vault login` directly under `VAULTPOW_BYPASS=1` and let the
    /// shell hook capture the resulting token.
    Auth {
        #[command(subcommand)]
        action: Option<AuthCommand>,

        /// (Only when no subcommand) Auth method to use when refreshing.
        ///
        /// Supported: token, userpass, oidc.
        #[arg(long, value_parser = ["token", "userpass", "oidc"])]
        method: Option<String>,
    },

    /// Renew the current cluster's token (within max_ttl).
    ///
    /// Useful in scripts before a long-running operation. Returns non-zero if
    /// the token isn't renewable or has reached its max_ttl.
    Renew,

    /// Print the current token's state.
    ///
    /// Output is one of: ok, renewable, expiring, expired, absent, unreachable.
    /// Used internally by the shell hook; also useful for scripting.
    CheckToken,

    /// Renew or re-authenticate as needed so the next vault call will work.
    ///
    /// Used internally by the shell hook before forwarding to `vault`. You
    /// generally don't need to call this directly.
    EnsureFresh,

    /// Print eval-able shell exports for the current cluster.
    ///
    /// Example:
    ///     eval "$(vaultpow env)"
    Env,

    /// Print the shell wrapper for `vault`. Eval its output in your shell init.
    ///
    /// Example (zsh):
    ///     eval "$(vaultpow shell-init zsh)"
    ShellInit {
        /// Target shell.
        #[arg(value_parser = ["zsh", "bash"])]
        shell: String,
    },

    /// Print shell completion script for vaultpow itself.
    ///
    /// Examples:
    ///   # zsh — append to a function path or eval directly
    ///   vaultpow completions zsh > "${fpath[1]}/_vaultpow"
    ///
    ///   # bash
    ///   vaultpow completions bash > /etc/bash_completion.d/vaultpow
    ///
    ///   # fish
    ///   vaultpow completions fish > ~/.config/fish/completions/vaultpow.fish
    Completions {
        /// Target shell.
        #[arg(value_parser = ["bash", "zsh", "fish", "elvish", "powershell"])]
        shell: String,
    },

    /// Internal: store a token captured by the shell hook after `vault login`.
    ///
    /// Not for direct use.
    #[command(hide = true, name = "_internal-set-token")]
    InternalSetToken { cluster: String, token: String },

    /// Forward arbitrary arguments to `vault` with the current cluster's env.
    ///
    /// This is the catch-all that runs when none of the above match. With the
    /// shell hook installed it's rarely needed — the wrapped `vault` is faster.
    #[command(external_subcommand)]
    Forward(Vec<String>),
}

#[derive(Subcommand, Debug)]
pub enum NsCommand {
    /// Show the selected namespace for the current cluster.
    #[command(name = "show", hide = true)]
    Show,

    /// List namespaces from the server (Vault Enterprise only).
    #[command(visible_alias = "ls")]
    List,

    /// Select a namespace for the current cluster (local config change).
    ///
    /// You can also omit the `set` keyword: `vaultpow ns admin/team-a`.
    Set {
        /// Namespace path (e.g. "admin/team-a"). Use empty string for root.
        name: String,
    },

    /// Create a namespace on the server (Vault Enterprise only).
    ///
    /// This is a *server-side* operation that calls `vault namespace create`.
    /// To merely select an existing namespace for local use, see `ns set`
    /// (or the `vaultpow ns <name>` shorthand).
    Add { name: String },

    /// Delete a namespace on the server (Vault Enterprise only).
    ///
    /// This is a *server-side* operation that calls `vault namespace delete`.
    /// It does NOT just clear your local namespace selection — to do that,
    /// run `vaultpow ns set ""` (empty string = root).
    #[command(visible_aliases = ["remove", "delete"])]
    Rm { name: String },

    /// Catch-all: `vaultpow ns <something>` is treated as `set <something>`.
    #[command(external_subcommand)]
    SetShorthand(Vec<String>),
}

// `vaultpow ns` (no subcommand) prints the current namespace; that's wired in
// commands/ns.rs by detecting an empty NsCommand. clap's external_subcommand
// already routes unknown subcommands; we add `set <name>` as the explicit verb,
// since `ns <name>` would conflict with `ns add` etc.

#[derive(Subcommand, Debug)]
pub enum AuthCommand {
    /// List named auths for the current cluster (`*` = current).
    #[command(visible_alias = "ls")]
    List,

    /// Switch the current cluster's selected auth.
    ///
    /// Pure config change — does NOT re-authenticate. The new auth keeps
    /// whatever cached token it already has; if it has none, the next
    /// command that needs one will trigger a re-auth.
    Use { name: String },

    /// Create a new named auth and authenticate.
    ///
    /// Examples:
    ///     vaultpow auth add                                      (interactive)
    ///     vaultpow auth add --name admin --method oidc --role admin --non-interactive
    ///     vaultpow auth add --name ro --method userpass --username alice
    Add {
        /// Name for this auth profile (defaults to the method if omitted).
        #[arg(long)]
        name: Option<String>,

        /// Auth method. Supported: token, userpass, oidc, other.
        #[arg(long, value_parser = ["token", "userpass", "oidc", "other"])]
        method: Option<String>,

        /// OIDC role (only meaningful with --method=oidc).
        #[arg(long)]
        role: Option<String>,

        /// userpass username (only meaningful with --method=userpass).
        #[arg(long)]
        username: Option<String>,

        /// Skip interactive prompts; error out if any required field is missing.
        #[arg(long, default_value_t = false)]
        non_interactive: bool,
    },

    /// Remove a named auth from the current cluster.
    ///
    /// If the removed auth was the cluster's `current_auth`, vaultpow does
    /// NOT auto-pick a replacement (even if exactly one auth remains) —
    /// you'll need to `vaultpow auth use <name>` explicitly. This is
    /// deliberate: never silently switch identities.
    #[command(visible_aliases = ["remove", "delete"])]
    Rm { name: String },

    /// (Internal) Print a one-line hint about *other* auths configured on
    /// the current cluster. Used by the shell wrapper after a wrapped
    /// command fails with `ok` token state — the common cause is the user
    /// having the wrong auth profile selected for the operation they tried.
    ///
    /// Exits 0 with no output unless the cluster has 2+ auths.
    #[command(hide = true)]
    Hint,
}
