# >>> vaultpow shell-init (zsh) >>>
# Wraps both `vault` and `bao` (the OpenBao fork) so they pick up the current
# vaultpow cluster automatically and transparently renew or re-auth expired
# tokens. Tokens are interchangeable between the two CLIs, so the same
# vaultpow config drives both.
#
#   vault login ... | bao login ... → run real CLI, capture token into ~/.vaultctx
#   vault <anything> | bao <anything> → ensure-fresh (renew if possible, re-auth if not), then run
#
# Set VAULTPOW_BYPASS=1 to skip the wrapper for one shell.
#
# Implementation notes:
#   - We use `whence -p <cli>` to find the *binary*, never `command -v` —
#     the latter returns this function's own name when called from inside
#     it, which would cause infinite recursion.
#   - Source this with `eval "$(vaultpow shell-init zsh)"`.

# Internal helper. Callers are `vault()` and `bao()` below; first arg is the
# CLI name they want to wrap.
_vp_wrap() {
  emulate -L zsh
  local _vp_cli="$1"; shift
  local _vp_real
  _vp_real="$(whence -p "$_vp_cli" 2>/dev/null)"
  if [[ -z "$_vp_real" ]]; then
    print -u2 "$_vp_cli: binary not found in PATH"
    return 127
  fi

  if [[ "$VAULTPOW_BYPASS" == "1" ]]; then
    "$_vp_real" "$@"; return $?
  fi

  # If vaultpow isn't installed (yet), fall back gracefully.
  whence -p vaultpow >/dev/null 2>&1 || { "$_vp_real" "$@"; return $?; }

  local _vp_env
  _vp_env="$(vaultpow env 2>/dev/null)"
  if [[ -z "$_vp_env" ]]; then
    "$_vp_real" "$@"; return $?
  fi

  # Run inside a subshell so env mutations don't leak into the user's shell.
  (
    eval "$_vp_env"

    # Special-case `<cli> login`: capture the token into vaultpow's config.
    if [[ "$1" == "login" ]]; then
      shift
      local _vp_token _vp_cluster
      if _vp_token="$("$_vp_real" login -token-only "$@")"; then
        _vp_cluster="$(vaultpow ctx | awk '/^\* /{print $2}')"
        if [[ -n "$_vp_cluster" ]]; then
          vaultpow _internal-set-token "$_vp_cluster" "$_vp_token" >/dev/null \
            && print "Token stored in vaultpow for cluster '$_vp_cluster'."
        fi
        return 0
      fi
      return $?
    fi

    # Pre-flight: renew/re-auth if needed.
    if ! vaultpow ensure-fresh; then
      # Server unreachable, or user bailed on auth. Run anyway; commands
      # like `vault status` may still work.
      "$_vp_real" "$@"
      return $?
    fi
    eval "$(vaultpow env)"

    "$_vp_real" "$@"
    local _rc=$?
    if (( _rc != 0 )); then
      # Token may have been revoked between pre-flight and now. Re-probe.
      local _vp_state
      _vp_state="$(vaultpow check-token 2>/dev/null)"
      case "$_vp_state" in
        expired|absent)
          print -u2 "$_vp_cli: command failed and token is invalid — re-authenticating"
          vaultpow auth || return $_rc
          eval "$(vaultpow env)"
          "$_vp_real" "$@"
          _rc=$?
          ;;
        renewable)
          print -u2 "$_vp_cli: command failed; token is renewable — renewing & retrying"
          if vaultpow renew >/dev/null 2>&1; then
            eval "$(vaultpow env)"
            "$_vp_real" "$@"
            _rc=$?
          fi
          ;;
        ok)
          # The token is valid but the command still failed. Most likely
          # the user's selected auth profile lacks the permission the
          # command needs (e.g. a read-only role trying a write op). Hint
          # at other configured profiles. The hint command writes to
          # stderr and is silent when the user has at most one auth, so
          # this is free in the common case.
          vaultpow auth hint
          ;;
      esac
    fi
    return $_rc
  )
}

vault() { _vp_wrap vault "$@"; }
bao()   { _vp_wrap bao   "$@"; }
# <<< vaultpow shell-init (zsh) <<<
