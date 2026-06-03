# >>> vaultpow shell-init (bash) >>>
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
#   - We use `type -P <cli>` to find the *binary*, never `command -v` —
#     the latter returns this function's own name when called from inside
#     it, which would cause infinite recursion.
#   - Source this with `eval "$(vaultpow shell-init bash)"`, NOT
#     `source <(vaultpow shell-init bash)` — bash 3.2 (the macOS default)
#     drops function definitions loaded via process substitution.

# Internal helper. Callers are `vault()` and `bao()` below; first arg is the
# CLI name they want to wrap.
_vp_wrap() {
  local _vp_cli="$1"; shift
  local _vp_real
  _vp_real="$(type -P "$_vp_cli" 2>/dev/null)"
  if [[ -z "$_vp_real" ]]; then
    echo "$_vp_cli: binary not found in PATH" >&2
    return 127
  fi

  if [[ "$VAULTPOW_BYPASS" == "1" ]]; then
    "$_vp_real" "$@"; return $?
  fi

  type -P vaultpow >/dev/null 2>&1 || { "$_vp_real" "$@"; return $?; }

  local _vp_env
  _vp_env="$(vaultpow env 2>/dev/null)"
  if [[ -z "$_vp_env" ]]; then
    "$_vp_real" "$@"; return $?
  fi

  (
    eval "$_vp_env"

    if [[ "$1" == "login" ]]; then
      shift
      local _vp_token _vp_cluster
      if _vp_token="$("$_vp_real" login -token-only "$@")"; then
        _vp_cluster="$(vaultpow ctx | awk '/^\* /{print $2}')"
        if [[ -n "$_vp_cluster" ]]; then
          vaultpow _internal-set-token "$_vp_cluster" "$_vp_token" >/dev/null \
            && echo "Token stored in vaultpow for cluster '$_vp_cluster'."
        fi
        return 0
      fi
      return $?
    fi

    if ! vaultpow ensure-fresh; then
      "$_vp_real" "$@"
      return $?
    fi
    eval "$(vaultpow env)"

    "$_vp_real" "$@"
    local _rc=$?
    if (( _rc != 0 )); then
      local _vp_state
      _vp_state="$(vaultpow check-token 2>/dev/null)"
      case "$_vp_state" in
        expired|absent)
          echo "$_vp_cli: command failed and token is invalid — re-authenticating" >&2
          vaultpow auth || return $_rc
          eval "$(vaultpow env)"
          "$_vp_real" "$@"
          _rc=$?
          ;;
        renewable)
          echo "$_vp_cli: command failed; token is renewable — renewing & retrying" >&2
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
# <<< vaultpow shell-init (bash) <<<
