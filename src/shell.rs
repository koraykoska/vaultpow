// Shell hook generators. The actual snippets live in shell/*.sh as static
// resources and are embedded into the binary at compile time, so there's a
// single source of truth versioned with the binary.

pub const ZSH_INIT: &str = include_str!("../shell/zsh-init.sh");
pub const BASH_INIT: &str = include_str!("../shell/bash-init.sh");

pub fn for_shell(shell: &str) -> Option<&'static str> {
    match shell {
        "zsh" => Some(ZSH_INIT),
        "bash" => Some(BASH_INIT),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn for_shell_returns_zsh_snippet() {
        let s = for_shell("zsh").expect("zsh known");
        assert!(
            s.contains("emulate -L zsh"),
            "expected zsh-specific snippet"
        );
        assert!(s.contains("vault()"));
    }

    #[test]
    fn for_shell_returns_bash_snippet() {
        let s = for_shell("bash").expect("bash known");
        assert!(s.contains("vault()"));
        // Should not contain the zsh-specific guard.
        assert!(!s.contains("emulate -L zsh"));
    }

    #[test]
    fn for_shell_unknown_is_none() {
        assert!(for_shell("fish").is_none());
        assert!(for_shell("").is_none());
    }

    #[test]
    fn shell_snippets_call_ensure_fresh_and_check_token() {
        // The snippets are the contract with the binary's subcommands. If
        // someone renames `ensure-fresh` or `check-token` they need to
        // update the snippets too — this test makes that loud.
        for snippet in [ZSH_INIT, BASH_INIT] {
            assert!(snippet.contains("vaultpow ensure-fresh"));
            assert!(snippet.contains("vaultpow check-token"));
            assert!(snippet.contains("vaultpow env"));
            assert!(snippet.contains("vaultpow _internal-set-token"));
        }
    }

    #[test]
    fn shell_snippets_avoid_recursive_command_v_lookup() {
        // Regression guard: `command -v vault` from inside the `vault()`
        // function returns the function name itself, causing infinite
        // recursion when the wrapper later tries to invoke "$_vp_real".
        // The fix is to use `whence -p` (zsh) / `type -P` (bash), which
        // ignore functions and aliases.
        for snippet in [ZSH_INIT, BASH_INIT] {
            assert!(
                !snippet.contains("command -v vault"),
                "snippet must not use `command -v vault`"
            );
            assert!(
                !snippet.contains("command -v bao"),
                "snippet must not use `command -v bao`"
            );
        }
        assert!(ZSH_INIT.contains("whence -p"));
        assert!(BASH_INIT.contains("type -P"));
    }

    #[test]
    fn shell_snippets_wrap_both_vault_and_bao() {
        // Both CLIs need a wrapper. The helper they share is internal but
        // checking for both function definitions is the right contract.
        for snippet in [ZSH_INIT, BASH_INIT] {
            assert!(snippet.contains("vault()"), "missing vault() wrapper");
            assert!(snippet.contains("bao()"), "missing bao() wrapper");
            // Helper that does the heavy lifting.
            assert!(
                snippet.contains("_vp_wrap"),
                "snippet should share logic via `_vp_wrap`"
            );
        }
    }
}
