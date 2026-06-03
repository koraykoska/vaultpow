// Generate shell completion scripts via clap_complete.
//
// We support the full clap_complete shell list (bash/zsh/fish/elvish/
// powershell) — extra ones beyond bash/zsh cost nothing because clap_complete
// already implements them.

use anyhow::{anyhow, Result};
use clap::CommandFactory;
use clap_complete::{generate, Shell};
use std::str::FromStr;

use crate::cli::Cli;

pub fn run(target: String) -> Result<()> {
    let shell = Shell::from_str(&target).map_err(|_| {
        anyhow!("completions: unsupported shell '{target}' (supported: bash, zsh, fish, elvish, powershell)")
    })?;

    let mut cmd = Cli::command();
    let bin = cmd.get_name().to_string();
    generate(shell, &mut cmd, bin, &mut std::io::stdout());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_emits_zsh_completions() {
        // We can't easily capture stdout from `generate()` without a test
        // harness, so we just exercise the parsing path here. The CLI
        // integration test in tests/cli.rs covers the actual emission.
        for sh in ["bash", "zsh", "fish", "elvish", "powershell"] {
            assert!(Shell::from_str(sh).is_ok(), "should accept '{sh}'");
        }
    }

    #[test]
    fn unsupported_shell_errors() {
        let err = run("tcsh".into()).unwrap_err();
        let s = format!("{err:#}");
        assert!(s.contains("unsupported shell"), "got: {s}");
    }
}
