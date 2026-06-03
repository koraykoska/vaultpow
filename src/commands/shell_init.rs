use anyhow::{anyhow, Result};

use crate::shell;

pub fn run(target: String) -> Result<()> {
    match shell::for_shell(&target) {
        Some(snippet) => {
            print!("{snippet}");
            Ok(())
        }
        None => Err(anyhow!(
            "shell-init: unsupported shell '{target}' (supported: zsh, bash)"
        )),
    }
}
