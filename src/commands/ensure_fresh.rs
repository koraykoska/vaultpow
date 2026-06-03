// `ensure-fresh` is the single hook the shell wrapper calls before forwarding
// to `vault`. It evaluates token state and renews / re-auths as needed.

use std::process::ExitCode;

use anyhow::Result;

use crate::commands::{info, resolve_current, warn};
use crate::config;
use crate::vault::{self, TokenState};

pub fn run() -> Result<ExitCode> {
    let mut cfg = config::load()?;
    let cluster_name = resolve_current(&mut cfg)?;
    let cluster = cfg.cluster(&cluster_name).unwrap().clone();

    let state = vault::classify(&cluster);

    match state {
        TokenState::Ok => Ok(ExitCode::SUCCESS),

        TokenState::Renewable => {
            info(format!(
                "token for '{cluster_name}' is near expiry — attempting renewal"
            ));
            // Inline renewal so we don't double-load config.
            match crate::commands::renew::run() {
                Ok(_) => Ok(ExitCode::SUCCESS),
                Err(e) => {
                    info(format!(
                        "renewal failed ({e}) — falling back to full re-auth"
                    ));
                    crate::commands::auth::refresh(None)?;
                    Ok(ExitCode::SUCCESS)
                }
            }
        }

        TokenState::Expiring => {
            info(format!(
                "token for '{cluster_name}' is near expiry and not renewable (or past max_ttl) — re-authenticating"
            ));
            crate::commands::auth::refresh(None)?;
            Ok(ExitCode::SUCCESS)
        }

        TokenState::Expired => {
            info(format!(
                "token for '{cluster_name}' has expired or been revoked — re-authenticating"
            ));
            crate::commands::auth::refresh(None)?;
            Ok(ExitCode::SUCCESS)
        }

        TokenState::Absent => {
            info(format!("no token for '{cluster_name}' — authenticating"));
            crate::commands::auth::refresh(None)?;
            Ok(ExitCode::SUCCESS)
        }

        TokenState::Unreachable => {
            warn(format!(
                "vault server for '{cluster_name}' is unreachable — not re-authenticating"
            ));
            Ok(ExitCode::from(1))
        }
    }
}
