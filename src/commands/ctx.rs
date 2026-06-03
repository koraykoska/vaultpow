use anyhow::Result;

use crate::commands::cluster_or_error;
use crate::config;

pub fn run(name: Option<String>) -> Result<()> {
    let mut cfg = config::load()?;

    match name {
        None => {
            // List
            if cfg.clusters.is_empty() {
                println!("no clusters configured");
                println!("\nRun `vaultpow add-cluster` to add one.");
                return Ok(());
            }
            for cluster in &cfg.clusters {
                let marker = if cluster.name == cfg.current_cluster {
                    "*"
                } else {
                    " "
                };
                println!("{marker} {}", cluster.name);
            }
        }
        Some(target) => {
            cluster_or_error(&cfg, &target)?;
            cfg.current_cluster = target.clone();
            config::save(&cfg)?;
            println!("switched to '{target}'");
        }
    }

    Ok(())
}
