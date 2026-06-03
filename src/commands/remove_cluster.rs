use anyhow::{anyhow, Result};
use dialoguer::Select;

use crate::config;

pub fn run(name: Option<String>) -> Result<()> {
    let mut cfg = config::load()?;

    if cfg.clusters.is_empty() {
        return Err(anyhow!("no clusters configured"));
    }

    let target = match name {
        Some(n) => n,
        None => {
            let names: Vec<String> = cfg.clusters.iter().map(|c| c.name.clone()).collect();
            let idx = Select::new()
                .with_prompt("Remove which cluster?")
                .items(&names)
                .default(0)
                .interact()
                .map_err(|e| anyhow!("prompt failed: {e}"))?;
            names[idx].clone()
        }
    };

    let before = cfg.clusters.len();
    cfg.clusters.retain(|c| c.name != target);
    if cfg.clusters.len() == before {
        return Err(anyhow!("cluster '{target}' not found"));
    }

    if cfg.current_cluster == target {
        cfg.current_cluster.clear();
    }

    config::save(&cfg)?;
    println!("removed '{target}'");
    Ok(())
}
