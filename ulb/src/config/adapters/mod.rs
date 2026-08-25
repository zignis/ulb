pub mod native;

use std::{
    collections::HashMap,
    fs,
    path::Path,
};

use anyhow::{
    Context,
    bail,
};
use ulb_common::ir::{
    MAX_BACKEND_CONNECTION_POOL_SIZE,
    MAX_BACKENDS_PER_CLUSTER,
    MAX_CLUSTERS,
    MAX_HEADER_RULES_PER_ROUTE,
    MAX_LISTENERS,
    MAX_VHOSTS,
};

use crate::config::canonical::UlbConfig;

pub trait ConfigAdapter {
    fn load_file<P>(path: P) -> anyhow::Result<String>
    where
        P: AsRef<Path>,
    {
        fs::read_to_string(&path)
            .with_context(|| format!("failed to read config file: `{}`", path.as_ref().display()))
    }

    fn parse(content: String) -> anyhow::Result<UlbConfig>;
}

pub fn load_config<T, P>(path: P) -> anyhow::Result<UlbConfig>
where
    T: ConfigAdapter,
    P: AsRef<Path>,
{
    let cfg_content = T::load_file(path)?;
    let parsed_cfg = T::parse(cfg_content)?;
    validate_config(parsed_cfg)
}

fn validate_config(cfg: UlbConfig) -> anyhow::Result<UlbConfig> {
    // listeners

    if cfg.listeners.len() >= MAX_LISTENERS {
        bail!(
            "exceeded maximum listeners ({}/{MAX_LISTENERS})",
            cfg.listeners.len()
        );
    }

    for listener in &cfg.listeners {
        if listener.hosts.len() >= MAX_VHOSTS as usize {
            bail!(
                "exceeded maximum vhosts ({}/{MAX_VHOSTS})",
                listener.hosts.len()
            );
        }

        for host in &listener.hosts {
            for route in &host.routes {
                if route.headers.len() > MAX_HEADER_RULES_PER_ROUTE {
                    bail!(
                        "exceeded maximum headers per route ({}/{MAX_HEADER_RULES_PER_ROUTE})",
                        route.headers.len()
                    );
                }
            }
        }
    }

    // clusters

    let mut cluster_name_map = HashMap::new();

    if cfg.clusters.len() > MAX_CLUSTERS as usize {
        bail!(
            "exceeded maximum clusters ({}/{MAX_CLUSTERS})",
            cfg.clusters.len()
        );
    }

    for cluster in &cfg.clusters {
        if cluster_name_map.insert(cluster.name.clone(), 0).is_some() {
            bail!("unexpected duplicate cluster name: `{}`", cluster.name);
        }

        if cluster.backends.len() > MAX_BACKENDS_PER_CLUSTER {
            bail!(
                "exceeded maximum backends per cluster ({}/{MAX_BACKENDS_PER_CLUSTER})",
                cluster.backends.len()
            );
        }

        for backend in &cluster.backends {
            if backend.pool_size > MAX_BACKEND_CONNECTION_POOL_SIZE {
                bail!(
                    "exceeded maximum pool size for backend `{}` ({}/{MAX_BACKEND_CONNECTION_POOL_SIZE})",
                    backend.addr,
                    backend.pool_size
                );
            }
        }
    }

    Ok(cfg)
}
