use std::collections::{
    HashMap,
    HashSet,
};

use anyhow::{
    anyhow,
    bail,
};
use ulb_common::{
    SocketCookie,
    ir::{
        BackendCluster,
        BackendEndpoint,
        LoadBalancingPolicy,
        MAX_BACKENDS_PER_CLUSTER,
        MAX_CLUSTERS,
    },
};

use crate::config::canonical::UlbConfig;

pub fn compile_clusters(
    cfg: &UlbConfig,
    cookie_map: HashMap<String, Vec<SocketCookie>>,
) -> anyhow::Result<(Vec<BackendCluster>, HashMap<String, u32>)> {
    let mut clusters = Vec::new();
    let mut cluster_idx_map = HashMap::new();

    if cfg.clusters.len() > MAX_CLUSTERS as usize {
        bail!(
            "exceeded maximum clusters ({}/{MAX_CLUSTERS})",
            cfg.clusters.len()
        );
    }

    for (idx, cluster_cfg) in cfg.clusters.iter().enumerate() {
        if cluster_idx_map
            .insert(cluster_cfg.name.clone(), idx as u32)
            .is_some()
        {
            bail!("unexpected duplicate cluster name: {}", cluster_cfg.name);
        }

        let cookies = cookie_map.get(&cluster_cfg.name).ok_or(anyhow!(
            "missing cluster `{}` in `cookie_map`",
            cluster_cfg.name
        ))?;

        if cookies.len() > MAX_BACKENDS_PER_CLUSTER {
            bail!(
                "exceeded maximum backends per cluster ({}/{MAX_BACKENDS_PER_CLUSTER})",
                cookies.len()
            );
        }

        let endpoints = cookies
            .iter()
            .map(|&cookie| BackendEndpoint {
                cookie,
                flags: 1, // TODO: future usage
            })
            .collect::<Vec<_>>();

        clusters.push(BackendCluster {
            policy: LoadBalancingPolicy::RoundRobin,
            endpoints: endpoints.try_into().map_err(|_| anyhow!("infallible"))?,
            rr_counter: 0,
        });
    }

    Ok((clusters, cluster_idx_map))
}
