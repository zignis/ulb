use std::collections::HashMap;

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
        MAX_BACKEND_CLUSTERS,
        MAX_BACKENDS_PER_CLUSTER,
    },
};

use crate::config::canonical::UlbConfig;

pub fn compile_clusters(
    cfg: &UlbConfig,
    cookie_map: HashMap<String, Vec<SocketCookie>>,
) -> anyhow::Result<(Vec<BackendCluster>, HashMap<String, u32>)> {
    let mut clusters = Vec::new();
    let mut cluster_idx_map = HashMap::new();

    if cfg.clusters.len() > MAX_BACKEND_CLUSTERS as usize {
        bail!(
            "exceeded MAX_BACKEND_CLUSTERS ({}/{MAX_BACKEND_CLUSTERS})",
            cfg.clusters.len()
        );
    }

    for (idx, cluster_cfg) in cfg.clusters.iter().enumerate() {
        cluster_idx_map.insert(cluster_cfg.name.clone(), idx as u32);

        let cookies = cookie_map.get(&cluster_cfg.name).ok_or(anyhow!(
            "missing cluster `{}` in `cookie_map`",
            cluster_cfg.name
        ))?;

        if cookies.len() > MAX_BACKENDS_PER_CLUSTER {
            bail!(
                "exceeded MAX_BACKENDS_PER_CLUSTER ({}/{MAX_BACKENDS_PER_CLUSTER})",
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
