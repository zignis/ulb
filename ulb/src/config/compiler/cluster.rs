use std::collections::HashMap;

use anyhow::anyhow;
use ulb_common::ir::{
    Backend,
    Cluster,
};

use crate::config::canonical::{
    ClusterConnectionPoolMap,
    ClusterIdxMap,
    UlbConfig,
};

pub fn compile_clusters(
    cfg: &UlbConfig,
    cluster_conn_pool_map: ClusterConnectionPoolMap,
) -> anyhow::Result<(Vec<Cluster>, ClusterIdxMap)> {
    let mut clusters = Vec::new();
    let mut cluster_idx_map = HashMap::new();

    for (idx, cluster_cfg) in cfg.clusters.iter().enumerate() {
        cluster_idx_map.insert(cluster_cfg.name.clone(), idx as u32);

        let backends = cluster_conn_pool_map
            .get(&cluster_cfg.name)
            .ok_or(anyhow!(
                "missing connection pool for cluster `{}`",
                cluster_cfg.name
            ))?
            .iter()
            .map(|&pool_idx| Backend {
                pool_idx,
                flags: 0, // future use
            })
            .collect::<Vec<_>>();

        clusters.push(Cluster {
            policy: cluster_cfg.policy.unwrap_or_default(),
            backends: backends.try_into().map_err(|_| anyhow!("infallible"))?,
            rr_counter: 0,
        });
    }

    Ok((clusters, cluster_idx_map))
}
