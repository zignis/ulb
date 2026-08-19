use std::collections::HashMap;

use ulb_common::ir::{
    Cluster,
    RouteValue,
    VHostKey,
    VHostValue,
};

use crate::config::{
    canonical::{
        ClusterConnectionPoolMap,
        UlbConfig,
    },
    compiler::{
        cluster::compile_clusters,
        vhost::compile_vhosts,
    },
};

mod cluster;
mod vhost;

#[derive(Debug)]
pub struct CompiledIR {
    pub vhost_map: HashMap<VHostKey, VHostValue>,
    pub route_table: Vec<RouteValue>,
    pub cluster_table: Vec<Cluster>,
}

pub fn compile(
    cfg: &UlbConfig,
    cluster_conn_pool_map: ClusterConnectionPoolMap,
) -> anyhow::Result<CompiledIR> {
    let (cluster_table, cluster_idx_map) = compile_clusters(cfg, cluster_conn_pool_map)?;
    let (vhost_map, route_table) = compile_vhosts(cfg, cluster_idx_map)?;

    Ok(CompiledIR {
        vhost_map,
        route_table,
        cluster_table,
    })
}
