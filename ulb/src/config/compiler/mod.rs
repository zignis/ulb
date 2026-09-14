use std::collections::HashMap;

use ulb_common::{
    http::HTTP_HDR_KEY_MAX_LEN,
    ir::{
        Cluster,
        HeaderRule,
        RouteValue,
        VHostKey,
        VHostValue,
    },
};

use crate::config::{
    canonical::{
        ClusterConnectionPoolMap,
        UlbConfig,
    },
    compiler::{
        cluster::compile_clusters,
        vhost::{
            CompiledVHosts,
            compile_vhosts,
        },
    },
};

mod cluster;
mod vhost;

#[derive(Debug)]
pub struct CompiledIR {
    pub vhost_map: HashMap<VHostKey, VHostValue>,
    pub route_table: Vec<RouteValue>,
    pub cluster_table: Vec<Cluster>,
    pub header_rule_table: Vec<HeaderRule>,
    pub header_key_map: HashMap<[u8; HTTP_HDR_KEY_MAX_LEN], u64>,
}

pub fn compile(
    cfg: &UlbConfig,
    cluster_conn_pool_map: ClusterConnectionPoolMap,
) -> anyhow::Result<CompiledIR> {
    let (cluster_table, cluster_idx_map) = compile_clusters(cfg, cluster_conn_pool_map)?;
    let CompiledVHosts {
        vhost_map,
        route_table,
        header_rule_table,
        header_key_map,
    } = compile_vhosts(cfg, cluster_idx_map)?;

    Ok(CompiledIR {
        vhost_map,
        route_table,
        cluster_table,
        header_rule_table,
        header_key_map,
    })
}
