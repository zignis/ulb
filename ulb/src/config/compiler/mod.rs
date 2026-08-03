use std::collections::HashMap;

use ulb_common::{
    SocketCookie,
    ir::{
        BackendCluster,
        RouteValue,
        VHostKey,
        VHostValue,
    },
};

use crate::config::{
    canonical::UlbConfig,
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
    pub cluster_table: Vec<BackendCluster>,
}

pub fn compile(
    cfg: &UlbConfig,
    cookie_map: HashMap<String, Vec<SocketCookie>>,
) -> anyhow::Result<CompiledIR> {
    let (cluster_table, cluster_idx_map) = compile_clusters(cfg, cookie_map)?;
    let (vhost_map, route_table) = compile_vhosts(cfg, cluster_idx_map)?;

    Ok(CompiledIR {
        vhost_map,
        route_table,
        cluster_table,
    })
}
