use std::collections::HashMap;

#[cfg(feature = "schema")]
use schemars::JsonSchema;
use serde::{
    Deserialize,
    Serialize,
};

mod backend;
mod cluster;
mod listener;
mod route;
mod vhost;

pub use backend::*;
pub use cluster::*;
pub use listener::*;
pub use route::*;
pub use vhost::*;

pub type BackendConnectionPoolIdx = u32;

// <cluster name, vec<(idx into BACKEND_CONNECTION_POOL_TABLE, weight)> for each
// backend under this cluster>
pub type ClusterConnectionPoolMap = HashMap<String, Vec<(BackendConnectionPoolIdx, u32)>>;

// <cluster name, idx in CLUSTER_TABLE>
pub type ClusterIdxMap = HashMap<String, u32>;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct UlbConfig {
    pub listeners: Vec<ListenerConfig>,
    pub clusters: Vec<ClusterConfig>,
}
