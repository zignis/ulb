#[cfg(feature = "schema")]
use schemars::JsonSchema;
#[cfg(feature = "user")]
use serde::{
    Deserialize,
    Serialize,
};

use crate::{
    containers::BoundedVec,
    ir::MAX_BACKENDS_PER_CLUSTER,
};

#[repr(C)]
#[derive(Debug, Copy, Clone, Default)]
#[cfg_attr(feature = "user", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "user", serde(rename_all = "kebab-case"))]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub enum LoadBalancingPolicy {
    #[default]
    RoundRobin,
    LeastLoaded,
    IpHash,
    Random,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct Cluster {
    // 8B align
    pub backends: BoundedVec<Backend, MAX_BACKENDS_PER_CLUSTER>,
    // 8B align
    pub policy: LoadBalancingPolicy,
    pub rr_counter: u32, // round-robin counter
    // 8B align
    pub uniform_weight: u32, // 1 if weight=1 for all backends
    pub total_weight: u32,   // total weight for WRR
}

#[repr(C)]
#[derive(Debug, Copy, Clone, Default)]
pub struct Backend {
    // 8B align
    pub pool_idx: u32, // index into BACKEND_CONNECTION_POOL_TABLE
    pub weight: u32,   // weight for round-robin
}

#[repr(C)]
#[derive(Debug, Copy, Clone, Default)]
pub struct BackendConnectionPoolStats {
    // 8B align
    pub active_connections: u64, // used for least-loaded policy
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Cluster {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for LoadBalancingPolicy {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Backend {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for BackendConnectionPoolStats {}
