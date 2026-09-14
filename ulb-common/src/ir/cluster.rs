use super::{
    MAX_BACKEND_CONNECTION_POOL_SIZE,
    MAX_BACKENDS_PER_CLUSTER,
};
use crate::{
    containers::BoundedVec,
    session::SocketCookie,
};

#[repr(C)]
#[derive(Debug, Copy, Clone, Default)]
#[cfg_attr(feature = "user", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "user", serde(rename_all = "kebab-case"))]
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
    pub total_weight: u64, // total weight for WRR
}

#[repr(C)]
#[derive(Debug, Copy, Clone, Default)]
pub struct Backend {
    // 8B align
    pub pool_idx: u32, // index into BACKEND_CONNECTION_POOL_TABLE
    pub weight: u32,   // weight for round-robin
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct BackendConnectionPool {
    // 8B align
    pub connections: BoundedVec<SocketCookie, MAX_BACKEND_CONNECTION_POOL_SIZE>,
    // connection load balancing state
    // 8B align
    pub active_connections: u32, // used for least-loaded policy
    pub rr_counter: u32,         // round-robin counter
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Cluster {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for LoadBalancingPolicy {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Backend {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for BackendConnectionPool {}
