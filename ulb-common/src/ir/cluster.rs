use super::{
    MAX_BACKEND_CONNECTION_POOL_SIZE,
    MAX_BACKENDS_PER_CLUSTER,
};
use crate::{
    SocketCookie,
    containers::BoundedVec,
};

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub enum LoadBalancingPolicy {
    RoundRobin,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct Cluster {
    pub policy: LoadBalancingPolicy,
    pub backends: BoundedVec<Backend, MAX_BACKENDS_PER_CLUSTER>,
    // TODO: load balancing state
    pub rr_counter: u32, // round-robin counter
}

#[repr(C)]
#[derive(Debug, Copy, Clone, Default)]
pub struct Backend {
    pub pool_idx: u32, // index into BACKEND_CONNECTION_POOL_TABLE
    pub flags: u8,     // TODO: backend state for future usage
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct BackendConnectionPool {
    pub connections: BoundedVec<SocketCookie, MAX_BACKEND_CONNECTION_POOL_SIZE>,
    // connection load balancing state
    pub rr_counter: u32, // round-robin counter
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Cluster {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for LoadBalancingPolicy {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Backend {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for BackendConnectionPool {}
