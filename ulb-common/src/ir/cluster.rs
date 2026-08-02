use super::MAX_BACKENDS_PER_CLUSTER;
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
pub struct BackendCluster {
    pub policy: LoadBalancingPolicy,
    pub endpoints: BoundedVec<BackendEndpoint, MAX_BACKENDS_PER_CLUSTER>,
    // load balancing state
    pub rr_counter: u32, // round-robin counter
}

#[repr(C)]
#[derive(Debug, Copy, Clone, Default)]
pub struct BackendEndpoint {
    pub cookie: SocketCookie, // socket cookie of the backend connection
    pub flags: u8,            // TODO: endpoint state for future usage
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for BackendCluster {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for LoadBalancingPolicy {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for BackendEndpoint {}
