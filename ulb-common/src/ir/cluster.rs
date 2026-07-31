use super::MAX_BACKENDS_PER_CLUSTER;
use crate::containers::BoundedVec;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub enum LoadBalancingPolicy {
    RoundRobin,
    WeightedRoundRobin,
    LeastLoadedBackend,
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
    pub sock_map_idx: u32, // idx into backend sock-map
    pub flags: u8,         // healthcheck
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for BackendCluster {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for LoadBalancingPolicy {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for BackendEndpoint {}
