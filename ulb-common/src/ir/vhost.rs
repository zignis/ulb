use super::VHOST_MAX_LEN;
use crate::containers::BoundedStr;

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VHostKey {
    pub host: BoundedStr<VHOST_MAX_LEN>,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VHostValue {
    pub route_start: u32, // idx of first route for this vhost
    pub route_count: u32, // number of routes for this vhost
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for VHostKey {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for VHostValue {}
