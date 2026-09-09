use crate::{
    HTTP_HDR_VAL_MAX_LEN,
    containers::BoundedStr,
};

#[repr(C)]
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "user", derive(PartialEq, Eq, Hash))]
pub struct VHostKey {
    // we also need port here since multiple listeners can contain `host`
    pub port: u32, // listener port (needs to be u32 to avoid explicit padding)
    pub host: BoundedStr<HTTP_HDR_VAL_MAX_LEN>,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "user", derive(PartialEq, Eq))]
pub struct VHostValue {
    pub route_start: u32, // idx of first route for this vhost
    pub route_count: u32, // number of routes for this vhost
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for VHostKey {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for VHostValue {}
