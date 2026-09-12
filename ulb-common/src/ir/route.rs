#[cfg(feature = "user")]
use serde::{
    Deserialize,
    Serialize,
};

use crate::{
    HTTP_URI_MAX_LEN,
    containers::BoundedStr,
};

#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "user", derive(Serialize, Deserialize))]
pub enum RouteMatchType {
    Prefix,
    Exact,
}

pub const ROUTE_ACTION_DROP: u32 = u32::MAX;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct RouteValue {
    // 8B align
    pub path: BoundedStr<HTTP_URI_MAX_LEN>, // match string
    // 8B align
    pub match_type: RouteMatchType,
    pub method_mask: u32, // bitmask of allowed http methods
    // 8B align
    pub required_headers_mask: u32, // bitmask of header rules that must match
    pub action: u32,                // drop action if == u32::MAX; idx into cluster table otherwise
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for RouteValue {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for RouteMatchType {}
