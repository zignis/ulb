#[cfg(feature = "user")]
use serde::{
    Deserialize,
    Serialize,
};

use crate::{
    HTTP_HDR_KEY_MAX_LEN,
    HTTP_HDR_VAL_MAX_LEN,
    containers::{
        BoundedStr,
        BoundedVec,
    },
    ir::{
        MAX_HEADER_RULES_PER_ROUTE,
        PATH_MAX_LEN,
    },
};

// TODO: support more complex matching (wildcards, optionals)

#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "user", derive(Serialize, Deserialize))]
pub enum RouteMatchType {
    Prefix,
    Exact,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, Default)]
#[cfg_attr(feature = "user", derive(Serialize, Deserialize))]
pub enum HeaderMatchType {
    Prefix,
    Exact,
    #[default]
    Present,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub enum RouteAction {
    Forward { cluster_idx: u32 }, // index into backend cluster
    Drop,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, Default)]
pub struct HeaderMatch {
    pub name: BoundedStr<HTTP_HDR_KEY_MAX_LEN>,
    pub value: BoundedStr<HTTP_HDR_VAL_MAX_LEN>,
    pub match_type: HeaderMatchType,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct RouteValue {
    pub path: BoundedStr<PATH_MAX_LEN>, // match string
    pub method_mask: u16,               // bitmask of allowed http methods
    pub match_type: RouteMatchType,
    pub action: RouteAction,
    pub headers: BoundedVec<HeaderMatch, MAX_HEADER_RULES_PER_ROUTE>,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for RouteValue {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for RouteMatchType {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for HeaderMatch {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for HeaderMatchType {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for RouteAction {}
