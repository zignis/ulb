#[cfg(feature = "user")]
use serde::{
    Deserialize,
    Serialize,
};

use super::PATH_MAX_LEN;
use crate::containers::BoundedStr;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "user", derive(Serialize, Deserialize))]
pub enum RouteMatchType {
    Prefix,
    Exact,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub enum RouteAction {
    Forward { cluster_idx: u32 }, // index into backend cluster
    Drop,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct RouteValue {
    pub path: BoundedStr<PATH_MAX_LEN>, // match string
    pub method_mask: u16,               // bitmask of allowed http methods
    pub match_type: RouteMatchType,
    pub action: RouteAction,
}
