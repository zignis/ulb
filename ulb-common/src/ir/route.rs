use super::PATH_MAX_LEN;
use crate::containers::BoundedStr;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub enum RouteMatchType {
    Prefix,
    Exact,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub enum RouteAction {
    Forward,
    Drop,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct RouteValue {
    pub path: BoundedStr<PATH_MAX_LEN>, // match string
    pub cluster_idx: u32,               // index into backend cluster
    pub method_mask: u16,               // bitmask of allowed http methods
    pub match_type: RouteMatchType,
    pub action: RouteAction,
}
