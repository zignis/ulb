#[cfg(feature = "debug")]
use core::ffi::CStr;

use crate::{
    containers::{
        BoundedStr,
        BoundedVec,
    },
    ir::MAX_ROUTES,
};

// 8kb for req line and headers
pub const HTTP_REQ_MAX_SCRATCH_SIZE: usize = 8 * 1024;

// must be a multiple of 8 (for aligned batch reading) and a power of 2 (for
// verifier bound checks)
pub const HTTP_URI_MAX_LEN: usize = 256;

pub const HTTP_MAX_HEADERS: usize = 256; // TODO: try to increase this since we're matching headers on the fly

// must be a multiple of 8 (for aligned batch reading) and a power of 2 (for
// verifier bound checks)
pub const HTTP_HDR_KEY_MAX_LEN: usize = 32;

// must be a multiple of 8 (for aligned batch reading) and a power of 2 (for
// verifier bound checks)
pub const HTTP_HDR_VAL_MAX_LEN: usize = 128; // TODO: try to increase this to maximum possible

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub enum HttpMethod {
    Get     = 1 << 0,
    Put     = 1 << 1,
    Post    = 1 << 2,
    Head    = 1 << 3,
    Patch   = 1 << 4,
    Trace   = 1 << 5,
    Query   = 1 << 6, // RFC 10008
    Delete  = 1 << 7,
    Connect = 1 << 8,
    Options = 1 << 9,
}

impl From<HttpMethod> for u16 {
    fn from(value: HttpMethod) -> Self {
        value as u16
    }
}

impl From<HttpMethod> for u32 {
    fn from(value: HttpMethod) -> Self {
        value as u32
    }
}

impl HttpMethod {
    pub fn match_mask(&self, mask: u32) -> bool {
        // if no allowed methods are specified by user, allow all methods
        if mask == 0 {
            return true;
        }

        (mask & u32::from(*self)) != 0
    }

    #[cfg(feature = "debug")]
    pub const fn as_c_str(&self) -> &'static CStr {
        match self {
            Self::Get => c"GET",
            Self::Put => c"PUT",
            Self::Post => c"POST",
            Self::Head => c"HEAD",
            Self::Patch => c"PATCH",
            Self::Trace => c"TRACE",
            Self::Query => c"QUERY",
            Self::Delete => c"DELETE",
            Self::Connect => c"CONNECT",
            Self::Options => c"OPTIONS",
        }
    }
}

#[cfg(feature = "user")]
impl TryFrom<&str> for HttpMethod {
    type Error = ();

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value.to_ascii_lowercase().as_str() {
            "get" => Ok(Self::Get),
            "put" => Ok(Self::Put),
            "post" => Ok(Self::Post),
            "head" => Ok(Self::Head),
            "patch" => Ok(Self::Patch),
            "trace" => Ok(Self::Trace),
            "query" => Ok(Self::Query),
            "delete" => Ok(Self::Delete),
            "connect" => Ok(Self::Connect),
            "options" => Ok(Self::Options),
            _ => Err(()),
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub enum HttpVersion {
    V1P0,
    V1P1,
}

impl HttpVersion {
    #[cfg(feature = "debug")]
    pub const fn as_c_str(&self) -> &'static CStr {
        match self {
            Self::V1P0 => c"HTTP/1.0",
            Self::V1P1 => c"HTTP/1.1",
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct HttpHeader {
    pub key: BoundedStr<HTTP_HDR_KEY_MAX_LEN>,
    pub val: BoundedStr<HTTP_HDR_VAL_MAX_LEN>,
}

impl HttpHeader {
    // resets the len of key and val
    // does not zero out the buffer
    pub fn reset(&mut self) {
        self.key.len = 0;
        self.val.len = 0;
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct HttpRequest {
    pub method: HttpMethod,
    pub version: HttpVersion,
    pub uri: BoundedStr<HTTP_URI_MAX_LEN>,
    pub host: BoundedStr<HTTP_HDR_VAL_MAX_LEN>, // `Host` header value
    // bit "x" is set in u32 if header rule "x" for this route is satisfied
    pub satisfied_rule_masks: [u32; MAX_ROUTES as usize],
    // to speedup reset_mask for next request
    pub dirty_route_idx: BoundedVec<u32, { MAX_ROUTES as usize }>,
    pub dirty_route_map: [bool; MAX_ROUTES as usize],
    // -- internal
    pub _offset: u32, // read offset
}

impl HttpRequest {
    pub fn mark_route_dirty(&mut self, route_idx: usize) {
        if !self.dirty_route_map[route_idx] {
            self.dirty_route_map[route_idx] = true;

            let len = self.dirty_route_idx.len;
            if len < MAX_ROUTES as u64 {
                self.dirty_route_idx[len as usize] = route_idx as u32;
                self.dirty_route_idx.len += 1;
            }
        }
    }

    pub fn reset_rule_masks(&mut self) {
        let len = self.dirty_route_idx.len as usize;

        for i in 0..(MAX_ROUTES as usize) {
            if i >= len {
                break;
            }

            let route_idx = self.dirty_route_idx[i] as usize;

            if route_idx < MAX_ROUTES as usize {
                self.satisfied_rule_masks[route_idx] = 0;
                self.dirty_route_map[route_idx] = false;
            }
        }

        self.dirty_route_idx.reset();
    }
}
