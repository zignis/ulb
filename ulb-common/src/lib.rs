#![no_std]

#[cfg(feature = "user")]
extern crate alloc;

pub mod containers;
pub mod ir;
pub mod utils;

#[cfg(feature = "debug")]
use core::ffi::CStr;

use containers::*;
use ir::*;
use utils::*;

// total programs available for tail call
pub const JMP_PROG_COUNT: u32 = 2;

// prog idx for tail calls
pub const JMP_PROG_ROUTER: u32 = 0;
pub const JMP_PROG_HEADER_PARSER: u32 = 1;

// around 8kb for req line and headers
pub const HTTP_REQ_MAX_SCRATCH_SIZE: usize = 8 * 1024;

// headers
pub const HTTP_MAX_HEADERS: usize = 256; // TODO: try to increase this since we're matching headers on the fly

// must be a multiple of 8 (for aligned batch reading) and a power of 2 (for
// verifier bound checks)
pub const HTTP_HDR_KEY_MAX_LEN: usize = 32;

// must be a multiple of 8 (for aligned batch reading) and a power of 2 (for
// verifier bound checks)
pub const HTTP_HDR_VAL_MAX_LEN: usize = 128; // TODO: try to increase this to maximum possible

// req line

// must be a multiple of 8 (for aligned batch reading) and a power of 2 (for
// verifier bound checks)
pub const HTTP_URI_MAX_LEN: usize = 256;

pub type SocketCookie = u64;

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
    pub headers: BoundedVec<HttpHeader, HTTP_MAX_HEADERS>,
    // -- internal
    pub _offset: u32, // read offset
}

impl HttpRequest {
    pub fn reset_headers(&mut self) {
        self.headers.len = 0;
    }
}
