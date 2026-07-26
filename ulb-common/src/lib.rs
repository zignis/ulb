#![no_std]

pub mod containers;

#[cfg(feature = "debug")]
use core::ffi::CStr;

use containers::*;

// -4 to keep loop iterations under verifier's 8192 jump limit
pub const HTTP_REQ_MAX_SCRATCH_SIZE: usize = 8 * 1024 - 4; // around 8kb for req line and headers

// headers
pub const HTTP_MAX_HEADERS: usize = 256;
pub const HTTP_HDR_KEY_MAX_SIZE: usize = 32;
pub const HTTP_HDR_VAL_MAX_SIZE: usize = 64;

// req line
pub const HTTP_URI_MAX_SIZE: usize = 256;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub enum HttpMethod {
    Get,
    Put,
    Post,
    Head,
    Patch,
    Trace,
    Query, // RFC 10008
    Delete,
    Connect,
    Options,
}

impl HttpMethod {
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
#[derive(Debug, Clone, Copy)]
pub struct HttpHeader {
    pub key: BoundedStr<HTTP_HDR_KEY_MAX_SIZE>,
    pub value: BoundedStr<HTTP_HDR_VAL_MAX_SIZE>,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct HttpRequest {
    pub method: HttpMethod,
    pub version: HttpVersion,
    pub uri: BoundedStr<HTTP_URI_MAX_SIZE>,
    pub headers: BoundedVec<HttpHeader, HTTP_MAX_HEADERS>,
    // -- internal
    pub _offset: u32, // read offset
}

impl HttpRequest {
    pub fn reset_headers(&mut self) {
        self.headers.len = 0;
    }
}
