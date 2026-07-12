#![no_std]

#[cfg(feature = "debug")]
use core::ffi::CStr;

pub const HTTP_MAX_HEADERS: usize = 4;
pub const HTTP_HDR_MAX_KEY_SIZE: usize = 32;
pub const HTTP_HDR_MAX_VAL_SIZE: usize = 64;
pub const HTTP_URI_SIZE: usize = 256;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub enum HttpMethod {
    Get,
    Put,
    Post,
    Delete,
    Patch,
    Head,
    Connect,
    Trace,
    Options,
}

impl HttpMethod {
    #[cfg(feature = "debug")]
    pub const fn as_c_str(&self) -> &'static CStr {
        match self {
            Self::Get => c"GET",
            Self::Put => c"PUT",
            Self::Post => c"POST",
            Self::Delete => c"DELETE",
            Self::Patch => c"PATCH",
            Self::Head => c"HEAD",
            Self::Connect => c"CONNECT",
            Self::Trace => c"TRACE",
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
    pub key_len: u32,
    pub key: [u8; HTTP_HDR_MAX_KEY_SIZE],
    pub value_len: u32,
    pub value: [u8; HTTP_HDR_MAX_VAL_SIZE],
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct HttpRequest {
    pub method: HttpMethod,
    pub version: HttpVersion,
    pub uri_len: u32,
    pub uri: [u8; HTTP_URI_SIZE],
    pub headers: [HttpHeader; HTTP_MAX_HEADERS],
    // -- internal
    pub _offset: u32,    // read offset
    pub _hdr_count: u32, // number of parsed headers
}
