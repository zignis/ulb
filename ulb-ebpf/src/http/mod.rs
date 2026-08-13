use aya_ebpf::{
    macros::map,
    maps::PerCpuArray,
    programs::SkBuffContext,
};
use ulb_common::HttpRequest;

mod get_http_buf;
mod headers;
mod request_line;
mod skb_data;

pub use get_http_buf::*;
use headers::*;
use request_line::*;
pub use skb_data::*;

pub const CH_CR: u8 = b'\r';
pub const CH_LF: u8 = b'\n';
pub const CH_SP: u8 = b' ';
pub const CH_COLON: u8 = b':';

use crate::debug;

/// shared per-cpu slot holding the parsed http request for the current packet
#[map]
pub static HTTP_REQ_BUF: PerCpuArray<HttpRequest> = PerCpuArray::with_max_entries(1, 0);

#[derive(Debug)]
pub enum HttpParseError {
    InvalidMethod,
    InvalidUri,
    InvalidVersion,
    Internal,
}

impl HttpParseError {
    #[cfg(feature = "debug")]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::InvalidMethod => "invalid method",
            Self::InvalidUri => "invalid uri",
            Self::InvalidVersion => "invalid http version",
            Self::Internal => "internal error",
        }
    }
}

pub fn parse_req(ctx: &SkBuffContext) -> Result<(), ()> {
    let req = get_http_buf().ok_or(())?;

    #[allow(unused_variables)]
    if let Err(err) = parse_request_line(ctx, req) {
        debug!(&ctx, "failed to parse request line: {}", err.as_str());
        return Err(());
    }

    #[allow(unused_variables)]
    if let Err(err) = parse_headers(ctx, req) {
        debug!(&ctx, "failed to parse header: {}", err.as_str());
        return Err(());
    }

    Ok(())
}
