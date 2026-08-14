use aya_ebpf::programs::SkBuffContext;

mod headers;
mod request_line;

use headers::*;
use request_line::*;

use crate::{
    debug,
    utils::{
        b8,
        get_http_buf,
    },
};

pub const CH_CR: u8 = b8(b"\r");
pub const CH_LF: u8 = b8(b"\n");
pub const CH_SP: u8 = b8(b" ");
pub const CH_COLON: u8 = b8(b":");

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
