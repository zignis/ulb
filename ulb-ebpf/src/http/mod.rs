mod headers;
mod request_line;

use aya_ebpf::{
    bindings::sk_action::SK_DROP,
    programs::SkBuffContext,
};
pub use headers::parse_headers;
use ulb_common::JmpProg;

use crate::{
    debug,
    error,
    http::request_line::parse_request_line,
    maps::JMP_TABLE,
    utils::{
        HTTP_414_URI_TOO_LONG,
        HTTP_500_INTERNAL_SERVER_ERROR,
        HTTP_501_NOT_IMPLEMENTED,
        HTTP_505_HTTP_VERSION_NOT_SUPPORTED,
        get_http_buf,
        send_client_response,
    },
};

#[derive(Debug)]
pub enum HttpParseError {
    InvalidMethod,
    InvalidUri,
    InvalidVersion,
    Internal,
}

impl HttpParseError {
    #[cfg(feature = "debug")]
    #[inline(always)]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::InvalidMethod => "invalid method",
            Self::InvalidUri => "invalid uri",
            Self::InvalidVersion => "invalid http version",
            Self::Internal => "internal error",
        }
    }

    #[inline(always)]
    fn http_response(&self) -> &[u8] {
        match self {
            Self::InvalidMethod => HTTP_501_NOT_IMPLEMENTED,
            Self::InvalidUri => HTTP_414_URI_TOO_LONG,
            Self::InvalidVersion => HTTP_505_HTTP_VERSION_NOT_SUPPORTED,
            Self::Internal => HTTP_500_INTERNAL_SERVER_ERROR,
        }
    }
}

#[inline(always)]
pub fn parse_req(ctx: &SkBuffContext) -> u32 {
    let req = match get_http_buf() {
        Some(x) => x,
        None => return SK_DROP,
    };

    req.reset_offset();

    #[allow(unused_variables)]
    if let Err(err) = parse_request_line(ctx, req) {
        debug!(&ctx, "[E:2] failed to parse request line: {}", err.as_str());
        return send_client_response(ctx, err.http_response());
    }

    unsafe {
        JMP_TABLE.tail_call(ctx, JmpProg::HdrParser as u32);
    }

    error!(ctx, "[E:2] tail call to header parser failed");

    SK_DROP
}
