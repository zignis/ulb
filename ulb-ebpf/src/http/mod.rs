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

use crate::debug;
#[cfg(feature = "debug")]
use crate::log::get_req_trace_mut;

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

pub fn parse_req(ctx: &SkBuffContext) -> Result<(), ()> {
    let req = get_http_buf().ok_or(())?;

    if let Err(err) = parse_request_line(ctx, req) {
        debug!(&ctx, "failed to parse request line: {}", err);
        return Err(());
    }

    if let Err(err) = parse_headers(ctx, req) {
        debug!(&ctx, "failed to parse header: {}", err);
        return Err(());
    }

    #[cfg(feature = "debug")]
    if let Some(trace) = get_req_trace_mut() {
        trace.parsed = true;
        trace.method = req.method;
        trace.uri = req.uri;
    }

    Ok(())
}
