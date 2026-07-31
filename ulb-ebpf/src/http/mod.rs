use aya_ebpf::{
    macros::map,
    maps::PerCpuArray,
    programs::SkBuffContext,
};
#[cfg(feature = "debug")]
use aya_log_ebpf::info;
use ulb_common::HttpRequest;

mod get_http_buf;
mod headers;
mod request_line;
mod skb_data;

pub use get_http_buf::*;
use headers::*;
use request_line::*;
pub use skb_data::*;

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

    if parse_request_line(ctx, req).is_err() {
        #[cfg(feature = "debug")]
        info!(&ctx, "parse_request_line failed");
        return Err(());
    }

    if parse_headers(ctx, req).is_err() {
        #[cfg(feature = "debug")]
        info!(&ctx, "parse_headers failed");
        return Err(());
    }

    Ok(())
}
