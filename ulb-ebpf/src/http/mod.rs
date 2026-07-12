use aya_ebpf::{
    macros::map,
    maps::PerCpuArray,
};
use ulb_common::HttpRequest;

mod get_http_buf;
pub mod headers;
pub mod request_line;
pub mod skb_data;

pub use get_http_buf::*;

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
