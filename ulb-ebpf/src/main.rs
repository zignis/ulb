#![no_std]
#![no_main]

mod http;

#[cfg(feature = "debug")]
use aya_ebpf::bpf_printk;
use aya_ebpf::{
    bindings::sk_action::{
        SK_DROP,
        SK_PASS,
    },
    helpers::bpf_skb_pull_data,
    macros::{
        map,
        stream_parser,
        stream_verdict,
    },
    maps::SockMap,
    programs::SkBuffContext,
};
#[cfg(feature = "debug")]
use aya_log_ebpf::info;
use http::{
    get_http_buf,
    headers::parse_headers,
    request_line::parse_request_line,
};
use ulb_common::HTTP_REQ_MAX_SCRATCH_SIZE;

use crate::http::skb_data::SkbData;

#[map]
static CONN_MAP: SockMap = SockMap::with_max_entries(1024, 0);

#[stream_parser]
pub fn stream_parser(ctx: SkBuffContext) -> u32 {
    if unsafe {
        bpf_skb_pull_data(
            ctx.skb.skb,
            (HTTP_REQ_MAX_SCRATCH_SIZE as u32).min(ctx.len()),
        )
    } < 0
    {
        return 0;
    }

    let data = SkbData::from_ctx(&ctx);

    for i in 0..HTTP_REQ_MAX_SCRATCH_SIZE {
        if data.is_length_out_of_bounds(i + 4) {
            break;
        }

        if unsafe { data.slice_unchecked(i) } == b"\r\n\r\n" {
            return ctx.len();
        }
    }
    0
}

#[stream_verdict]
pub fn stream_verdict(ctx: SkBuffContext) -> u32 {
    try_stream_verdict(ctx).unwrap_or(SK_DROP)
}

fn try_stream_verdict(ctx: SkBuffContext) -> Result<u32, u32> {
    if unsafe { bpf_skb_pull_data(ctx.skb.skb, 0) } < 0 {
        return Err(SK_DROP);
    }

    #[cfg(feature = "debug")]
    info!(&ctx, "stream_verdict triggered, skb_size={}", ctx.len());

    let req = get_http_buf().ok_or(SK_DROP)?;

    if let Err(_) = parse_request_line(&ctx, req) {
        #[cfg(feature = "debug")]
        info!(&ctx, "parse_request_line failed");
        return Err(SK_DROP);
    }

    #[cfg(feature = "debug")]
    info!(&ctx, "parsed req line, offset={}", req._offset);

    #[cfg(feature = "debug")]
    unsafe {
        bpf_printk!(
            c"[%s][%s]: %s",
            req.method.as_c_str().as_ptr(),
            req.version.as_c_str().as_ptr(),
            req.uri.as_ptr()
        );
    }

    if let Err(_) = parse_headers(&ctx, req) {
        #[cfg(feature = "debug")]
        info!(&ctx, "parse_headers failed");
        return Err(SK_DROP);
    }

    #[cfg(feature = "debug")]
    info!(ctx, "parsed {} headers", req.headers.len);

    Ok(SK_PASS)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
