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

const MAX_SKB_SIZE: u32 = 4096;

#[map]
static CONN_MAP: SockMap = SockMap::with_max_entries(1024, 0);

#[stream_parser]
pub fn stream_parser(ctx: SkBuffContext) -> u32 {
    ctx.len()
}

#[stream_verdict]
pub fn stream_verdict(ctx: SkBuffContext) -> u32 {
    try_stream_verdict(ctx).unwrap_or(SK_DROP)
}

fn try_stream_verdict(ctx: SkBuffContext) -> Result<u32, u32> {
    let skb_size = MAX_SKB_SIZE.min(ctx.len());

    if unsafe { bpf_skb_pull_data(ctx.skb.skb, skb_size) } < 0 {
        return Err(SK_DROP);
    }

    #[cfg(feature = "debug")]
    info!(&ctx, "stream_verdict triggered, skb_size={}", skb_size);

    let req = get_http_buf().ok_or(SK_DROP)?;
    req._offset = 0;
    req._hdr_count = 0;

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
    info!(ctx, "parsed {} headers", req._hdr_count);

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
