use aya_ebpf::{
    cty::c_void,
    helpers::{
        bpf_get_socket_cookie,
        bpf_skb_pull_data,
    },
    macros::stream_parser,
    programs::SkBuffContext,
};
use ulb_common::HTTP_REQ_MAX_SCRATCH_SIZE;

use crate::{
    maps::SESSION_MAP,
    utils::{
        SkbData,
        b32,
    },
};

const CRLF_CRLF: u32 = b32(b"\r\n\r\n"); // signifies end of headers

#[stream_parser]
fn ulb_stream_parser(ctx: SkBuffContext) -> u32 {
    let cookie = unsafe { bpf_get_socket_cookie(ctx.skb.skb as *mut c_void) };

    // fast-path
    if unsafe { SESSION_MAP.get(cookie) }.is_some() {
        return ctx.len();
    }

    if unsafe {
        bpf_skb_pull_data(
            ctx.skb.skb,
            (HTTP_REQ_MAX_SCRATCH_SIZE as u32).min(ctx.len()),
        )
    } < 0
    {
        // TODO: should we return -ERRCODE and let the userspace drop conn?
        // fwd to stream_verdict which will discard this non-linear packet
        return ctx.len();
    }

    let data = SkbData::from_ctx(&ctx);

    for i in 0..HTTP_REQ_MAX_SCRATCH_SIZE {
        if data.is_length_out_of_bounds(i + 4) {
            break;
        }

        if unsafe { data.match_u32_unchecked(i, CRLF_CRLF) } {
            return ctx.len();
        }
    }

    // fwd to stream_verdict if \r\n\r\n is not found within scratch size
    if ctx.len() >= HTTP_REQ_MAX_SCRATCH_SIZE as u32 {
        return ctx.len();
    }

    0 // wait for more data
}
