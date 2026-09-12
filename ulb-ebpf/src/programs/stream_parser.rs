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
        // fwd to stream_verdict which will discard this non-linear packet
        return ctx.len();
    }

    let data = SkbData::from_ctx(&ctx);
    let mut tail = 0;

    for i in (0..HTTP_REQ_MAX_SCRATCH_SIZE).step_by(5) {
        tail = i;

        let Some(word) = data.read_u64(i) else {
            break;
        };

        if word as u32 == CRLF_CRLF
            || (word >> 8) as u32 == CRLF_CRLF
            || (word >> 16) as u32 == CRLF_CRLF
            || (word >> 24) as u32 == CRLF_CRLF
            || (word >> 32) as u32 == CRLF_CRLF
        {
            return ctx.len();
        }
    }

    // check left over bytes
    for _ in 0..4 {
        if tail >= HTTP_REQ_MAX_SCRATCH_SIZE {
            break;
        }

        if data.is_length_out_of_bounds(tail + 4) {
            break;
        }

        if unsafe { data.match_u32_unchecked(tail, CRLF_CRLF) } {
            return ctx.len();
        }

        tail += 1;
    }

    // fwd to stream_verdict if \r\n\r\n is not found within scratch size
    if ctx.len() >= HTTP_REQ_MAX_SCRATCH_SIZE as u32 {
        return ctx.len();
    }

    0 // wait for more data
}
