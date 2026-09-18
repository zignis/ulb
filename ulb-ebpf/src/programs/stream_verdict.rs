use aya_ebpf::{
    bindings::sk_action::SK_DROP,
    cty::c_void,
    helpers::{
        bpf_get_socket_cookie,
        bpf_skb_pull_data,
    },
    macros::stream_verdict,
    programs::SkBuffContext,
};
use ulb_common::http::HTTP_REQ_MAX_SCRATCH_SIZE;

use crate::{
    BPF_SKB_EGRESS,
    debug,
    http::{
        headers::parse_headers,
        parse_req,
    },
    maps::{
        BACKEND_CONNECTION_MAP,
        CLIENT_CONNECTION_MAP,
        SESSION_MAP,
    },
    router::route_req,
    utils::remove_session_mapping,
};

#[stream_verdict]
fn ulb_client_stream_verdict(ctx: SkBuffContext) -> u32 {
    let cookie = unsafe { bpf_get_socket_cookie(ctx.skb.skb as *mut c_void) };

    debug!(ctx, "[D:1] client connection arrived ({}B)", ctx.len());

    // fast-path
    if let Some(backend) = unsafe { SESSION_MAP.get(cookie) } {
        let mut backend_cookie = backend.cookie;
        let ret =
            BACKEND_CONNECTION_MAP.redirect_skb(&ctx, &mut backend_cookie, BPF_SKB_EGRESS) as u32;
        if ret == SK_DROP {
            debug!(ctx, "[E:1] removing stale session");
            remove_session_mapping(&cookie);
        } else {
            return ret;
        }
    }

    if unsafe {
        bpf_skb_pull_data(
            ctx.skb.skb,
            (HTTP_REQ_MAX_SCRATCH_SIZE as u32).min(ctx.len()),
        )
    } < 0
    {
        return SK_DROP;
    }

    parse_req(&ctx)
}

#[stream_verdict]
fn ulb_backend_stream_verdict(ctx: SkBuffContext) -> u32 {
    let cookie = unsafe { bpf_get_socket_cookie(ctx.skb.skb as *mut c_void) };

    debug!(ctx, "[D:4] response from backend ({}B)", ctx.len());

    // fast-path
    if let Some(client) = unsafe { SESSION_MAP.get(cookie) } {
        let mut cookie = client.cookie;
        return CLIENT_CONNECTION_MAP.redirect_skb(&ctx, &mut cookie, BPF_SKB_EGRESS) as u32;
    }

    SK_DROP
}

#[stream_verdict]
fn ulb_header_parser(ctx: SkBuffContext) -> u32 {
    parse_headers(&ctx)
}

#[stream_verdict]
fn ulb_router(ctx: SkBuffContext) -> u32 {
    route_req(&ctx)
}
