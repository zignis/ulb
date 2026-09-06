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
use ulb_common::JMP_PROG_ROUTING;

use crate::{
    BPF_SKB_EGRESS,
    debug,
    http::parse_req,
    maps::{
        BACKEND_CONNECTION_MAP,
        CLIENT_CONNECTION_MAP,
        JMP_TABLE,
        SESSION_MAP,
    },
    router::route_req,
};

#[stream_verdict]
fn client_stream_verdict(ctx: SkBuffContext) -> u32 {
    let cookie = unsafe { bpf_get_socket_cookie(ctx.skb.skb as *mut c_void) };

    debug!(
        ctx,
        "client connection arrived for verdict ({}B)",
        ctx.len()
    );

    // fast-path
    if let Some(mut backend) = unsafe { SESSION_MAP.get(cookie) }.copied() {
        return BACKEND_CONNECTION_MAP.redirect_skb(&ctx, &mut backend, BPF_SKB_EGRESS) as u32;
    }

    if unsafe { bpf_skb_pull_data(ctx.skb.skb, 0) } < 0 {
        return SK_DROP;
    }

    if parse_req(&ctx).is_err() {
        return SK_DROP;
    }

    // tail call to router
    unsafe {
        JMP_TABLE.tail_call(&ctx, JMP_PROG_ROUTING);
    }

    debug!(ctx, "tail call to router failed");

    SK_DROP
}

#[stream_verdict]
fn backend_stream_verdict(ctx: SkBuffContext) -> u32 {
    let cookie = unsafe { bpf_get_socket_cookie(ctx.skb.skb as *mut c_void) };

    debug!(
        ctx,
        "backend connection arrived for verdict ({}B)",
        ctx.len()
    );

    // fast-path
    if let Some(mut client) = unsafe { SESSION_MAP.get(cookie) }.copied() {
        return CLIENT_CONNECTION_MAP.redirect_skb(&ctx, &mut client, BPF_SKB_EGRESS) as u32;
    }

    SK_DROP
}

#[stream_verdict]
fn router(ctx: SkBuffContext) -> u32 {
    route_req(&ctx).unwrap_or(SK_DROP)
}
