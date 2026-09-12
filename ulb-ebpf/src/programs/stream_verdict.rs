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
        JMP_TABLE,
        SESSION_MAP,
    },
    router::route_req,
};

#[stream_verdict]
fn ulb_client_stream_verdict(ctx: SkBuffContext) -> u32 {
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

    parse_req(&ctx)
}

#[stream_verdict]
fn ulb_backend_stream_verdict(ctx: SkBuffContext) -> u32 {
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
fn ulb_header_parser(ctx: SkBuffContext) -> u32 {
    parse_headers(&ctx)
}

#[stream_verdict]
fn ulb_router(ctx: SkBuffContext) -> u32 {
    route_req(&ctx)
}
