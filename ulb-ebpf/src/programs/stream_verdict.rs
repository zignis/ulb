use aya_ebpf::{
    bindings::sk_action::{
        SK_DROP,
        SK_PASS,
    },
    cty::c_void,
    helpers::{
        bpf_get_socket_cookie,
        bpf_skb_pull_data,
    },
    macros::stream_verdict,
    programs::SkBuffContext,
};
use ulb_common::{
    JMP_PROG_ROUTING,
    SESSION_ENTRY_CLIENT,
};

use crate::{
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
fn stream_verdict(ctx: SkBuffContext) -> u32 {
    if unsafe { bpf_skb_pull_data(ctx.skb.skb, 0) } < 0 {
        return SK_DROP;
    }

    let cookie = unsafe { bpf_get_socket_cookie(ctx.skb.skb as *mut c_void) };

    debug!(ctx, "connection arrived for verdict ({}B)", ctx.len());

    // fast-path
    if let Some([mut key, kind]) = unsafe { SESSION_MAP.get(&cookie) }.copied() {
        if kind == SESSION_ENTRY_CLIENT {
            if CLIENT_CONNECTION_MAP.redirect_skb(&ctx, &mut key, 0) == (SK_PASS as i64) {
                return SK_PASS;
            }
        } else {
            if BACKEND_CONNECTION_MAP.redirect_skb(&ctx, &mut key, 0) == (SK_PASS as i64) {
                return SK_PASS;
            }
        }

        // TODO: what should be done as a fallback?
        // TODO: cleanup SESSION_MAP and return SK_DROP?
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
fn router(ctx: SkBuffContext) -> u32 {
    route_req(&ctx).unwrap_or(SK_DROP)
}
