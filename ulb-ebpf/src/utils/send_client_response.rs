use core::ffi::c_void;

use aya_ebpf::{
    bindings::sk_action::SK_DROP,
    helpers::{
        bpf_get_socket_cookie,
        bpf_skb_change_tail,
        bpf_skb_store_bytes,
    },
    programs::SkBuffContext,
};
use ulb_common::SocketCookie;

use crate::{
    BPF_SKB_EGRESS,
    maps::CLIENT_CONNECTION_MAP,
};

pub const HTTP_400_BAD_REQUEST: &[u8] =
    b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";

pub fn send_client_response(ctx: &SkBuffContext, response: &[u8]) -> u32 {
    let mut cookie = unsafe { bpf_get_socket_cookie(ctx.skb.skb as *mut c_void) } as SocketCookie;
    let len = response.len() as u32;

    if unsafe { bpf_skb_change_tail(ctx.skb.skb, len, 0) } != 0 {
        return SK_DROP;
    }

    if unsafe { bpf_skb_store_bytes(ctx.skb.skb, 0, response.as_ptr() as *const c_void, len, 0) }
        != 0
    {
        return SK_DROP;
    }

    CLIENT_CONNECTION_MAP.redirect_skb(ctx, &mut cookie, BPF_SKB_EGRESS) as u32
}
