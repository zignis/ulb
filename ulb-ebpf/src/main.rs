#![no_std]
#![no_main]

mod http;
mod router;

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
    macros::{
        map,
        stream_parser,
        stream_verdict,
    },
    maps::{
        Array,
        HashMap,
        ProgramArray,
        SockHash,
    },
    programs::SkBuffContext,
};
#[cfg(feature = "debug")]
use aya_log_ebpf::info;
use http::SkbData;
use ulb_common::{
    HTTP_REQ_MAX_SCRATCH_SIZE,
    JMP_PROG_COUNT,
    JMP_PROG_ROUTING,
    SESSION_ENTRY_CLIENT,
    SessionEntry,
    ir::{
        BackendCluster,
        MAX_BACKEND_CLUSTERS,
        MAX_ROUTES,
        MAX_VHOSTS,
        RouteValue,
        VHostKey,
        VHostValue,
    },
};

//

#[map]
static JMP_TABLE: ProgramArray = ProgramArray::with_max_entries(JMP_PROG_COUNT, 0);

#[map]
static BACKEND_MAP: SockHash<u64> = SockHash::with_max_entries(1024, 0);

#[map]
static CONNECTION_MAP: SockHash<u64> = SockHash::with_max_entries(1024, 0);

#[map]
static SESSION_MAP: HashMap<u64, SessionEntry> = HashMap::with_max_entries(4096, 0);

#[map]
static VHOST_MAP: HashMap<VHostKey, VHostValue> = HashMap::with_max_entries(MAX_VHOSTS, 0);

#[map]
static ROUTE_TABLE: Array<RouteValue> = Array::with_max_entries(MAX_ROUTES, 0);

#[map]
static CLUSTER_TABLE: Array<BackendCluster> = Array::with_max_entries(MAX_BACKEND_CLUSTERS, 0);

//

#[stream_parser]
pub fn stream_parser(ctx: SkBuffContext) -> u32 {
    let cookie = unsafe { bpf_get_socket_cookie(ctx.skb.skb as *mut c_void) };

    // fast-path
    if unsafe { SESSION_MAP.get(&cookie) }.is_some() {
        return ctx.len();
    }

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
    if unsafe { bpf_skb_pull_data(ctx.skb.skb, 0) } < 0 {
        return SK_DROP;
    }

    #[cfg(feature = "debug")]
    info!(&ctx, "stream_verdict triggered, skb_size={}", ctx.len());

    let cookie = unsafe { bpf_get_socket_cookie(ctx.skb.skb as *mut c_void) };

    // fast-path
    if let Some([mut key, kind]) = unsafe { SESSION_MAP.get(&cookie) }.copied() {
        if kind == SESSION_ENTRY_CLIENT {
            if { CONNECTION_MAP.redirect_skb(&ctx, &mut key, 0) } == (SK_PASS as i64) {
                return SK_PASS;
            }
        } else {
            if { BACKEND_MAP.redirect_skb(&ctx, &mut key, 0) } == (SK_PASS as i64) {
                return SK_PASS;
            }
        }
    }

    if http::parse_req(&ctx).is_err() {
        return SK_DROP;
    }

    // tail call to router
    unsafe {
        JMP_TABLE.tail_call(&ctx, JMP_PROG_ROUTING);
    }

    #[cfg(feature = "debug")]
    info!(&ctx, "router tail call failed");

    // TODO: change default action
    SK_DROP
}

#[stream_verdict]
pub fn router(ctx: SkBuffContext) -> u32 {
    match router::route_req(&ctx) {
        Ok(action) => {
            #[cfg(feature = "debug")]
            info!(&ctx, "req routed");
            action
        }

        Err(_) => SK_DROP,
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
