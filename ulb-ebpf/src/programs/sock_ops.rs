use core::ffi::c_int;

use aya_ebpf::{
    bindings::{
        BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB,
        BPF_SOCK_OPS_STATE_CB,
        BPF_SOCK_OPS_STATE_CB_FLAG,
        BPF_TCP_CLOSE,
        BPF_TCP_TIME_WAIT,
    },
    cty::c_void,
    helpers::{
        bpf_get_socket_cookie,
        bpf_sock_hash_update,
        bpf_sock_ops_cb_flags_set,
    },
    macros::sock_ops,
    programs::SockOpsContext,
};
use ulb_common::session::SocketCookie;

use crate::{
    debug,
    error,
    maps::{
        BACKEND_CONNECTION_POOL_TABLE,
        CLIENT_CONNECTION_MAP,
        LISTENER_PORTS,
        SESSION_MAP,
    },
    utils::atomic_add_i32,
};

#[sock_ops]
fn ulb_sock_ops(ctx: SockOpsContext) -> u32 {
    match ctx.op() {
        // remove stale mapping from SESSION_MAP
        BPF_SOCK_OPS_STATE_CB if matches!(ctx.arg(1), BPF_TCP_CLOSE | BPF_TCP_TIME_WAIT) => {
            let cookie = unsafe { bpf_get_socket_cookie(ctx.ops as *mut c_void) } as SocketCookie;

            if let Some(target) = unsafe { SESSION_MAP.get(cookie) } {
                if let Some(pool) =
                    BACKEND_CONNECTION_POOL_TABLE.get_ptr_mut(target.pool_idx as u32)
                {
                    unsafe {
                        atomic_add_i32((&raw mut (*pool).active_connections) as *mut i32, -1);
                    }
                }

                let _ = SESSION_MAP.remove(cookie);
                let _ = SESSION_MAP.remove(target.cookie);

                debug!(
                    &ctx,
                    "cleared session (CK:{}, CK:{})", cookie, target.cookie
                );
            }
        }

        // incoming client connection
        BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB => {
            let cookie = unsafe { bpf_get_socket_cookie(ctx.ops as *mut c_void) } as SocketCookie;
            let local_port = ctx.local_port();

            if LISTENER_PORTS.get(local_port) == Some(&1) {
                if unsafe {
                    // https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_SOCK_OPS/#bpf_sock_ops_state_cb
                    let next_flags = (*ctx.ops).bpf_sock_ops_cb_flags | BPF_SOCK_OPS_STATE_CB_FLAG;
                    // returns the number of bits that were not able to set
                    bpf_sock_ops_cb_flags_set(ctx.ops, next_flags as c_int) != 0
                } {
                    error!(&ctx, "[E:0] `bpf_sock_ops_cb_flags_set` failed");
                }

                let ret_val = unsafe {
                    bpf_sock_hash_update(
                        ctx.ops,
                        &CLIENT_CONNECTION_MAP as *const _ as *mut c_void,
                        &cookie as *const _ as *mut c_void,
                        0,
                    )
                };

                if ret_val == 0 {
                    debug!(
                        &ctx,
                        "inserted CK:{} to CLIENT_CONNECTION_MAP (listener :{})",
                        cookie,
                        local_port
                    );
                } else {
                    error!(
                        &ctx,
                        "[E:0] failed to insert CK:{} to CLIENT_CONNECTION_MAP (listener :{}): {}",
                        cookie,
                        local_port,
                        ret_val
                    );
                }
            }
        }

        _ => {}
    };

    0
}
