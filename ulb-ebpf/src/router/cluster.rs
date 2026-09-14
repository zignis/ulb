use aya_ebpf::{
    bindings::BPF_NOEXIST,
    helpers::bpf_get_prandom_u32,
    programs::SkBuffContext,
};
use ulb_common::{
    ir::cluster::LoadBalancingPolicy,
    session::{
        SessionTarget,
        SocketCookie,
    },
};

use crate::{
    debug,
    maps::{
        BACKEND_CONNECTION_POOL_TABLE,
        CLUSTER_TABLE,
        SESSION_MAP,
    },
    utils::atomic_add_u64,
    warn,
};

const MAX_BACKEND_SELECT_ATTEMPTS: u32 = 8;
const MAX_CONNECTION_SELECT_ATTEMPTS: u32 = 4;

#[inline(always)]
fn claim_connection(
    ctx: &SkBuffContext,
    pool_idx: u32,
    client_cookie: SocketCookie,
    update_active_connections: bool,
) -> Option<SocketCookie> {
    let pool = BACKEND_CONNECTION_POOL_TABLE.get_ptr_mut(pool_idx)?;
    let pool_len = unsafe { (*pool).connections.len };

    if pool_len == 0 {
        return None;
    }

    // intentionally avoid atomic operation for this counter (eventual consistency
    // is maintained)
    let counter = unsafe { &mut (*pool).rr_counter };
    let start_idx = *counter % pool_len;
    *counter = counter.wrapping_add(1);

    // search for idle connection in pool
    for i in 0..MAX_CONNECTION_SELECT_ATTEMPTS as u64 {
        let cookie_idx = (start_idx + i) % pool_len;
        let cookie = unsafe { (*pool).connections.data.get(cookie_idx as usize) }?;

        if SESSION_MAP
            .insert(
                cookie,
                SessionTarget::new(client_cookie, pool_idx, update_active_connections),
                BPF_NOEXIST as u64, // atomically claim the backend socket for this client
            )
            .is_ok()
        {
            if update_active_connections {
                unsafe {
                    atomic_add_u64(&raw mut (*pool).active_connections, 1);
                }
            }

            debug!(
                ctx,
                "[D:3] claimed backend (CK:{}) from pool {}", *cookie, pool_idx
            );

            return Some(*cookie);
        }
    }

    None
}

pub fn select_backend(
    ctx: &SkBuffContext,
    cluster_idx: u32,
    client_cookie: SocketCookie,
) -> Option<(SocketCookie, u32, bool)> {
    let cluster = CLUSTER_TABLE.get_ptr_mut(cluster_idx)?;
    let len = unsafe { (*cluster).backends.len } as u32;
    let mut update_active_connections = false;

    debug!(ctx, "[D:3] cluster {} has {} backends", cluster_idx, len);

    if len == 0 {
        return None;
    }

    let start_idx = match unsafe { (*cluster).policy } {
        LoadBalancingPolicy::Random => unsafe { bpf_get_prandom_u32() % len },

        LoadBalancingPolicy::IpHash => ctx.skb.remote_ipv4() % len,

        LoadBalancingPolicy::RoundRobin => {
            // TODO: impl

            let counter = unsafe { &mut (*cluster).rr_counter };
            let start_idx = *counter % len;
            *counter = counter.wrapping_add(1);
            start_idx
        }

        LoadBalancingPolicy::LeastLoaded => {
            update_active_connections = true;

            // TODO: impl
            0
        }
    };

    // search for idle backends
    for i in 0..MAX_BACKEND_SELECT_ATTEMPTS {
        let idx = (start_idx + i) % len;

        if let Some(backend) = unsafe { (*cluster).backends.data.get(idx as usize) }
            && let Some(cookie) = claim_connection(
                ctx,
                backend.pool_idx,
                client_cookie,
                update_active_connections,
            )
        {
            return Some((cookie, backend.pool_idx, update_active_connections));
        }
    }

    warn!(ctx, "[E:3] no backend available");

    // TODO(future): fallback to userspace proxy when no backend are available

    None
}
