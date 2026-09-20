use aya_ebpf::{
    bindings::BPF_NOEXIST,
    helpers::bpf_get_prandom_u32,
    programs::SkBuffContext,
};
use ulb_common::{
    containers::BoundedVec,
    ir::{
        Backend,
        LoadBalancingPolicy,
        MAX_BACKENDS_PER_CLUSTER,
    },
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

/// https://github.com/torvalds/linux/blob/587858367581b9c55c3690f4e63382ad622719d4/include/linux/socket.h#L207
const AF_INET: u32 = 2;

/// https://github.com/torvalds/linux/blob/587858367581b9c55c3690f4e63382ad622719d4/include/linux/socket.h#L215
const AF_INET6: u32 = 10;

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

#[inline(always)]
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

        LoadBalancingPolicy::IpHash => {
            let ip = match ctx.skb.family() {
                AF_INET => ctx.skb.remote_ipv4(),
                AF_INET6 => {
                    let ip = ctx.skb.remote_ipv6();
                    ip[0] ^ ip[1] ^ ip[2] ^ ip[3] // 4 octets
                }
                _ => 0,
            };

            ip % len
        }

        LoadBalancingPolicy::RoundRobin => {
            if unsafe { (*cluster).uniform_weight } == 1 {
                let counter = unsafe { &mut (*cluster).rr_counter };
                let start_idx = *counter % len;
                *counter = counter.wrapping_add(1);
                start_idx
            } else {
                let counter = unsafe { &mut (*cluster).rr_counter };
                let target = *counter % unsafe { (*cluster).total_weight }.max(1);
                *counter = counter.wrapping_add(1);
                let mut weight = 0;
                let mut idx = 0;

                while idx < MAX_BACKENDS_PER_CLUSTER {
                    if idx >= len as usize {
                        break;
                    }

                    if let Some(backend) = unsafe { (*cluster).backends.data.get(idx) } {
                        weight += backend.weight;

                        if weight > target {
                            break;
                        }
                    }

                    idx += 1;
                }

                idx as u32
            }
        }

        LoadBalancingPolicy::LeastLoaded => {
            update_active_connections = true;

            if len == 1 {
                0
            } else {
                let idx1 = unsafe { bpf_get_prandom_u32() } % len;
                let mut idx2 = unsafe { bpf_get_prandom_u32() } % (len - 1);

                if idx2 >= idx1 {
                    idx2 += 1;
                }

                let (active1, w1) =
                    get_backend_stats(unsafe { &(*cluster).backends }, idx1 as usize);
                let (active2, w2) =
                    get_backend_stats(unsafe { &(*cluster).backends }, idx2 as usize);

                if active2 == u64::MAX {
                    idx1
                } else if active1 == u64::MAX {
                    idx2
                } else if unsafe { (*cluster).uniform_weight } == 1 {
                    if active1 <= active2 { idx1 } else { idx2 }
                } else if active1 * w2 <= active2 * w1 {
                    idx1
                } else {
                    idx2
                }
            }
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

#[inline(always)]
fn get_backend_stats(
    backends: &BoundedVec<Backend, MAX_BACKENDS_PER_CLUSTER>,
    idx: usize,
) -> (u64, u64) {
    if idx >= MAX_BACKENDS_PER_CLUSTER {
        return (u64::MAX, 1);
    }

    let backend = match backends.data.get(idx) {
        Some(backend) => backend,
        None => return (u64::MAX, 1),
    };
    let weight = backend.weight as u64;
    let active = match BACKEND_CONNECTION_POOL_TABLE.get_ptr(backend.pool_idx) {
        Some(pool) => unsafe { (*pool).active_connections },
        None => u64::MAX,
    };

    (active, weight)
}
