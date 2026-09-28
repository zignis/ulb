use core::ffi::{
    c_long,
    c_void,
};

use aya_ebpf::{
    bindings::{
        BPF_EXIST,
        BPF_NOEXIST,
    },
    btf_maps::Queue,
    helpers::{
        bpf_get_prandom_u32,
        bpf_loop,
    },
    programs::SkBuffContext,
};
use ulb_common::{
    containers::BoundedVec,
    ir::{
        Backend,
        Cluster,
        LoadBalancingPolicy,
        MAX_BACKEND_CONNECTION_POOL_SIZE,
        MAX_BACKENDS_PER_CLUSTER,
    },
    session::{
        SessionTarget,
        SocketCookie,
    },
};

use crate::{
    BPF_LOOP_NEXT,
    BPF_LOOP_STOP,
    debug,
    error,
    maps::{
        BACKEND_CONNECTION_MAP,
        BACKEND_CONNECTION_POOL_STATS_TABLE,
        BACKEND_CONNECTION_POOL_TABLE,
        CLUSTER_TABLE,
        SESSION_MAP,
    },
    utils::{
        bpf_map_exists_key,
        incr_pool_active_connections,
    },
    warn,
};

/// https://github.com/torvalds/linux/blob/587858367581b9c55c3690f4e63382ad622719d4/include/linux/socket.h#L207
const AF_INET: u32 = 2;

/// https://github.com/torvalds/linux/blob/587858367581b9c55c3690f4e63382ad622719d4/include/linux/socket.h#L215
const AF_INET6: u32 = 10;

pub enum ResolveBackendError {
    PoolExhausted { backend_idx: u32 },
    Internal,
}

struct SessionCtx<'a> {
    skb_ctx: &'a SkBuffContext,
    pool_idx: u32,
    client_cookie: SocketCookie,
    needs_connection_update: bool,
    queue: &'a Queue<SocketCookie, MAX_BACKEND_CONNECTION_POOL_SIZE>,
    created: Option<SocketCookie>,
}

extern "C" fn create_session(_idx: u32, ctx: *mut c_void) -> c_long {
    let ctx = unsafe { &mut *(ctx as *mut SessionCtx) };
    let cookie = match ctx.queue.pop().ok().flatten() {
        Some(x) => x,
        None => return BPF_LOOP_STOP,
    };

    if !bpf_map_exists_key(
        &BACKEND_CONNECTION_MAP as *const _ as *mut c_void,
        &cookie as *const _ as *const c_void,
    ) {
        return BPF_LOOP_NEXT; // dead connection; discard cookie
    }

    if SESSION_MAP
        .insert(
            cookie,
            SessionTarget::new(
                ctx.client_cookie,
                ctx.pool_idx,
                ctx.needs_connection_update,
                false,
            ),
            BPF_NOEXIST as u64, // atomically claim the backend socket for this client
        )
        .is_ok()
    {
        if ctx.needs_connection_update {
            incr_pool_active_connections(ctx.pool_idx);
        }

        debug!(
            ctx.skb_ctx,
            "[D:3] claimed backend (CK:{}) from pool {}", cookie, ctx.pool_idx
        );

        ctx.created = Some(cookie);
        return BPF_LOOP_STOP;
    }

    // put back in queue if insert failed
    #[allow(unused_variables)]
    if let Err(eno) = ctx.queue.push(cookie, BPF_EXIST as u64) {
        error!(ctx.skb_ctx, "[E:3] failed to push to queue: {}", eno);
    }

    BPF_LOOP_NEXT
}

//

struct SelectBackendCtx<'a> {
    skb_ctx: &'a SkBuffContext,
    cluster: *mut Cluster,
    backend_idx: u32,
    client_cookie: SocketCookie,
    needs_connection_update: bool,
    selected: Option<(SocketCookie, u32)>,
}

extern "C" fn select_backend(itr: u32, ctx: *mut c_void) -> c_long {
    let ctx = unsafe { &mut *(ctx as *mut SelectBackendCtx) };
    let len = unsafe { (*ctx.cluster).backends.len } as u32;

    if len == 0 {
        return BPF_LOOP_STOP;
    }

    let idx = (ctx.backend_idx + itr) % len;
    let backend = match unsafe { (*ctx.cluster).backends.data.get(idx as usize) } {
        Some(x) => x,
        None => return BPF_LOOP_STOP,
    };

    let queue = match BACKEND_CONNECTION_POOL_TABLE.get(backend.pool_idx) {
        Some(x) => x,
        None => return BPF_LOOP_STOP,
    };

    let mut session_ctx = SessionCtx {
        skb_ctx: ctx.skb_ctx,
        pool_idx: backend.pool_idx,
        client_cookie: ctx.client_cookie,
        needs_connection_update: ctx.needs_connection_update,
        queue,
        created: None,
    };

    let session_ret = unsafe {
        bpf_loop(
            MAX_BACKEND_CONNECTION_POOL_SIZE as u32,
            create_session as *mut c_void,
            &mut session_ctx as *mut SessionCtx as *mut c_void,
            0,
        )
    };

    if session_ret < 0 {
        return BPF_LOOP_STOP;
    }

    if let Some(cookie) = session_ctx.created {
        ctx.selected = Some((cookie, backend.pool_idx));
        return BPF_LOOP_STOP;
    }

    BPF_LOOP_NEXT
}

#[inline(always)]
pub fn resolve_backend(
    ctx: &SkBuffContext,
    cluster_idx: u32,
    client_cookie: SocketCookie,
) -> Result<(SocketCookie, u32, bool), ResolveBackendError> {
    let cluster = match CLUSTER_TABLE.get_ptr_mut(cluster_idx) {
        Some(x) => x,
        None => return Err(ResolveBackendError::Internal),
    };
    let len = unsafe { (*cluster).backends.len } as u32;
    let mut needs_connection_update = false;

    debug!(ctx, "[D:3] cluster {} has {} backends", cluster_idx, len);

    if len == 0 {
        return Err(ResolveBackendError::Internal);
    }

    let backend_idx = match unsafe { (*cluster).policy } {
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
                let backend_idx = *counter % len;
                *counter = counter.wrapping_add(1);
                backend_idx
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

                idx.min((len as usize).saturating_sub(1)) as u32
            }
        }

        LoadBalancingPolicy::LeastLoaded => {
            needs_connection_update = true;

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

    let mut backend_ctx = SelectBackendCtx {
        skb_ctx: ctx,
        cluster,
        backend_idx,
        client_cookie,
        needs_connection_update,
        selected: None,
    };

    let backend_ret = unsafe {
        bpf_loop(
            MAX_BACKENDS_PER_CLUSTER as u32,
            select_backend as *mut c_void,
            &mut backend_ctx as *mut SelectBackendCtx as *mut c_void,
            0,
        )
    };

    if backend_ret < 0 {
        return Err(ResolveBackendError::Internal);
    }

    if let Some((cookie, pool_idx)) = backend_ctx.selected {
        return Ok((cookie, pool_idx, needs_connection_update));
    }

    warn!(
        ctx,
        "[W:3] no backend connection available, adding to resident queue"
    );

    Err(ResolveBackendError::PoolExhausted { backend_idx })
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
    let active = match BACKEND_CONNECTION_POOL_STATS_TABLE.get_ptr(backend.pool_idx) {
        Some(pool) => unsafe { (*pool).active_connections },
        None => u64::MAX,
    };

    (active, weight)
}
