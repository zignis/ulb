use aya_ebpf::{
    bindings::BPF_NOEXIST,
    programs::SkBuffContext,
};
use ulb_common::SocketCookie;

use crate::{
    debug,
    maps::{
        BACKEND_CONNECTION_POOL_TABLE,
        CLUSTER_TABLE,
        SESSION_MAP,
    },
};

const MAX_BACKEND_SELECT_ATTEMPTS: u32 = 8;
const MAX_CONNECTION_SELECT_ATTEMPTS: u32 = 4;

#[inline(always)]
fn claim_connection(
    ctx: &SkBuffContext,
    pool_idx: u32,
    client_cookie: SocketCookie,
) -> Option<SocketCookie> {
    let pool = BACKEND_CONNECTION_POOL_TABLE.get_ptr_mut(pool_idx)?;
    let pool_len = unsafe { (*pool).connections.len };

    if pool_len == 0 {
        return None;
    }

    // TODO: make this atomic
    let counter = unsafe { &mut (*pool).rr_counter };
    let start_idx = *counter % pool_len;
    *counter = counter.wrapping_add(1);

    // search for idle connection in pool
    for i in 0..MAX_CONNECTION_SELECT_ATTEMPTS {
        let cookie_idx = (start_idx + i) % pool_len;
        let cookie = unsafe { (*pool).connections.data.get(cookie_idx as usize) }?;

        if SESSION_MAP
            .insert(
                cookie,
                client_cookie,
                BPF_NOEXIST as u64, // atomically claim the backend socket for this client
            )
            .is_ok()
        {
            debug!(ctx, "claimed backend {} from pool {}", *cookie, pool_idx);
            return Some(*cookie);
        }
    }

    None
}

pub fn select_backend(
    ctx: &SkBuffContext,
    cluster_idx: u32,
    client_cookie: SocketCookie,
) -> Result<SocketCookie, ()> {
    let cluster = CLUSTER_TABLE.get_ptr_mut(cluster_idx).ok_or(())?;
    let len = unsafe { (*cluster).backends.len };

    debug!(ctx, "cluster {} has {} backends", cluster_idx, len);

    if len == 0 {
        return Err(());
    }

    // TODO: make this atomic
    let counter = unsafe { &mut (*cluster).rr_counter };
    let start_idx = *counter % len;
    *counter = counter.wrapping_add(1);

    // search for idle backend
    for i in 0..MAX_BACKEND_SELECT_ATTEMPTS {
        let idx = (start_idx + i) % len;

        if let Some(backend) = unsafe { (*cluster).backends.data.get(idx as usize) } {
            if let Some(cookie) = claim_connection(ctx, backend.pool_idx, client_cookie) {
                return Ok(cookie);
            }
        }
    }

    debug!(ctx, "no backend available");

    // TODO(future): fallback to userspace proxy when no backend are available

    Err(())
}
