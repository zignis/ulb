use aya_ebpf::{
    bindings::BPF_NOEXIST,
    programs::SkBuffContext,
};
use ulb_common::{
    SESSION_ENTRY_CLIENT,
    SocketCookie,
    ir::MAX_BACKENDS_PER_CLUSTER,
};

use crate::{
    debug,
    maps::{
        CLUSTER_TABLE,
        SESSION_MAP,
    },
};

pub fn select_backend(
    ctx: &SkBuffContext,
    cluster_idx: u32,
    client_cookie: SocketCookie,
) -> Result<SocketCookie, ()> {
    let cluster = CLUSTER_TABLE.get_ptr_mut(cluster_idx).ok_or(())?;
    let len = unsafe { (*cluster).endpoints.len };

    debug!(ctx, "cluster {} has {} endpoints", cluster_idx, len);

    if len == 0 {
        return Err(());
    }

    // TODO: make this atomic since counter can be updated from multiple CPUs
    let counter = unsafe { &mut (*cluster).rr_counter };
    let start_idx = *counter % len;
    *counter = counter.wrapping_add(1);

    for i in 0..MAX_BACKENDS_PER_CLUSTER {
        if i as u32 >= len {
            break;
        }

        let idx = (start_idx + i as u32) % len;

        if let Some(endpoint) = unsafe { (*cluster).endpoints.data.get(idx as usize) } {
            let cookie = endpoint.cookie;

            if SESSION_MAP
                .insert(
                    &cookie,
                    &[client_cookie, SESSION_ENTRY_CLIENT],
                    BPF_NOEXIST as u64, // atomically claim the backend socket for this client
                )
                .is_ok()
            {
                debug!(ctx, "claimed backend {}", cookie);
                return Ok(cookie);
            }
        }
    }

    debug!(ctx, "no backend available");

    // TODO(future): fallback to userspace proxy when no backend are available

    Err(())
}
