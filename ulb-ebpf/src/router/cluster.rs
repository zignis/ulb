use ulb_common::SocketCookie;

use crate::CLUSTER_TABLE;

pub fn select_backend(cluster_idx: u32) -> Result<SocketCookie, ()> {
    let ptr = CLUSTER_TABLE.get_ptr_mut(cluster_idx).ok_or(())?;
    let cluster = unsafe { &mut *ptr };

    if cluster.endpoints.len == 0 {
        return Err(());
    }

    // TODO: very crude way to choose a backend using rr
    let idx = cluster.rr_counter % cluster.endpoints.len;

    if (idx as usize) >= cluster.endpoints.data.len() {
        return Err(());
    }

    cluster.rr_counter = (idx + 1) % cluster.endpoints.len;
    Ok(cluster.endpoints.data[idx as usize].cookie)
}
