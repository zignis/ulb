use crate::CLUSTER_TABLE;

pub fn select_backend(cluster_idx: u32) -> Result<u32, ()> {
    let ptr = CLUSTER_TABLE.get_ptr_mut(cluster_idx).ok_or(())?;
    let cluster = unsafe { &mut *ptr };

    if cluster.endpoints.is_empty() {
        return Err(());
    }

    // TODO: very crude way to choose a backend using rr
    let idx = cluster.rr_counter % cluster.endpoints.len;
    cluster.rr_counter = (idx + 1) % cluster.endpoints.len;
    Ok(cluster.endpoints[idx as usize].sock_map_idx)
}
