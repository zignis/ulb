use crate::{
    maps::BACKEND_CONNECTION_POOL_STATS_TABLE,
    utils::{
        atomic_add_i64,
        atomic_add_u64,
    },
};

#[inline(always)]
pub fn incr_pool_active_connections(pool_idx: u32) {
    if let Some(stats) = BACKEND_CONNECTION_POOL_STATS_TABLE.get_ptr_mut(pool_idx) {
        unsafe {
            atomic_add_u64(&raw mut (*stats).active_connections, 1);
        }
    }
}

#[inline(always)]
pub fn decr_pool_active_connections(pool_idx: u32) {
    if let Some(stats) = BACKEND_CONNECTION_POOL_STATS_TABLE.get_ptr_mut(pool_idx) {
        unsafe { atomic_add_i64((&raw mut (*stats).active_connections) as *mut i64, -1) };
    }
}
