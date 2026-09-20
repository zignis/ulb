use ulb_common::session::SocketCookie;

use crate::{
    maps::{
        BACKEND_CONNECTION_POOL_TABLE,
        SESSION_MAP,
    },
    utils::atomic_add_i64,
};

#[inline(always)]
pub fn remove_session_mapping(cookie: &SocketCookie) {
    if let Some(target) = unsafe { SESSION_MAP.get(cookie) } {
        if target.update_active_connections == 1
            && let Some(pool) = BACKEND_CONNECTION_POOL_TABLE.get_ptr_mut(target.pool_idx)
        {
            unsafe { atomic_add_i64((&raw mut (*pool).active_connections) as *mut i64, -1) };
        }

        let _ = SESSION_MAP.remove(cookie);
        let _ = SESSION_MAP.remove(target.cookie);
    }
}
