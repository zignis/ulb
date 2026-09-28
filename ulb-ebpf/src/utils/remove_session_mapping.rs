use ulb_common::session::SocketCookie;

use crate::{
    maps::SESSION_MAP,
    utils::decr_pool_active_connections,
};

#[inline(always)]
pub fn remove_session_mapping(cookie: &SocketCookie) {
    if let Some(target) = SESSION_MAP.get_ptr_mut(cookie) {
        if unsafe { (*target).needs_connection_update() } {
            decr_pool_active_connections(unsafe { (*target).pool_idx });
        }

        let _ = SESSION_MAP.remove(cookie);
        let _ = SESSION_MAP.remove(unsafe { (*target).cookie });
    }
}
