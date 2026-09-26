use aya_ebpf::bindings::BPF_EXIST;
use ulb_common::session::SocketCookie;

use crate::{
    maps::{
        BACKEND_CONNECTION_POOL_TABLE,
        SESSION_MAP,
    },
    utils::decr_pool_active_connections,
};

#[inline(always)]
pub fn remove_session_mapping(cookie: &SocketCookie, recycle_backend: bool) {
    if let Some(target) = unsafe { SESSION_MAP.get(cookie) } {
        if target.update_active_connections() {
            decr_pool_active_connections(target.pool_idx);
        }

        if recycle_backend {
            let backend_cookie = if target.is_backend_cookie() {
                &target.cookie
            } else {
                cookie
            };

            if let Some(queue) = BACKEND_CONNECTION_POOL_TABLE.get(target.pool_idx) {
                let _ = queue.push(backend_cookie, BPF_EXIST as u64);
            }
        }

        let _ = SESSION_MAP.remove(cookie);
        let _ = SESSION_MAP.remove(target.cookie);
    }
}
