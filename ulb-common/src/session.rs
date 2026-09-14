pub type SocketCookie = u64;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct SessionTarget {
    // 8B align
    pub cookie: SocketCookie,
    // 8B align
    pub pool_idx: u32,                  // idx into BACKEND_CONNECTION_POOL_TABLE
    pub update_active_connections: u32, // logically a bool value
}

impl SessionTarget {
    pub fn new(cookie: SocketCookie, pool_idx: u32, update_active_connections: bool) -> Self {
        Self {
            cookie,
            pool_idx,
            update_active_connections: u32::from(update_active_connections),
        }
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for SessionTarget {}
