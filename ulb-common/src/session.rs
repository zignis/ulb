pub type SocketCookie = u64;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct SessionTarget {
    // 8B align
    pub cookie: SocketCookie,
    pub pool_idx: u64, // idx into BACKEND_CONNECTION_POOL_TABLE
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for SessionTarget {}
