pub type SocketCookie = u64;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct SessionTarget {
    // 8B align
    pub cookie: SocketCookie,
    pub pool_idx: u64,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for SessionTarget {}
