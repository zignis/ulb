pub type SocketCookie = u64;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct SessionTarget {
    // 8B align
    pub cookie: SocketCookie,
    // 8B align
    pub pool_idx: u32, // idx into BACKEND_CONNECTION_POOL_TABLE
    pub flags: u32,
}

#[repr(u32)]
#[derive(Debug)]
enum Flag {
    UpdateActiveConnections = 1 << 0,
    IsBackendCookie         = 1 << 1,
}

impl SessionTarget {
    #[inline(always)]
    pub fn new(
        cookie: SocketCookie,
        pool_idx: u32,
        update_active_connections: bool,
        is_backend_cookie: bool,
    ) -> Self {
        let mut flags = 0;

        if update_active_connections {
            flags |= Flag::UpdateActiveConnections as u32;
        }

        if is_backend_cookie {
            flags |= Flag::IsBackendCookie as u32;
        }

        Self {
            cookie,
            pool_idx,
            flags,
        }
    }

    #[inline(always)]
    pub fn update_active_connections(&self) -> bool {
        (self.flags & Flag::UpdateActiveConnections as u32) != 0
    }

    #[inline(always)]
    pub fn is_backend_cookie(&self) -> bool {
        (self.flags & Flag::IsBackendCookie as u32) != 0
    }
}

#[repr(transparent)]
#[derive(Debug, Copy, Clone)]
pub struct ResidentTarget(pub u64);

impl ResidentTarget {
    #[inline(always)]
    pub fn new(cluster_idx: u32, backend_idx: u32) -> Self {
        Self(((cluster_idx as u64) << 32) | (backend_idx as u64))
    }

    #[inline(always)]
    pub fn cluster_idx(&self) -> u32 {
        (self.0 >> 32) as u32
    }

    #[inline(always)]
    pub fn backend_idx(&self) -> u32 {
        self.0 as u32
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for SessionTarget {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ResidentTarget {}
