pub const VHOST_MAX_LEN: usize = 64;
pub const PATH_MAX_LEN: usize = 128;
pub const MAX_VHOSTS: u32 = 64;
pub const MAX_ROUTES: u32 = 4096;
pub const MAX_ROUTES_PER_VHOST: u32 = 64;
pub const MAX_BACKEND_CLUSTERS: u32 = 256;
pub const MAX_BACKENDS_PER_CLUSTER: usize = 32;

pub mod cluster;
pub mod route;
pub mod vhost;

pub use cluster::*;
pub use route::*;
pub use vhost::*;
