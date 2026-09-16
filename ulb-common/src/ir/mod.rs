pub const MAX_LISTENERS: usize = 256;
pub const MAX_VHOSTS: u32 = 32;
pub const MAX_ROUTES_PER_VHOST: u32 = 64;
pub const MAX_ROUTES: u32 = MAX_VHOSTS * MAX_ROUTES_PER_VHOST;
pub const MAX_HEADER_RULES_PER_ROUTE: usize = u32::BITS as usize; // must fit in the mask
pub const MAX_HEADER_RULES: u32 = MAX_ROUTES * MAX_HEADER_RULES_PER_ROUTE as u32;

pub const MAX_CLUSTERS: u32 = 64;
pub const MAX_BACKENDS_PER_CLUSTER: usize = 64;
pub const MAX_BACKEND_CONNECTION_POOL_SIZE: usize = 1024;
pub const MAX_BACKEND_CONNECTION_POOLS: u32 = (MAX_BACKENDS_PER_CLUSTER as u32) * MAX_CLUSTERS;

pub const MAX_CLIENT_CONNECTIONS: u32 = 1024;
pub const MAX_BACKEND_CONNECTIONS: u32 = 1024;
pub const MAX_SESSIONS: u32 = 4096; // maximum client-backend sessions for a given instant

pub const MAX_TCP_PORTS: u32 = 65536;
pub const LISTEN_BACKLOG_QUEUE_SIZE: u32 = 1024; // listener socket queue size
pub const DEFAULT_BACKEND_WEIGHT: u32 = 1;

pub mod cluster;
pub mod header;
pub mod route;
pub mod vhost;

pub use cluster::*;
pub use header::*;
pub use route::*;
pub use vhost::*;
