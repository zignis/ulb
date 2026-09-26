pub const MAX_LISTENERS: usize = 1 << 8;
pub const MAX_VHOSTS: u32 = 1 << 5;
pub const MAX_ROUTES_PER_VHOST: u32 = 1 << 6;
pub const MAX_ROUTES: u32 = MAX_VHOSTS * MAX_ROUTES_PER_VHOST;
pub const MAX_HEADER_RULES_PER_ROUTE: usize = u32::BITS as usize; // must fit in the mask
pub const MAX_HEADER_RULES: u32 = MAX_ROUTES * MAX_HEADER_RULES_PER_ROUTE as u32;

pub const MAX_CLUSTERS: u32 = 1 << 6;
pub const MAX_BACKENDS_PER_CLUSTER: usize = 1 << 6;
pub const MAX_BACKEND_CONNECTION_POOL_SIZE: usize = 1 << 16;
pub const MAX_BACKEND_CONNECTION_POOLS: u32 = (MAX_BACKENDS_PER_CLUSTER as u32) * MAX_CLUSTERS;

pub const MAX_CLIENT_CONNECTIONS: u32 = 1 << 16;
pub const MAX_BACKEND_CONNECTIONS: u32 = 1 << 16;
pub const MAX_SESSIONS: u32 = MAX_CLIENT_CONNECTIONS * 2; // maximum client-backend sessions for a given instant
pub const DEFAULT_MAX_RESIDENT_CONNECTIONS: u32 = 1 << 10;

pub const MAX_TCP_PORTS: u32 = 1 << 16;
pub const LISTEN_BACKLOG_QUEUE_SIZE: u32 = 1 << 10; // listener socket queue size
pub const DEFAULT_BACKEND_WEIGHT: u32 = 1;

mod cluster;
mod header;
mod route;
mod vhost;

pub use cluster::*;
pub use header::*;
pub use route::*;
pub use vhost::*;
