pub const PATH_MAX_LEN: usize = 128;
pub const MAX_VHOSTS: u32 = 64;
pub const MAX_ROUTES: u32 = 4096;
pub const MAX_ROUTES_PER_VHOST: u32 = 64;
pub const MAX_CLUSTERS: u32 = 256;
pub const MAX_BACKENDS_PER_CLUSTER: usize = 512;

pub const MAX_LISTENER_PORTS: u32 = 1024; // listener ports defined in the config
pub const MAX_BACKEND_PORTS: u32 = 1024; // backend ports defined in the config
pub const MAX_CONNECTIONS: u32 = 1024; // maximum client connections
pub const MAX_SESSIONS: u32 = 4096; // maximum client-backend sessions for a given instant

pub const LISTEN_BACKLOG_QUEUE_SIZE: u32 = 1024; // listener socket queue size

pub mod cluster;
pub mod route;
pub mod vhost;

pub use cluster::*;
pub use route::*;
pub use vhost::*;
