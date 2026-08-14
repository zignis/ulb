use aya_ebpf::{
    macros::map,
    maps::{
        Array,
        HashMap,
        PerCpuArray,
        ProgramArray,
        SockHash,
    },
};
use ulb_common::{
    HttpRequest,
    JMP_PROG_COUNT,
    SessionEntry,
    SocketCookie,
    ir::{
        BackendCluster,
        MAX_BACKEND_CONNECTIONS,
        MAX_CLIENT_CONNECTIONS,
        MAX_CLUSTERS,
        MAX_ROUTES,
        MAX_SESSIONS,
        MAX_TCP_PORTS,
        MAX_VHOSTS,
        RouteValue,
        VHostKey,
        VHostValue,
    },
};

#[map]
pub static JMP_TABLE: ProgramArray = ProgramArray::with_max_entries(JMP_PROG_COUNT, 0);

//

/// shared per-cpu slot holding the parsed http request for the current request
#[map]
pub static HTTP_REQ_BUF: PerCpuArray<HttpRequest> = PerCpuArray::with_max_entries(1, 0);

//

#[map]
pub static BACKEND_CONNECTION_MAP: SockHash<SocketCookie> =
    SockHash::with_max_entries(MAX_BACKEND_CONNECTIONS, 0);

#[map]
pub static CLIENT_CONNECTION_MAP: SockHash<SocketCookie> =
    SockHash::with_max_entries(MAX_CLIENT_CONNECTIONS, 0);

#[map]
pub static SESSION_MAP: HashMap<SocketCookie, SessionEntry> =
    HashMap::with_max_entries(MAX_SESSIONS, 0);

#[map]
pub static VHOST_MAP: HashMap<VHostKey, VHostValue> = HashMap::with_max_entries(MAX_VHOSTS, 0);

#[map]
pub static ROUTE_TABLE: Array<RouteValue> = Array::with_max_entries(MAX_ROUTES, 0);

#[map]
pub static CLUSTER_TABLE: Array<BackendCluster> = Array::with_max_entries(MAX_CLUSTERS, 0);

//

#[map]
pub static LISTENER_PORTS: Array<u8> = Array::with_max_entries(MAX_TCP_PORTS, 0);
