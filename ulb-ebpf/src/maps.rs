use aya_ebpf::{
    bindings::{
        BPF_F_RDONLY_PROG,
        BPF_F_WRONLY,
        BPF_F_WRONLY_PROG,
    },
    btf_maps::{
        Queue,
        of_maps::ArrayOfMaps,
    },
    macros::{
        btf_map,
        map,
    },
    maps::{
        Array,
        HashMap,
        PerCpuArray,
        ProgramArray,
        SockHash,
    },
};
use ulb_common::{
    JMP_PROG_COUNT,
    http::{
        HTTP_HDR_KEY_MAX_LEN,
        HttpRequest,
    },
    ir::{
        BackendConnectionPoolStats,
        Cluster,
        DEFAULT_MAX_RESIDENT_CONNECTIONS,
        HeaderRule,
        MAX_BACKEND_CONNECTION_POOL_SIZE,
        MAX_BACKEND_CONNECTION_POOLS,
        MAX_BACKEND_CONNECTIONS,
        MAX_CLIENT_CONNECTIONS,
        MAX_CLUSTERS,
        MAX_HEADER_RULES,
        MAX_ROUTES,
        MAX_SESSIONS,
        MAX_TCP_PORTS,
        MAX_VHOSTS,
        RouteValue,
        VHostKey,
        VHostValue,
    },
    session::{
        ResidentTarget,
        SessionTarget,
        SocketCookie,
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
pub static SESSION_MAP: HashMap<SocketCookie, SessionTarget> =
    HashMap::with_max_entries(MAX_SESSIONS, 0);

#[map]
pub static RESIDUAL_CONNECTION_MAP: HashMap<SocketCookie, ResidentTarget> =
    HashMap::with_max_entries(DEFAULT_MAX_RESIDENT_CONNECTIONS, BPF_F_WRONLY_PROG);

#[map]
pub static VHOST_MAP: HashMap<VHostKey, VHostValue> =
    HashMap::with_max_entries(MAX_VHOSTS, BPF_F_WRONLY | BPF_F_RDONLY_PROG);

#[map]
pub static ROUTE_TABLE: Array<RouteValue> =
    Array::with_max_entries(MAX_ROUTES, BPF_F_WRONLY | BPF_F_RDONLY_PROG);

#[map]
pub static CLUSTER_TABLE: Array<Cluster> = Array::with_max_entries(MAX_CLUSTERS, BPF_F_WRONLY);

#[map]
pub static HEADER_RULE_TABLE: Array<HeaderRule> =
    Array::with_max_entries(MAX_HEADER_RULES, BPF_F_WRONLY | BPF_F_RDONLY_PROG);

/// {key name, index into HEADER_RULE_TABLE}
#[map]
pub static HEADER_KEY_MAP: HashMap<[u8; HTTP_HDR_KEY_MAX_LEN], u64> =
    HashMap::with_max_entries(MAX_HEADER_RULES, BPF_F_WRONLY | BPF_F_RDONLY_PROG);

#[btf_map]
pub static BACKEND_CONNECTION_POOL_TABLE: ArrayOfMaps<
    Queue<SocketCookie, MAX_BACKEND_CONNECTION_POOL_SIZE>,
    { MAX_BACKEND_CONNECTION_POOLS as usize },
> = ArrayOfMaps::new();

#[map]
pub static BACKEND_CONNECTION_POOL_STATS_TABLE: Array<BackendConnectionPoolStats> =
    Array::with_max_entries(MAX_BACKEND_CONNECTION_POOLS, 0);

//

#[map]
pub static LISTENER_PORTS: Array<u8> =
    Array::with_max_entries(MAX_TCP_PORTS, BPF_F_WRONLY | BPF_F_RDONLY_PROG);
