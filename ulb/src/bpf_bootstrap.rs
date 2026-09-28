use std::{
    cmp::max,
    fs::File,
};

use anyhow::anyhow;
use aya::{
    Ebpf,
    EbpfLoader,
    maps::{
        Array,
        HashMap,
        MapData,
        ProgramArray,
        Queue,
        SockHash,
        of_maps::ArrayOfMaps,
    },
    programs::{
        CgroupAttachMode,
        SkSkb,
        SockOps,
    },
};
#[cfg(feature = "debug")]
use aya_log::EbpfLogger;
#[cfg(feature = "debug")]
use tokio::{
    io::{
        Interest,
        unix::AsyncFd,
    },
    task,
};
use ulb_common::{
    JmpProg,
    http::HTTP_HDR_KEY_MAX_LEN,
    ir::{
        BackendConnectionPoolStats,
        Cluster,
        DEFAULT_MAX_RESIDENT_CONNECTIONS,
        HeaderRule,
        RouteValue,
        VHostKey,
        VHostValue,
    },
    session::{
        ResidentTarget,
        SocketCookie,
    },
};

#[cfg(feature = "debug")]
use crate::telemetry::bpf_log_closure;

pub(crate) type ClientConnectionMap = SockHash<MapData, SocketCookie>;
pub(crate) type BackendConnectionMap = SockHash<MapData, SocketCookie>;
pub(crate) type BackendConnectionPoolQueue = Queue<MapData, SocketCookie>;
pub(crate) type BackendConnectionPoolTable = ArrayOfMaps<MapData, BackendConnectionPoolQueue>;
pub(crate) type BackendConnectionPoolStatsTable = Array<MapData, BackendConnectionPoolStats>;
pub(crate) type VHostMap = HashMap<MapData, VHostKey, VHostValue>;
pub(crate) type RouteTable = Array<MapData, RouteValue>;
pub(crate) type ClusterTable = Array<MapData, Cluster>;
pub(crate) type HeaderRuleTable = Array<MapData, HeaderRule>;
pub(crate) type HeaderKeyMap = HashMap<MapData, [u8; HTTP_HDR_KEY_MAX_LEN], u64>;
pub(crate) type ResidualConnectionMap = HashMap<MapData, SocketCookie, ResidentTarget>;

#[allow(dead_code)]
pub struct BpfState {
    pub ebpf: Ebpf,
    pub client_connection_map: ClientConnectionMap,
    pub backend_connection_map: BackendConnectionMap,
    pub listener_ports: Array<MapData, u8>,
    pub backend_connection_pool_table: BackendConnectionPoolTable,
    pub backend_connection_pool_stats_table: BackendConnectionPoolStatsTable,
    pub vhost_map: VHostMap,
    pub route_table: RouteTable,
    pub cluster_table: ClusterTable,
    pub header_rule_table: HeaderRuleTable,
    pub header_key_map: HeaderKeyMap,
    pub residual_connection_map: ResidualConnectionMap,
    pub jmp_table: ProgramArray<MapData>,
}

pub const BPF_EXIST: u64 = 2; // for bpf queue

pub fn bootstrap_bpf(
    cgroup_path: &str,
    max_resident_connections: Option<u32>,
) -> anyhow::Result<BpfState> {
    let residual_capacity = max_resident_connections.unwrap_or(DEFAULT_MAX_RESIDENT_CONNECTIONS);
    let mut ebpf = EbpfLoader::new()
        .map_max_entries(
            "RESIDUAL_CONNECTION_MAP",
            max(1, residual_capacity), // map needs at-least one element
        )
        .load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/ulb"
        )))?;

    #[cfg(feature = "debug")]
    match EbpfLogger::init(&mut ebpf) {
        Err(err) => log::warn!("failed to initialize ebpf logger: {err}"),
        Ok(logger) => {
            let mut logger = AsyncFd::with_interest(logger, Interest::READABLE)?;
            task::spawn(async move {
                loop {
                    match logger.readable_mut().await {
                        Ok(mut x) => {
                            bpf_log_closure(|| x.get_inner_mut().flush());
                            x.clear_ready();
                        }
                        Err(err) => {
                            log::warn!("ebpf logger error: {err}");
                            break;
                        }
                    }
                }
            });
        }
    }

    let client_connection_map: SockHash<_, SocketCookie> = SockHash::try_from(
        ebpf.take_map("CLIENT_CONNECTION_MAP")
            .ok_or_else(|| anyhow!("missing `CLIENT_CONNECTION_MAP`"))?,
    )?;

    let backend_connection_map: SockHash<_, SocketCookie> = SockHash::try_from(
        ebpf.take_map("BACKEND_CONNECTION_MAP")
            .ok_or_else(|| anyhow!("missing `BACKEND_CONNECTION_MAP`"))?,
    )?;

    let parser: &mut SkSkb = ebpf
        .program_mut("ulb_stream_parser")
        .ok_or_else(|| anyhow!("missing `ulb_stream_parser` prog"))?
        .try_into()?;
    parser.load()?;
    parser.attach(client_connection_map.fd())?;

    let client_verdict: &mut SkSkb = ebpf
        .program_mut("ulb_client_stream_verdict")
        .ok_or_else(|| anyhow!("missing `ulb_client_stream_verdict` prog"))?
        .try_into()?;
    client_verdict.load()?;
    client_verdict.attach(client_connection_map.fd())?;

    let backend_verdict: &mut SkSkb = ebpf
        .program_mut("ulb_backend_stream_verdict")
        .ok_or_else(|| anyhow!("missing `ulb_backend_stream_verdict` prog"))?
        .try_into()?;
    backend_verdict.load()?;
    backend_verdict.attach(backend_connection_map.fd())?;

    // tail call programs

    let mut jmp_table: ProgramArray<_> = ProgramArray::try_from(
        ebpf.take_map("JMP_TABLE")
            .ok_or_else(|| anyhow!("missing `JMP_TABLE`"))?,
    )?;

    let router: &mut SkSkb = ebpf
        .program_mut("ulb_router")
        .ok_or_else(|| anyhow!("missing `ulb_router` prog"))?
        .try_into()?;
    router.load()?;

    jmp_table.set(
        JmpProg::Router as u32,
        router
            .fd()
            .map_err(|_| anyhow!("failed to set route tail prog"))?,
        0,
    )?;

    let header_parser: &mut SkSkb = ebpf
        .program_mut("ulb_header_parser")
        .ok_or_else(|| anyhow!("missing `ulb_header_parser` prog"))?
        .try_into()?;
    header_parser.load()?;

    jmp_table.set(
        JmpProg::HdrParser as u32,
        header_parser
            .fd()
            .map_err(|_| anyhow!("failed to set header parser tail prog"))?,
        0,
    )?;

    //

    let cgroup = File::open(cgroup_path)?;
    let sock_ops: &mut SockOps = ebpf
        .program_mut("ulb_sock_ops")
        .ok_or_else(|| anyhow!("missing `ulb_sock_ops` prog"))?
        .try_into()?;
    sock_ops.load()?;
    sock_ops.attach(cgroup, CgroupAttachMode::Single)?;

    // maps

    let listener_ports = Array::try_from(
        ebpf.take_map("LISTENER_PORTS")
            .ok_or_else(|| anyhow!("missing `LISTENER_PORTS`"))?,
    )?;

    let backend_connection_pool_table = ArrayOfMaps::try_from(
        ebpf.take_map("BACKEND_CONNECTION_POOL_TABLE")
            .ok_or_else(|| anyhow!("missing `BACKEND_CONNECTION_POOL_TABLE`"))?,
    )?;

    let backend_connection_pool_stats_table = Array::try_from(
        ebpf.take_map("BACKEND_CONNECTION_POOL_STATS_TABLE")
            .ok_or_else(|| anyhow!("missing `BACKEND_CONNECTION_POOL_STATS_TABLE`"))?,
    )?;

    let vhost_map = HashMap::try_from(
        ebpf.take_map("VHOST_MAP")
            .ok_or_else(|| anyhow!("missing `VHOST_MAP`"))?,
    )?;

    let route_table = Array::try_from(
        ebpf.take_map("ROUTE_TABLE")
            .ok_or_else(|| anyhow!("missing `ROUTE_TABLE`"))?,
    )?;

    let cluster_table = Array::try_from(
        ebpf.take_map("CLUSTER_TABLE")
            .ok_or_else(|| anyhow!("missing `CLUSTER_TABLE`"))?,
    )?;

    let header_rule_table = Array::try_from(
        ebpf.take_map("HEADER_RULE_TABLE")
            .ok_or_else(|| anyhow!("missing `HEADER_RULE_TABLE`"))?,
    )?;

    let header_key_map = HashMap::try_from(
        ebpf.take_map("HEADER_KEY_MAP")
            .ok_or_else(|| anyhow!("missing `HEADER_KEY_MAP`"))?,
    )?;

    let mut residual_connection_map = HashMap::try_from(
        ebpf.take_map("RESIDUAL_CONNECTION_MAP")
            .ok_or_else(|| anyhow!("missing `RESIDUAL_CONNECTION_MAP`"))?,
    )?;

    // fill the map to disable resident connections
    if residual_capacity == 0 {
        // we can safely use `0` as key here; kernel never generates socket cookies with
        // `0` value. https://github.com/torvalds/linux/blob/6812ce4e4379ffc99c52401ec28f0d7ffbc36206/net/core/sock_diag.c#L26
        let cookie = 0;
        let sentinel = ResidentTarget(0);
        residual_connection_map.insert(cookie, sentinel, 0)?;
    }

    Ok(BpfState {
        ebpf,
        client_connection_map,
        backend_connection_map,
        listener_ports,
        backend_connection_pool_table,
        backend_connection_pool_stats_table,
        vhost_map,
        route_table,
        cluster_table,
        header_rule_table,
        header_key_map,
        residual_connection_map,
        jmp_table,
    })
}
