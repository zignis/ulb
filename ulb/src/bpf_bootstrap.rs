use std::fs::File;

use anyhow::anyhow;
use aya::{
    Ebpf,
    maps::{
        Array,
        HashMap,
        MapData,
        ProgramArray,
        SockHash,
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
    JMP_PROG_HEADER_PARSER,
    JMP_PROG_ROUTER,
    http::HTTP_HDR_KEY_MAX_LEN,
    ir::{
        BackendConnectionPool,
        Cluster,
        HeaderRule,
        RouteValue,
        VHostKey,
        VHostValue,
    },
    session::SocketCookie,
};

#[cfg(feature = "debug")]
use crate::telemetry::bpf_log_closure;

#[allow(dead_code)]
pub struct BpfState {
    pub ebpf: Ebpf,
    pub client_connection_map: SockHash<MapData, SocketCookie>,
    pub backend_connection_map: SockHash<MapData, SocketCookie>,
    pub listener_ports: Array<MapData, u8>,
    pub backend_connection_pool_table: Array<MapData, BackendConnectionPool>,
    pub vhost_map: HashMap<MapData, VHostKey, VHostValue>,
    pub route_table: Array<MapData, RouteValue>,
    pub cluster_table: Array<MapData, Cluster>,
    pub header_rule_table: Array<MapData, HeaderRule>,
    pub header_key_map: HashMap<MapData, [u8; HTTP_HDR_KEY_MAX_LEN], u64>,
    pub jmp_table: ProgramArray<MapData>,
}

pub fn bootstrap_bpf(cgroup_path: &str) -> anyhow::Result<BpfState> {
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
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
        JMP_PROG_ROUTER,
        router
            .fd()
            .map_err(|_| anyhow!("failed to set `JMP_PROG_ROUTER`"))?,
        0,
    )?;

    let header_parser: &mut SkSkb = ebpf
        .program_mut("ulb_header_parser")
        .ok_or_else(|| anyhow!("missing `ulb_header_parser` prog"))?
        .try_into()?;
    header_parser.load()?;

    jmp_table.set(
        JMP_PROG_HEADER_PARSER,
        header_parser
            .fd()
            .map_err(|_| anyhow!("failed to set `JMP_PROG_HEADER_PARSER`"))?,
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

    let listener_ports: Array<_, u8> = Array::try_from(
        ebpf.take_map("LISTENER_PORTS")
            .ok_or_else(|| anyhow!("missing `LISTENER_PORTS`"))?,
    )?;

    let backend_connection_pool_table: Array<_, BackendConnectionPool> = Array::try_from(
        ebpf.take_map("BACKEND_CONNECTION_POOL_TABLE")
            .ok_or_else(|| anyhow!("missing `BACKEND_CONNECTION_POOL_TABLE`"))?,
    )?;

    let vhost_map: HashMap<_, VHostKey, VHostValue> = HashMap::try_from(
        ebpf.take_map("VHOST_MAP")
            .ok_or_else(|| anyhow!("missing `VHOST_MAP`"))?,
    )?;

    let route_table: Array<_, RouteValue> = Array::try_from(
        ebpf.take_map("ROUTE_TABLE")
            .ok_or_else(|| anyhow!("missing `ROUTE_TABLE`"))?,
    )?;

    let cluster_table: Array<_, Cluster> = Array::try_from(
        ebpf.take_map("CLUSTER_TABLE")
            .ok_or_else(|| anyhow!("missing `CLUSTER_TABLE`"))?,
    )?;

    let header_rule_table: Array<_, HeaderRule> = Array::try_from(
        ebpf.take_map("HEADER_RULE_TABLE")
            .ok_or_else(|| anyhow!("missing `HEADER_RULE_TABLE`"))?,
    )?;

    let header_key_map: HashMap<_, [u8; HTTP_HDR_KEY_MAX_LEN], u64> = HashMap::try_from(
        ebpf.take_map("HEADER_KEY_MAP")
            .ok_or_else(|| anyhow!("missing `HEADER_KEY_MAP`"))?,
    )?;

    Ok(BpfState {
        ebpf,
        client_connection_map,
        backend_connection_map,
        listener_ports,
        backend_connection_pool_table,
        vhost_map,
        route_table,
        cluster_table,
        header_rule_table,
        header_key_map,
        jmp_table,
    })
}
