use std::{
    os::fd::AsRawFd,
    time::Duration,
};

use anyhow::anyhow;
use aya::{
    maps::{
        Array,
        HashMap,
        ProgramArray,
        SockHash,
    },
    programs::{
        FEntry,
        SkSkb,
    },
};
use log::{
    Level,
    error,
    info,
    log_enabled,
};
use tokio::{
    io::AsyncReadExt,
    net::TcpListener,
    signal,
    task::JoinSet,
    time::timeout,
};
use ulb_common::{
    JMP_PROG_ROUTING,
    SocketCookie,
    ir::{
        BackendCluster,
        RouteValue,
        VHostKey,
        VHostValue,
    },
};

use crate::{
    backend::{
        BackendManager,
        get_socket_cookie,
    },
    config::{
        adapters::{
            load_config,
            native::NativeAdapter,
        },
        compiler::compile,
    },
};

mod backend;
mod config;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    if !log_enabled!(Level::Info) {
        println!("RUST_LOG: info level logging is not enabled");
    }

    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/ulb"
    )))?;

    #[cfg(feature = "debug")]
    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => {
            // can happen if there are no log statements in ebpf program
            log::warn!("failed to initialize ebpf logger: {e}");
        }
        Ok(logger) => {
            let mut logger =
                tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;

            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }

    let mut connection_map: SockHash<_, SocketCookie> = SockHash::try_from(
        ebpf.take_map("CONNECTION_MAP")
            .ok_or_else(|| anyhow!("missing `CONNECTION_MAP`"))?,
    )?;

    let mut backend_map: SockHash<_, SocketCookie> = SockHash::try_from(
        ebpf.take_map("BACKEND_MAP")
            .ok_or_else(|| anyhow!("missing `BACKEND_MAP`"))?,
    )?;

    let parser: &mut SkSkb = ebpf
        .program_mut("stream_parser")
        .ok_or_else(|| anyhow!("missing `stream_parser` prog"))?
        .try_into()?;
    parser.load()?;
    parser.attach(connection_map.fd())?;
    parser.attach(backend_map.fd())?;

    let verdict: &mut SkSkb = ebpf
        .program_mut("stream_verdict")
        .ok_or_else(|| anyhow!("missing `stream_verdict` prog"))?
        .try_into()?;
    verdict.load()?;
    verdict.attach(connection_map.fd())?;
    verdict.attach(backend_map.fd())?;

    // jump table for tail calls
    let mut jmp_table: ProgramArray<_> = ProgramArray::try_from(
        ebpf.take_map("JMP_TABLE")
            .ok_or_else(|| anyhow!("missing `JMP_TABLE`"))?,
    )?;

    let router: &mut SkSkb = ebpf
        .program_mut("router")
        .ok_or_else(|| anyhow!("missing `router` prog"))?
        .try_into()?;
    router.load()?;

    jmp_table.set(
        JMP_PROG_ROUTING,
        router
            .fd()
            .map_err(|_| anyhow!("failed to set `JMP_PROG_ROUTING`"))?,
        0,
    )?;

    // SESSION_MAP cleanup
    let btf = aya::Btf::from_sys_fs()?;
    let session_cleanup: &mut FEntry = ebpf
        .program_mut("session_cleanup")
        .ok_or_else(|| anyhow!("missing `session_cleanup` prog"))?
        .try_into()?;
    session_cleanup.load("tcp_set_state", &btf)?;
    session_cleanup.attach()?;

    // configuration
    let cfg = load_config::<NativeAdapter, _>("./__ulb_config.yaml")?; // TODO:
    let mut backend_manager = BackendManager::new();
    let cookie_map = backend_manager
        .initialize_clusters(&cfg, &mut backend_map)
        .await?;
    let ir = compile(&cfg, cookie_map)?;

    let mut vhost_map: HashMap<_, VHostKey, VHostValue> = HashMap::try_from(
        ebpf.take_map("VHOST_MAP")
            .ok_or_else(|| anyhow!("missing `VHOST_MAP`"))?,
    )?;

    for (key, val) in ir.vhost_map {
        vhost_map.insert(key, val, 0)?;
    }

    let mut route_table: Array<_, RouteValue> = Array::try_from(
        ebpf.take_map("ROUTE_TABLE")
            .ok_or_else(|| anyhow!("missing `ROUTE_TABLE`"))?,
    )?;

    for (i, route) in ir.route_table.into_iter().enumerate() {
        route_table.set(i as u32, route, 0)?;
    }

    let mut cluster_table: Array<_, BackendCluster> = Array::try_from(
        ebpf.take_map("CLUSTER_TABLE")
            .ok_or_else(|| anyhow!("missing `CLUSTER_TABLE`"))?,
    )?;

    for (i, cluster) in ir.cluster_table.into_iter().enumerate() {
        cluster_table.set(i as u32, cluster, 0)?;
    }

    info!("config loaded");

    let listener = TcpListener::bind("0.0.0.0:8082").await?;
    info!("listening on http://localhost:8082");

    let mut clients = JoinSet::new();

    loop {
        tokio::select! {
            res = listener.accept() => {
                let (mut stream, peer_addr) = res?;
                info!("accepted {peer_addr}");

                let fd = stream.as_raw_fd();
                let cookie = get_socket_cookie(fd)?;

                if let Err(err) = connection_map.insert(cookie, fd, 0) {
                    error!("failed to insert client into CONNECTION_MAP: {err}");
                }

                clients.spawn(async move {
                    let mut buf = [0u8; 1];
                    loop {
                        if let Ok(0) | Err(_) = stream.read(&mut buf).await {
                            break;
                        }
                    }
                });
            }

            Some(event) = backend_manager.next_reconnect_event() => {
                backend_manager.handle_reconnect(event, &mut backend_map, &mut cluster_table).await;
            }

            Some(res) = clients.join_next(), if !clients.is_empty() => {
                if let Err(err) = res {
                    error!("client failed: {err}");
                }
            }

            _ = signal::ctrl_c() => {
                info!("received SIGINT");
                backend_manager.shutdown();

                if !clients.is_empty() {
                    let _ = timeout(Duration::from_secs(5), async {
                        while clients.join_next().await.is_some() {}
                    }).await;
                }

                break;
            }
        }
    }

    Ok(())
}
