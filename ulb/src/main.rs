#![cfg(target_os = "linux")]

use std::{
    net::SocketAddr,
    num::NonZero,
    thread::available_parallelism,
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
        CgroupAttachMode,
        SkSkb,
        SockOps,
    },
};
use clap::Parser;
use log::{
    Level,
    info,
    log_enabled,
};
use tokio::{
    io::AsyncReadExt,
    net::{
        TcpListener,
        TcpSocket,
    },
    signal,
    task::JoinSet,
};
use tokio_util::sync::CancellationToken;
use ulb_common::{
    JMP_PROG_ROUTING,
    SocketCookie,
    ir::{
        BackendCluster,
        LISTEN_BACKLOG_QUEUE_SIZE,
        RouteValue,
        VHostKey,
        VHostValue,
    },
};

use crate::{
    backend::BackendManager,
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

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long, default_value = "./config.yaml")] // TODO: change default path
    config: String,
}

fn bind_port(addr: SocketAddr) -> anyhow::Result<TcpListener> {
    let socket = if addr.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };

    socket
        .set_reuseport(true)
        .map_err(|err| anyhow!("failed to set `reuseport` opt: {err}"))?;

    socket.bind(addr)?;
    Ok(socket.listen(LISTEN_BACKLOG_QUEUE_SIZE)?)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    env_logger::init();

    if !log_enabled!(Level::Info) {
        println!("RUST_LOG: info level logging is not enabled");
    }

    println!("launching...");

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

    let connection_map: SockHash<_, SocketCookie> = SockHash::try_from(
        ebpf.take_map("CLIENT_CONNECTION_MAP")
            .ok_or_else(|| anyhow!("missing `CLIENT_CONNECTION_MAP`"))?,
    )?;

    let mut backend_map: SockHash<_, SocketCookie> = SockHash::try_from(
        ebpf.take_map("BACKEND_CONNECTION_MAP")
            .ok_or_else(|| anyhow!("missing `BACKEND_CONNECTION_MAP`"))?,
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

    // TODO: make cgroup configurable
    let cgroup = std::fs::File::open("/sys/fs/cgroup")?;
    let sock_ops: &mut SockOps = ebpf
        .program_mut("sock_ops")
        .ok_or_else(|| anyhow!("missing `sock_ops` prog"))?
        .try_into()?;
    sock_ops.load()?;
    sock_ops.attach(cgroup, CgroupAttachMode::Single)?;

    // configuration
    let cfg = load_config::<NativeAdapter, _>(&args.config)?;

    let mut listener_ports: Array<_, u8> = Array::try_from(
        ebpf.take_map("LISTENER_PORTS")
            .ok_or_else(|| anyhow!("missing `LISTENER_PORTS`"))?,
    )?;

    for listener_cfg in &cfg.listeners {
        let addr: SocketAddr = listener_cfg
            .addr
            .parse()
            .map_err(|err| anyhow!("invalid listener address `{}`: {err}", listener_cfg.addr))?;

        listener_ports.set(addr.port() as u32, 1, 0)?;
    }

    let shutdown_token = CancellationToken::new();

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

    // TODO: change default value
    let num_cores = available_parallelism().map(NonZero::get).unwrap_or(4);
    let mut tasks = JoinSet::new();

    info!("starting {} workers per listener", num_cores);

    for listener_cfg in &cfg.listeners {
        // TODO: addr parsing step is done twice, move parsing to compiler
        if let Ok(addr) = listener_cfg.addr.parse::<SocketAddr>() {
            for _ in 0..num_cores {
                let listener = bind_port(addr)?;
                let shutdown_token = shutdown_token.clone();

                tasks.spawn(async move {
                    loop {
                        tokio::select! {
                            Ok((mut stream, _)) = listener.accept() => {
                                let _ = stream.set_nodelay(true);
                                let task_shutdown = shutdown_token.clone();

                                // EOF detection task
                                tokio::spawn(async move {
                                    let mut buf = [0u8; 1];

                                    loop {
                                        tokio::select! {
                                            _ = task_shutdown.cancelled() => {
                                                break;
                                            }

                                            res = stream.read(&mut buf) => {
                                                if let Ok(0) | Err(_) = res {
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                });
                            }

                            _ = shutdown_token.cancelled() => {
                                break;
                            }
                        }
                    }
                });
            }

            info!("listening on http://{addr}");
        }
    }

    loop {
        tokio::select! {
            // backend reconnect events
            Some(event) = backend_manager.next_event() => {
                backend_manager.handle_event(event, &mut cluster_table, &mut backend_map).await;
            }

            _ = signal::ctrl_c() => {
                info!("[SIGINT] shutting down...");

                shutdown_token.cancel();
                backend_manager.shutdown().await;

                while tasks.join_next().await.is_some() {}

                break;
            }
        }
    }

    Ok(())
}
