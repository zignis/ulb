#![cfg(target_os = "linux")]

use std::sync::Arc;

use clap::Parser;
use libc::{
    RLIM_INFINITY,
    RLIMIT_MEMLOCK,
    RLIMIT_NOFILE,
    getrlimit,
    rlimit,
    setrlimit,
};
use log::{
    Level,
    info,
    log_enabled,
};
use tokio::signal;
use tokio_util::sync::CancellationToken;
use ulb::{
    backend::BackendManager,
    bpf_bootstrap::bootstrap_bpf,
    config::{
        adapters::{
            load_config,
            native::NativeAdapter,
        },
        compiler::compile,
    },
    control_plane::ControlPlane,
    telemetry,
};

const DEFAULT_CONFIG_PATH: &str = "/etc/ulb/ulb.yaml";
const DEFAULT_CGROUP_PATH: &str = "/sys/fs/cgroup";

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(long, default_value = DEFAULT_CONFIG_PATH)]
    config: String,
    #[arg(long, default_value = DEFAULT_CGROUP_PATH)]
    cgroup: String,
    #[arg(long)]
    no_fancy: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    telemetry::init(!args.no_fancy);

    if !log_enabled!(Level::Info) {
        println!("RUST_LOG: info level logging is not enabled");
    }

    println!(
        "launching µlb v{}.{}",
        env!("CARGO_PKG_VERSION_MAJOR"),
        env!("CARGO_PKG_VERSION_MINOR")
    );

    let cfg = load_config::<NativeAdapter, _>(&args.config)?;
    info!("config loaded");

    bump_memlock_limit();
    bump_nofile_limit(cfg.rlimit_nofile);

    let mut bpf = bootstrap_bpf(&args.cgroup, cfg.max_resident_connections)?;

    for listener_cfg in &cfg.listeners {
        bpf.listener_ports
            .set(u32::from(listener_cfg.addr.port()), 1, 0)?;
    }

    let shutdown_token = CancellationToken::new();
    let mut backend_manager = BackendManager::new();

    let cluster_conn_pool_map = backend_manager
        .initialize_clusters(
            &cfg,
            &mut bpf.backend_connection_map,
            &mut bpf.backend_connection_pool_table,
            &mut bpf.backend_connection_pool_stats_table,
        )
        .await?;

    let ir = compile(&cfg, cluster_conn_pool_map)?;

    for (key, val) in ir.vhost_map {
        bpf.vhost_map.insert(key, val, 0)?;
    }

    for (i, route) in ir.route_table.into_iter().enumerate() {
        bpf.route_table.set(u32::try_from(i)?, route, 0)?;
    }

    for (i, cluster) in ir.cluster_table.into_iter().enumerate() {
        bpf.cluster_table.set(u32::try_from(i)?, cluster, 0)?;
    }

    for (i, rule) in ir.header_rule_table.into_iter().enumerate() {
        bpf.header_rule_table.set(u32::try_from(i)?, rule, 0)?;
    }

    for (key, val) in ir.header_key_map {
        bpf.header_key_map.insert(key, val, 0)?;
    }

    let mut control_plane = ControlPlane::new(
        shutdown_token.clone(),
        bpf.residual_connection_map,
        Arc::new(cfg.clusters.clone()),
        bpf.session_map,
        backend_manager.get_event_tx(),
    );

    control_plane.start(&cfg)?;

    loop {
        tokio::select! {
            Some(event) = backend_manager.next_event() => {
                backend_manager.handle_event(
                    event,
                    &mut bpf.backend_connection_map,
                    &mut bpf.backend_connection_pool_table,
                );
            }

            _ = signal::ctrl_c() => {
                info!("[SIGINT] shutting down...");

                shutdown_token.cancel();
                backend_manager.shutdown().await;
                control_plane.shutdown().await;

                break;
            }
        }
    }

    Ok(())
}

fn bump_memlock_limit() {
    // this is needed for older kernels that don't use the new
    // memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = rlimit {
        rlim_cur: RLIM_INFINITY,
        rlim_max: RLIM_INFINITY,
    };
    let ret = unsafe { setrlimit(RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        info!("remove limit on locked memory failed, ret is: {ret}");
    }
}

fn bump_nofile_limit(limit: Option<u64>) {
    let mut rlim = rlimit {
        rlim_cur: 0,
        rlim_max: limit.unwrap_or_default(),
    };

    if limit.is_none() && unsafe { getrlimit(RLIMIT_NOFILE, &mut rlim) } != 0 {
        info!("failed to get OS open file limit");
        return;
    }

    rlim.rlim_cur = rlim.rlim_max;
    let ret = unsafe { setrlimit(RLIMIT_NOFILE, &rlim) };
    if ret != 0 {
        info!("increase open file limit failed, ret is: {ret}");
    }
}
