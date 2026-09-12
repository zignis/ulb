#![cfg(target_os = "linux")]

use clap::Parser;
use log::{
    Level,
    info,
    log_enabled,
};
use tokio::signal;
use tokio_util::sync::CancellationToken;

use crate::{
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
};

mod backend;
mod bpf_bootstrap;
mod config;
mod control_plane;
mod telemetry;
mod utils;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long, default_value = "/etc/ulb/ulb.yaml")]
    config: String,
    #[arg(long, default_value = "/sys/fs/cgroup")]
    cgroup: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    telemetry::init();

    if !log_enabled!(Level::Info) {
        println!("RUST_LOG: info level logging is not enabled");
    }

    println!(
        "launching µlb v{}.{}",
        env!("CARGO_PKG_VERSION_MAJOR"),
        env!("CARGO_PKG_VERSION_MINOR")
    );

    let mut bpf = bootstrap_bpf(&args.cgroup)?;

    let cfg = load_config::<NativeAdapter, _>(&args.config)?;
    info!("config loaded");

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

    let mut control_plane = ControlPlane::new(shutdown_token.clone());
    control_plane.start(&cfg)?;

    loop {
        tokio::select! {
            Some(event) = backend_manager.next_event() => {
                backend_manager.handle_event(
                    event,
                    &mut bpf.backend_connection_map,
                    &mut bpf.backend_connection_pool_table
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
