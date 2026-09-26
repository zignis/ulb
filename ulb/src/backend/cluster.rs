use std::collections::HashMap;

use aya::maps::Queue;
use log::{
    error,
    info,
};
use tokio::{
    net::TcpStream,
    sync::mpsc::UnboundedSender,
    task::JoinSet,
};
use ulb_common::ir::BackendConnectionPoolStats;

use crate::{
    backend::{
        connection::register_backend,
        event::ManagerEvent,
    },
    bpf_bootstrap::{
        BPF_EXIST,
        BackendConnectionMap,
        BackendConnectionPoolQueue,
        BackendConnectionPoolStatsTable,
        BackendConnectionPoolTable,
    },
    config::canonical::{
        ClusterConnectionPoolMap,
        UlbConfig,
    },
    telemetry::ProgressBar,
};

const CONNECT_BATCH_SIZE: usize = 1 << 6; // avoid tcp flood at backend for large pool sizes

pub async fn initialize_clusters(
    tx_event: UnboundedSender<ManagerEvent>,
    tasks: &mut JoinSet<()>,
    cfg: &UlbConfig,
    backend_map: &mut BackendConnectionMap,
    backend_conn_pool_table: &mut BackendConnectionPoolTable,
    backend_conn_pool_stats_table: &mut BackendConnectionPoolStatsTable,
) -> anyhow::Result<ClusterConnectionPoolMap> {
    let mut cookie_map = HashMap::new();
    let mut next_pool_idx = 0;

    for (idx, cluster_cfg) in cfg.clusters.iter().enumerate() {
        let mut conn_pools = Vec::new();

        for backend in &cluster_cfg.backends {
            let addr = backend.addr;
            let pool_idx = next_pool_idx;
            next_pool_idx += 1;
            conn_pools.push((pool_idx, backend.weight));
            let mut queue: BackendConnectionPoolQueue = Queue::create(backend.pool_size as u32, 0)?;
            let stats = BackendConnectionPoolStats::default();
            let pb = ProgressBar::new(backend.pool_size as u64, "filling up connection pool");

            if !pb.enabled() {
                info!(
                    "[{addr}] setting up connection pool ({})",
                    backend.pool_size
                );
            }

            let mut remaining = backend.pool_size;
            let mut connected = 0;

            while remaining > 0 {
                let batch = remaining.min(CONNECT_BATCH_SIZE);
                remaining -= batch;

                let mut join_set = JoinSet::new();
                for _ in 0..batch {
                    join_set.spawn(async move { TcpStream::connect(&addr).await });
                }

                while let Some(join) = join_set.join_next().await {
                    match join {
                        Ok(Ok(stream)) => {
                            match register_backend(
                                tx_event.clone(),
                                tasks,
                                stream,
                                idx as u32,
                                pool_idx,
                                addr,
                                backend_map,
                            ) {
                                Ok(cookie) => {
                                    if let Err(err) = queue.push(cookie, BPF_EXIST) {
                                        error!("failed to push to queue: {err}");
                                    } else {
                                        connected += 1;
                                        pb.inc();
                                    }
                                }

                                Err(err) => error!("failed to register backend: {err}"),
                            }
                        }

                        Ok(Err(err)) => {
                            error!("failed to connect to backend {addr}: {err}");
                            // TODO: max reconnect attempt limit
                            let _ = tx_event.send(ManagerEvent::Disconnect {
                                cluster_idx: idx as u32,
                                pool_idx,
                                addr,
                            });
                        }

                        Err(err) => {
                            error!("join error for {addr}: {err}");
                        }
                    }
                }
            }

            pb.finish(format!("[{addr}] setup {connected} connections to backend"));

            if !pb.enabled() {
                info!("[{addr}] setup {connected} connections to backend");
            }

            if let Err(err) = backend_conn_pool_table.set(pool_idx, &queue, 0) {
                error!("failed to insert into BACKEND_CONNECTION_POOL_TABLE: {err}");
            }

            if let Err(err) = backend_conn_pool_stats_table.set(pool_idx, stats, 0) {
                error!("failed to insert into BACKEND_CONNECTION_POOL_STATS_TABLE: {err}");
            }
        }

        cookie_map.insert(cluster_cfg.name.clone(), conn_pools);
    }

    Ok(cookie_map)
}
