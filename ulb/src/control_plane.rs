use std::{
    net::SocketAddr,
    num::NonZero,
    os::unix::io::AsRawFd,
    sync::{
        Arc,
        Mutex,
    },
    thread::available_parallelism,
};

use anyhow::anyhow;
use log::{
    debug,
    error,
    info,
    warn,
};
use tokio::{
    io::AsyncReadExt,
    net::{
        TcpListener,
        TcpSocket,
        TcpStream,
    },
    task::JoinSet,
};
use tokio_util::{
    sync::CancellationToken,
    task::TaskTracker,
};
use ulb_common::ir::DEFAULT_LISTEN_BACKLOG_QUEUE_SIZE;

use crate::{
    bpf_bootstrap::ResidualConnectionMap,
    config::canonical::{
        ClusterConfig,
        UlbConfig,
    },
    resident::handle_resident_session,
    utils::get_socket_cookie,
};

// TODO: move this to config
const DEFAULT_WORKERS: usize = 4;

pub struct ControlPlane {
    listener_tasks: JoinSet<()>,
    shutdown_token: CancellationToken,
    connection_tracker: TaskTracker,
    residual_connection_map: Arc<Mutex<ResidualConnectionMap>>,
    clusters: Arc<Vec<ClusterConfig>>,
}

impl ControlPlane {
    pub fn new(
        shutdown_token: CancellationToken,
        residual_connection_map: ResidualConnectionMap,
        clusters: Arc<Vec<ClusterConfig>>,
    ) -> Self {
        Self {
            listener_tasks: JoinSet::new(),
            shutdown_token,
            connection_tracker: TaskTracker::new(),
            residual_connection_map: Arc::new(Mutex::new(residual_connection_map)),
            clusters,
        }
    }

    pub fn start(&mut self, cfg: &UlbConfig) -> anyhow::Result<()> {
        let num_cores = available_parallelism().map_or(DEFAULT_WORKERS, NonZero::get);
        info!("starting {num_cores} workers per listener");

        for listener_cfg in &cfg.listeners {
            let addr = listener_cfg.addr;
            let backlog = listener_cfg
                .backlog
                .unwrap_or(DEFAULT_LISTEN_BACKLOG_QUEUE_SIZE);

            for _ in 0..num_cores {
                let listener = bind_port(addr, backlog)?;
                let shutdown_token = self.shutdown_token.clone();
                let residual_connection_map = self.residual_connection_map.clone();
                let clusters = self.clusters.clone();
                let connection_tracker = self.connection_tracker.clone();

                self.listener_tasks.spawn(async move {
                    loop {
                        tokio::select! {
                            Ok((stream, _)) = listener.accept() => {
                                handle_connection(
                                    stream,
                                    residual_connection_map.clone(),
                                    clusters.clone(),
                                    shutdown_token.clone(),
                                    connection_tracker.clone(),
                                );
                            }

                            () = shutdown_token.cancelled() => {
                                break;
                            }
                        }
                    }
                });
            }

            info!("listening on http://{addr}");
        }

        self.connection_tracker.close();

        Ok(())
    }

    pub async fn shutdown(&mut self) {
        while self.listener_tasks.join_next().await.is_some() {}
        self.connection_tracker.close();
        self.connection_tracker.wait().await;
    }
}

fn handle_connection(
    mut stream: TcpStream,
    residual_connection_map: Arc<Mutex<ResidualConnectionMap>>,
    clusters: Arc<Vec<ClusterConfig>>,
    task_shutdown: CancellationToken,
    connection_tracker: TaskTracker,
) {
    connection_tracker.spawn(async move {
        let _ = stream.set_nodelay(true);
        let cookie = match get_socket_cookie(stream.as_raw_fd()) {
            Ok(x) => x,
            Err(err) => {
                error!("{err}");
                return;
            }
        };

        let mut peek_buf = [0u8; 1];
        tokio::select! {
            () = task_shutdown.cancelled() => return,
            res = stream.peek(&mut peek_buf) => {
                if let Ok(0) | Err(_) = res {
                    return;
                }
            }
        }

        // is this a resident connection?
        let resident_data = match residual_connection_map.lock() {
            Ok(mut map) => match map.get(&cookie, 0) {
                Ok(data) => {
                    if let Err(err) = map.remove(&cookie) {
                        debug!("failed to remove cookie from resident map: {err}");
                    }

                    Some(data)
                }
                Err(_) => None,
            },
            Err(err) => {
                error!("`residual_connection_map` lock poisoned: {err}");
                return;
            }
        };

        if let Some(resident) = resident_data {
            let cluster_idx = resident.cluster_idx() as usize;
            let backend_idx = resident.backend_idx() as usize;

            if let Some(addr) = clusters
                .get(cluster_idx)
                .and_then(|cluster| cluster.backends.get(backend_idx))
                .map(|backend| backend.addr)
            {
                debug!(
                    "routing resident connection to cluster {cluster_idx} (backend {backend_idx})"
                );
                handle_resident_session(stream, addr, task_shutdown.clone()).await;
            } else {
                warn!("stray resident connection (cluster {cluster_idx}; backend {backend_idx})");
            }

            return;
        }

        let mut buf = [0u8; 1 << 6];
        loop {
            tokio::select! {
                () = task_shutdown.cancelled() => break,
                // either an eof (TCP FIN) or stray payload that must be drained
                res = stream.read(&mut buf) => {
                    if let Ok(0) | Err(_) = res {
                        break;
                    }
                }
            }
        }
    });
}

fn bind_port(addr: SocketAddr, backlog: u32) -> anyhow::Result<TcpListener> {
    let socket = if addr.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };

    socket
        .set_reuseport(true)
        .map_err(|err| anyhow!("failed to set `reuseport` opt: {err}"))?;
    socket
        .bind(addr)
        .map_err(|err| anyhow!("failed to bind {addr}: {err}"))?;
    socket
        .listen(backlog)
        .map_err(|err| anyhow!("failed to listen on {addr}: {err}"))
}
