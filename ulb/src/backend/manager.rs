use std::{
    collections::HashMap,
    net::SocketAddr,
    os::fd::AsRawFd,
    time::Duration,
};

use anyhow::{
    Result,
    anyhow,
};
use aya::maps::{
    Array,
    MapData,
    SockHash,
};
use backoff::{
    ExponentialBackoff,
    future::retry,
};
use log::{
    debug,
    error,
    info,
};
use tokio::{
    io::AsyncReadExt,
    net::TcpStream,
    sync::mpsc::{
        UnboundedReceiver,
        UnboundedSender,
        unbounded_channel,
    },
    task::JoinSet,
};
use ulb_common::{
    SocketCookie,
    ir::{
        BackendCluster,
        MAX_BACKENDS_PER_CLUSTER,
    },
};

use crate::{
    backend::socket_cookie::get_socket_cookie,
    config::canonical::UlbConfig,
};

// TODO: move this to config
const MAX_RETRY_DURATION: u64 = 30; // seconds

#[derive(Debug)]
pub enum ManagerEvent {
    Disconnect {
        cluster_idx: u32,
        addr: SocketAddr,
        old_cookie: SocketCookie,
    },
    Reconnected {
        cluster_idx: u32,
        addr: SocketAddr,
        old_cookie: SocketCookie,
        new_cookie: SocketCookie,
        stream: TcpStream,
    },
}

pub struct BackendManager {
    tasks: JoinSet<()>,
    event_tx: UnboundedSender<ManagerEvent>,
    event_rx: UnboundedReceiver<ManagerEvent>,
}

impl BackendManager {
    pub fn new() -> Self {
        let (event_tx, event_rx) = unbounded_channel();
        Self {
            event_tx,
            event_rx,
            tasks: JoinSet::new(),
        }
    }

    pub async fn next_event(&mut self) -> Option<ManagerEvent> {
        self.event_rx.recv().await
    }

    pub async fn shutdown(&mut self) {
        info!("shutting down backend manager...");
        self.tasks.abort_all();
        while self.tasks.join_next().await.is_some() {}
        info!("backend manager shut down");
    }

    pub async fn initialize_clusters(
        &mut self,
        cfg: &UlbConfig,
        backend_map: &mut SockHash<MapData, SocketCookie>,
    ) -> Result<HashMap<String, Vec<SocketCookie>>> {
        let mut cookie_map = HashMap::new();

        for (idx, cluster_cfg) in cfg.clusters.iter().enumerate() {
            let mut cookies = Vec::new();
            // TODO: temporary wrong default value for pool_size
            let pool_size = cluster_cfg.pool_size.unwrap_or(MAX_BACKENDS_PER_CLUSTER);

            for endpoint in &cluster_cfg.endpoints {
                let addr: SocketAddr = endpoint.addr.parse()?;
                let mut join_set = JoinSet::new();

                // TODO: separate map for pool of individual backend?
                for _ in 0..pool_size {
                    join_set.spawn(async move { TcpStream::connect(&addr).await });
                }

                while let Some(join) = join_set.join_next().await {
                    match join {
                        Ok(Ok(stream)) => {
                            match Self::register_backend(
                                self.event_tx.clone(),
                                &mut self.tasks,
                                stream,
                                idx as u32,
                                addr,
                                backend_map,
                            ) {
                                Ok(cookie) => cookies.push(cookie),
                                Err(err) => error!("failed to register backend: {err}"),
                            }
                        }

                        Ok(Err(err)) => {
                            error!("failed to connect to backend {addr}: {err}");
                        }

                        Err(err) => {
                            error!("join error for {addr}: {err}");
                        }
                    }
                }

                if !cookies.is_empty() {
                    info!("setup {} connections to backend: {addr}", cookies.len());
                }
            }

            cookie_map.insert(cluster_cfg.name.clone(), cookies);
        }

        Ok(cookie_map)
    }

    pub async fn handle_event(
        &mut self,
        event: ManagerEvent,
        cluster_table: &mut Array<MapData, BackendCluster>,
        backend_map: &mut SockHash<MapData, SocketCookie>,
    ) {
        match event {
            ManagerEvent::Disconnect {
                cluster_idx,
                addr,
                old_cookie,
            } => {
                let tx = self.event_tx.clone();

                self.tasks.spawn(async move {
                    let backoff = ExponentialBackoff {
                        max_elapsed_time: Some(Duration::from_secs(MAX_RETRY_DURATION)),
                        ..Default::default()
                    };

                    match retry(backoff, || async {
                        match TcpStream::connect(&addr).await {
                            Ok(x) => Ok(x),
                            Err(err) => {
                                debug!("failed to reconnect to {addr}: {err}");
                                Err(backoff::Error::transient(err))
                            }
                        }
                    })
                    .await
                    {
                        Ok(stream) => {
                            let fd = stream.as_raw_fd();
                            if let Ok(cookie) = get_socket_cookie(fd) {
                                if let Err(err) = stream.set_nodelay(true) {
                                    error!("failed to set nodelay: {err}");
                                }

                                let _ = tx.send(ManagerEvent::Reconnected {
                                    cluster_idx,
                                    addr,
                                    old_cookie,
                                    new_cookie: cookie,
                                    stream,
                                });
                            }
                        }

                        Err(err) => {
                            error!("gave up reconnecting to backend {addr}: {err}");
                        }
                    }
                });
            }

            ManagerEvent::Reconnected {
                cluster_idx,
                addr,
                old_cookie,
                new_cookie,
                stream,
            } => {
                if let Err(err) = backend_map.insert(new_cookie, stream.as_raw_fd(), 0) {
                    error!("failed to insert socket into BACKEND_CONNECTION_MAP: {err}");
                } else {
                    info!(
                        "inserted backend {} into BACKEND_CONNECTION_MAP",
                        new_cookie
                    );
                }

                Self::spawn_connection_monitor(
                    self.event_tx.clone(),
                    &mut self.tasks,
                    stream,
                    cluster_idx,
                    addr,
                    new_cookie,
                );

                // update new cookie in cluster table
                if let Ok(mut cluster) = cluster_table.get(&cluster_idx, 0) {
                    for endpoint in cluster.endpoints.iter_mut() {
                        if endpoint.cookie == old_cookie {
                            endpoint.cookie = new_cookie;

                            if let Err(err) = cluster_table.set(cluster_idx, cluster, 0) {
                                error!("failed to update CLUSTER_TABLE: {err}");
                            }

                            break;
                        }
                    }
                }
            }
        }
    }

    fn register_backend(
        tx_event: UnboundedSender<ManagerEvent>,
        tasks: &mut JoinSet<()>,
        stream: TcpStream,
        cluster_idx: u32,
        addr: SocketAddr,
        backend_map: &mut SockHash<MapData, SocketCookie>,
    ) -> Result<SocketCookie> {
        let fd = stream.as_raw_fd();
        let cookie = get_socket_cookie(fd)?;

        backend_map
            .insert(cookie, fd, 0)
            .map_err(|err| anyhow!("failed to insert socket into BACKEND_CONNECTION_MAP: {err}"))?;

        stream
            .set_nodelay(true)
            .map_err(|err| anyhow!("failed to set nodelay: {err}"))?;

        Self::spawn_connection_monitor(tx_event, tasks, stream, cluster_idx, addr, cookie);

        Ok(cookie)
    }

    fn spawn_connection_monitor(
        tx_event: UnboundedSender<ManagerEvent>,
        tasks: &mut JoinSet<()>,
        mut stream: TcpStream,
        cluster_idx: u32,
        addr: SocketAddr,
        cookie: SocketCookie,
    ) {
        tasks.spawn(async move {
            let mut buf = [0u8; 1];

            loop {
                match stream.read(&mut buf).await {
                    Ok(0) | Err(_) => {
                        info!("connection closed for {addr}");

                        // TODO: add max reconnect attempt limit
                        let _ = tx_event.send(ManagerEvent::Disconnect {
                            cluster_idx,
                            addr,
                            old_cookie: cookie,
                        });

                        break;
                    }

                    _ => {}
                }
            }
        });
    }
}
