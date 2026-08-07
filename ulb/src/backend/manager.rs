use std::{
    collections::HashMap,
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
use log::{
    error,
    info,
};
use tokio::{
    io::AsyncReadExt,
    net::{
        TcpStream,
        tcp::{
            OwnedReadHalf,
            OwnedWriteHalf,
        },
    },
    sync::{
        mpsc,
        mpsc::{
            UnboundedReceiver,
            UnboundedSender,
        },
    },
    task::JoinSet,
    time::sleep,
};
use ulb_common::{
    SocketCookie,
    ir::BackendCluster,
};

use crate::{
    backend::socket_cookie::get_socket_cookie,
    config::canonical::UlbConfig,
};

const BACKEND_CONNECTION_POOL_SIZE: usize = 4; // connections per backend

type ConnectionPool = Vec<BackendConnection>;

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct BackendPoolKey {
    cluster_idx: u32,
    addr: String,
}

#[derive(Debug)]
struct BackendConnection {
    cookie: SocketCookie,
    writer: OwnedWriteHalf,
}

#[derive(Debug)]
pub struct ReconnectEvent {
    cluster_idx: u32,
    addr: String,
    old_cookie: SocketCookie,
}

#[derive(Debug)]
pub struct BackendManager {
    pools: HashMap<BackendPoolKey, ConnectionPool>,
    reconnect_tx: UnboundedSender<ReconnectEvent>,
    reconnect_rx: UnboundedReceiver<ReconnectEvent>,
}

impl BackendManager {
    pub fn new() -> Self {
        let (reconnect_tx, reconnect_rx) = mpsc::unbounded_channel();
        Self {
            pools: HashMap::new(),
            reconnect_tx,
            reconnect_rx,
        }
    }

    pub async fn next_reconnect_event(&mut self) -> Option<ReconnectEvent> {
        self.reconnect_rx.recv().await
    }

    pub async fn initialize_clusters(
        &mut self,
        cfg: &UlbConfig,
        backend_map: &mut SockHash<MapData, SocketCookie>,
    ) -> Result<HashMap<String, Vec<SocketCookie>>> {
        let mut cookie_map = HashMap::new();

        for (idx, cluster_cfg) in cfg.clusters.iter().enumerate() {
            let mut cookies = Vec::new();

            for endpoint in &cluster_cfg.endpoints {
                let addr = endpoint.addr.clone();
                let mut streams = Vec::new();
                let mut join_set = JoinSet::new();

                for _ in 0..BACKEND_CONNECTION_POOL_SIZE {
                    let addr = addr.clone();
                    join_set.spawn(async move { TcpStream::connect(&addr).await });
                }

                while let Some(join) = join_set.join_next().await {
                    match join {
                        Ok(Ok(stream)) => {
                            match Self::register_backend(
                                self.reconnect_tx.clone(),
                                backend_map,
                                stream,
                                idx as u32,
                                addr.clone(),
                            ) {
                                Ok((cookie, writer)) => {
                                    cookies.push(cookie);
                                    streams.push(BackendConnection { cookie, writer });
                                }

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

                if !streams.is_empty() {
                    info!("setup `{}` connections to backend: {addr}", streams.len());

                    self.pools
                        .entry(BackendPoolKey {
                            cluster_idx: idx as u32,
                            addr,
                        })
                        .or_default()
                        .extend(streams);
                }
            }

            cookie_map.insert(cluster_cfg.name.clone(), cookies);
        }

        Ok(cookie_map)
    }

    pub async fn handle_reconnect(
        &mut self,
        event: ReconnectEvent,
        backend_map: &mut SockHash<MapData, SocketCookie>,
        cluster_table: &mut Array<MapData, BackendCluster>,
    ) {
        if let Err(err) = backend_map.remove(&event.old_cookie) {
            error!("failed to remove cookie from BACKEND_MAP: {err}");
            return;
        }

        match TcpStream::connect(&event.addr).await {
            Ok(stream) => {
                match Self::register_backend(
                    self.reconnect_tx.clone(),
                    backend_map,
                    stream,
                    event.cluster_idx,
                    event.addr.clone(),
                ) {
                    Ok((cookie, writer)) => {
                        if let Some(connection) = self
                            .pools
                            .get_mut(&BackendPoolKey {
                                cluster_idx: event.cluster_idx,
                                addr: event.addr.clone(),
                            })
                            .and_then(|pool| pool.iter_mut().find(|c| c.cookie == event.old_cookie))
                        {
                            connection.cookie = cookie;
                            connection.writer = writer;
                            info!("reconnected to backend: {}", event.addr);
                        }

                        // update new cookie in cluster table
                        if let Ok(mut cluster) = cluster_table.get(&event.cluster_idx, 0) {
                            for i in 0..cluster.endpoints.len as usize {
                                if cluster.endpoints[i].cookie == event.old_cookie {
                                    cluster.endpoints[i].cookie = cookie;

                                    if let Err(err) =
                                        cluster_table.set(event.cluster_idx, cluster, 0)
                                    {
                                        error!("failed to update CLUSTER_TABLE: {err}");
                                    }

                                    break;
                                }
                            }
                        }
                    }

                    Err(err) => {
                        error!("failed to register backend: {err}");
                    }
                }
            }

            Err(err) => {
                error!("failed to reconnect to {}: {err}", event.addr);

                let tx = self.reconnect_tx.clone();
                tokio::spawn(async move {
                    // TODO: add reconnect retry limit
                    sleep(Duration::from_secs(5)).await;
                    let _ = tx.send(event);
                });
            }
        }
    }

    fn register_backend(
        tx_event: UnboundedSender<ReconnectEvent>,
        backend_map: &mut SockHash<MapData, SocketCookie>,
        stream: TcpStream,
        cluster_idx: u32,
        addr: String,
    ) -> Result<(SocketCookie, OwnedWriteHalf)> {
        let fd = stream.as_raw_fd();
        let cookie = get_socket_cookie(fd)?;

        stream
            .set_nodelay(true)
            .map_err(|err| anyhow!("failed to set nodelay: {err}"))?;

        backend_map
            .insert(cookie, fd, 0)
            .map_err(|err| anyhow!("failed to insert socket into BACKEND_MAP: {err}"))?;

        let (reader, writer) = stream.into_split();
        Self::spawn_connection_monitor(tx_event, reader, cluster_idx, addr, cookie);
        Ok((cookie, writer))
    }

    fn spawn_connection_monitor(
        tx_event: UnboundedSender<ReconnectEvent>,
        mut rx: OwnedReadHalf,
        cluster_idx: u32,
        addr: String,
        cookie: SocketCookie,
    ) {
        tokio::spawn(async move {
            let mut buf = [0u8; 1];

            loop {
                match rx.read(&mut buf).await {
                    Ok(0) | Err(_) => {
                        info!("connection closed/error for {addr}");

                        // TODO: add max reconnect attempt limit
                        let _ = tx_event.send(ReconnectEvent {
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

    pub fn shutdown(&mut self) {
        self.pools.clear();
    }
}
