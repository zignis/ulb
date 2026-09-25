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
    ir::BackendConnectionPool,
    session::SocketCookie,
};

use crate::{
    config::canonical::{
        ClusterConnectionPoolMap,
        UlbConfig,
    },
    utils::get_socket_cookie,
};

// TODO: move this to config
const MAX_RETRY_DURATION: u64 = 30; // seconds
const CONNECT_BATCH_SIZE: usize = 1 << 6; // avoid tcp flood at backend for large pool sizes

#[derive(Debug)]
pub enum ManagerEvent {
    Disconnect {
        cluster_idx: u32,
        pool_idx: u32,
        addr: SocketAddr,
        old_cookie: Option<SocketCookie>,
    },
    Reconnected {
        cluster_idx: u32,
        pool_idx: u32,
        addr: SocketAddr,
        new_cookie: SocketCookie,
        stream: TcpStream,
    },
}

pub struct BackendManager {
    tasks: JoinSet<()>,
    event_tx: UnboundedSender<ManagerEvent>,
    event_rx: UnboundedReceiver<ManagerEvent>,
    next_pool_idx: u32,
}

impl Default for BackendManager {
    fn default() -> Self {
        let (event_tx, event_rx) = unbounded_channel();
        Self {
            event_tx,
            event_rx,
            tasks: JoinSet::new(),
            next_pool_idx: 0,
        }
    }
}

impl BackendManager {
    pub fn new() -> Self {
        Self::default()
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
        backend_conn_pool_table: &mut Array<MapData, BackendConnectionPool>,
    ) -> Result<ClusterConnectionPoolMap> {
        let mut cookie_map = HashMap::new();

        for (idx, cluster_cfg) in cfg.clusters.iter().enumerate() {
            let mut conn_pools = Vec::new();

            for backend in &cluster_cfg.backends {
                let addr = backend.addr;
                let pool_idx = self.next_pool_idx;
                self.next_pool_idx += 1;
                conn_pools.push((pool_idx, backend.weight));

                let mut pool = BackendConnectionPool {
                    connections: Default::default(),
                    active_connections: 0,
                    rr_counter: 0,
                };

                info!(
                    "[{addr}] setting up connection pool ({})",
                    backend.pool_size
                );

                let mut remaining = backend.pool_size;

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
                                match Self::register_backend(
                                    self.event_tx.clone(),
                                    &mut self.tasks,
                                    stream,
                                    idx as u32,
                                    pool_idx,
                                    addr,
                                    backend_map,
                                ) {
                                    Ok(cookie) => {
                                        if pool.connections.push(cookie).is_err() {
                                            // this should never fail; pool limits are
                                            // validated during config compilation
                                            error!("infallible");
                                        }
                                    }

                                    Err(err) => error!("failed to register backend: {err}"),
                                }
                            }

                            Ok(Err(err)) => {
                                error!("failed to connect to backend {addr}: {err}");
                                // TODO: max reconnect attempt limit
                                let _ = self.event_tx.send(ManagerEvent::Disconnect {
                                    cluster_idx: idx as u32,
                                    pool_idx,
                                    addr,
                                    old_cookie: None,
                                });
                            }

                            Err(err) => {
                                error!("join error for {addr}: {err}");
                            }
                        }
                    }
                }

                if pool.connections.len > 0 {
                    info!(
                        "[{addr}] setup {} connections to backend",
                        pool.connections.len
                    );
                }

                if let Err(err) = backend_conn_pool_table.set(pool_idx, pool, 0) {
                    error!("failed to insert into BACKEND_CONNECTION_POOL_TABLE: {err}");
                }
            }

            cookie_map.insert(cluster_cfg.name.clone(), conn_pools);
        }

        Ok(cookie_map)
    }

    pub fn handle_event(
        &mut self,
        event: ManagerEvent,
        backend_map: &mut SockHash<MapData, SocketCookie>,
        backend_conn_pool_table: &mut Array<MapData, BackendConnectionPool>,
    ) {
        match event {
            ManagerEvent::Disconnect {
                cluster_idx,
                pool_idx,
                addr,
                old_cookie,
            } => {
                let tx = self.event_tx.clone();

                // TODO: improve error handling; the pool should exist here
                if let Some(old_cookie) = old_cookie
                    && let Ok(mut pool) = backend_conn_pool_table.get(&pool_idx, 0)
                {
                    // TODO: make this remove by value method internal to BoundedVec
                    if let Some(idx) = pool
                        .connections
                        .iter()
                        .position(|&cookie| cookie == old_cookie)
                    {
                        pool.connections.remove(idx);

                        if let Err(err) = backend_conn_pool_table.set(pool_idx, pool, 0) {
                            error!("failed to shrink connection pool: {err}");
                            return; // TODO: should not reconnect if pool can't be shrinked
                        }
                    }
                }

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
                                    pool_idx,
                                    addr,
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
                pool_idx,
                addr,
                new_cookie,
                stream,
            } => {
                if let Err(err) = backend_map.insert(new_cookie, stream.as_raw_fd(), 0) {
                    error!("failed to insert socket into BACKEND_CONNECTION_MAP: {err}");
                } else {
                    info!("inserted CK:{} into BACKEND_CONNECTION_MAP", new_cookie);
                }

                Self::spawn_connection_monitor(
                    self.event_tx.clone(),
                    &mut self.tasks,
                    stream,
                    cluster_idx,
                    pool_idx,
                    addr,
                    new_cookie,
                );

                // TODO: improve error handling
                if let Ok(mut pool) = backend_conn_pool_table.get(&pool_idx, 0) {
                    if pool.connections.push(new_cookie).is_err() {
                        error!("BACKEND_CONNECTION_POOL_TABLE overflow"); // TODO: should never happen
                        return;
                    }

                    if let Err(err) = backend_conn_pool_table.set(pool_idx, pool, 0) {
                        error!("failed to update BACKEND_CONNECTION_POOL_TABLE: {err}");
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
        pool_idx: u32,
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

        Self::spawn_connection_monitor(
            tx_event,
            tasks,
            stream,
            cluster_idx,
            pool_idx,
            addr,
            cookie,
        );

        Ok(cookie)
    }

    fn spawn_connection_monitor(
        tx_event: UnboundedSender<ManagerEvent>,
        tasks: &mut JoinSet<()>,
        mut stream: TcpStream,
        cluster_idx: u32,
        pool_idx: u32,
        addr: SocketAddr,
        cookie: SocketCookie,
    ) {
        tasks.spawn(async move {
            let mut buf = [0u8; 1];

            loop {
                match stream.read(&mut buf).await {
                    Ok(0) | Err(_) => {
                        info!("[{addr}] connection closed");

                        // TODO: add max reconnect attempt limit if it was an error response
                        // ; maybe an error counter to stop reconnecting when it overflows
                        let _ = tx_event.send(ManagerEvent::Disconnect {
                            cluster_idx,
                            pool_idx,
                            addr,
                            old_cookie: Some(cookie),
                        });

                        break;
                    }
                    _ => {}
                }
            }
        });
    }
}
