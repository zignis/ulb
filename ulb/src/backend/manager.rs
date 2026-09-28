use std::{
    collections::HashMap,
    net::SocketAddr,
    os::fd::AsRawFd,
};

use log::{
    debug,
    error,
    info,
};
use tokio::{
    sync::mpsc::{
        UnboundedReceiver,
        UnboundedSender,
        unbounded_channel,
    },
    task::{
        AbortHandle,
        JoinSet,
    },
};
use ulb_common::session::SocketCookie;

use crate::{
    backend::{
        cluster::initialize_clusters,
        connection::{
            handle_disconnect,
            spawn_connection_monitor,
        },
        event::ManagerEvent,
    },
    bpf_bootstrap::{
        BPF_EXIST,
        BackendConnectionMap,
        BackendConnectionPoolStatsTable,
        BackendConnectionPoolTable,
    },
    config::canonical::{
        ClusterConnectionPoolMap,
        UlbConfig,
    },
};

#[derive(Debug)]
pub struct BackendConnection {
    pub abort_handle: AbortHandle,
    pub cluster_idx: u32,
    pub pool_idx: u32,
    pub addr: SocketAddr,
}

pub struct BackendManager {
    tasks: JoinSet<()>,
    event_tx: UnboundedSender<ManagerEvent>,
    event_rx: UnboundedReceiver<ManagerEvent>,
    backend_connections: HashMap<SocketCookie, BackendConnection>,
}

impl Default for BackendManager {
    fn default() -> Self {
        let (event_tx, event_rx) = unbounded_channel();
        Self {
            event_tx,
            event_rx,
            tasks: JoinSet::new(),
            backend_connections: HashMap::new(),
        }
    }
}

impl BackendManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get_event_tx(&self) -> UnboundedSender<ManagerEvent> {
        self.event_tx.clone()
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
        backend_map: &mut BackendConnectionMap,
        backend_conn_pool_table: &mut BackendConnectionPoolTable,
        backend_conn_pool_stats_table: &mut BackendConnectionPoolStatsTable,
    ) -> anyhow::Result<ClusterConnectionPoolMap> {
        initialize_clusters(
            self.event_tx.clone(),
            &mut self.tasks,
            &mut self.backend_connections,
            cfg,
            backend_map,
            backend_conn_pool_table,
            backend_conn_pool_stats_table,
        )
        .await
    }

    pub fn handle_event(
        &mut self,
        event: ManagerEvent,
        backend_map: &mut BackendConnectionMap,
        backend_conn_pool_table: &mut BackendConnectionPoolTable,
    ) {
        match event {
            ManagerEvent::Disconnect {
                backend_cookie,
                cluster_idx,
                pool_idx,
                addr,
            } => {
                if let Some(cookie) = backend_cookie {
                    self.backend_connections.remove(&cookie);
                }

                handle_disconnect(
                    self.event_tx.clone(),
                    &mut self.tasks,
                    cluster_idx,
                    pool_idx,
                    addr,
                );
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
                    debug!("inserted CK:{new_cookie} into BACKEND_CONNECTION_MAP");
                }

                let abort_handle = spawn_connection_monitor(
                    self.event_tx.clone(),
                    &mut self.tasks,
                    stream,
                    new_cookie,
                    cluster_idx,
                    pool_idx,
                    addr,
                );

                self.backend_connections.insert(
                    new_cookie,
                    BackendConnection {
                        abort_handle,
                        cluster_idx,
                        pool_idx,
                        addr,
                    },
                );

                if let Ok(mut queue) = backend_conn_pool_table.get(&pool_idx, 0) {
                    if let Err(err) = queue.push(new_cookie, BPF_EXIST) {
                        error!("failed to push to queue in BACKEND_CONNECTION_POOL_TABLE: {err}");
                    }
                } else {
                    error!("failed to get queue from BACKEND_CONNECTION_POOL_TABLE");
                }
            }

            ManagerEvent::TerminateSession(backend_cookie) => {
                if let Some(connection) = self.backend_connections.remove(&backend_cookie) {
                    connection.abort_handle.abort();

                    handle_disconnect(
                        self.event_tx.clone(),
                        &mut self.tasks,
                        connection.cluster_idx,
                        connection.pool_idx,
                        connection.addr,
                    );
                }
            }
        }
    }
}
