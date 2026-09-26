use std::os::fd::AsRawFd;

use log::{
    error,
    info,
};
use tokio::{
    sync::mpsc::{
        UnboundedReceiver,
        UnboundedSender,
        unbounded_channel,
    },
    task::JoinSet,
};

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

pub struct BackendManager {
    tasks: JoinSet<()>,
    event_tx: UnboundedSender<ManagerEvent>,
    event_rx: UnboundedReceiver<ManagerEvent>,
}

impl Default for BackendManager {
    fn default() -> Self {
        let (event_tx, event_rx) = unbounded_channel();
        Self {
            event_tx,
            event_rx,
            tasks: JoinSet::new(),
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
        backend_map: &mut BackendConnectionMap,
        backend_conn_pool_table: &mut BackendConnectionPoolTable,
        backend_conn_pool_stats_table: &mut BackendConnectionPoolStatsTable,
    ) -> anyhow::Result<ClusterConnectionPoolMap> {
        initialize_clusters(
            self.event_tx.clone(),
            &mut self.tasks,
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
                cluster_idx,
                pool_idx,
                addr,
            } => {
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
                    info!("inserted CK:{} into BACKEND_CONNECTION_MAP", new_cookie);
                }

                spawn_connection_monitor(
                    self.event_tx.clone(),
                    &mut self.tasks,
                    stream,
                    cluster_idx,
                    pool_idx,
                    addr,
                );

                if let Ok(mut queue) = backend_conn_pool_table.get(&pool_idx, 0) {
                    if let Err(err) = queue.push(new_cookie, BPF_EXIST) {
                        error!("failed to push to queue in BACKEND_CONNECTION_POOL_TABLE: {err}");
                    }
                } else {
                    error!("failed to get queue from BACKEND_CONNECTION_POOL_TABLE");
                }
            }
        }
    }
}
