use std::{
    net::SocketAddr,
    os::fd::AsRawFd,
    time::Duration,
};

use anyhow::anyhow;
use backoff::{
    ExponentialBackoff,
    future::retry,
};
use log::{
    debug,
    error,
};
use tokio::{
    io::AsyncReadExt,
    net::TcpStream,
    sync::mpsc::UnboundedSender,
    task::{
        AbortHandle,
        JoinSet,
    },
};
use ulb_common::session::SocketCookie;

use crate::{
    backend::event::ManagerEvent,
    bpf_bootstrap::BackendConnectionMap,
    utils::get_socket_cookie,
};

// TODO: move this to config
const MAX_RETRY_DURATION: u64 = 30; // sec

pub fn register_backend(
    event_tx: UnboundedSender<ManagerEvent>,
    tasks: &mut JoinSet<()>,
    stream: TcpStream,
    cluster_idx: u32,
    pool_idx: u32,
    addr: SocketAddr,
    backend_map: &mut BackendConnectionMap,
) -> anyhow::Result<(SocketCookie, AbortHandle)> {
    let fd = stream.as_raw_fd();
    let cookie = get_socket_cookie(fd)?;

    backend_map
        .insert(cookie, fd, 0)
        .map_err(|err| anyhow!("failed to insert socket into BACKEND_CONNECTION_MAP: {err}"))?;

    let _ = stream.set_nodelay(true);
    let abort_handle =
        spawn_connection_monitor(event_tx, tasks, stream, cookie, cluster_idx, pool_idx, addr);
    Ok((cookie, abort_handle))
}

pub fn spawn_connection_monitor(
    event_tx: UnboundedSender<ManagerEvent>,
    tasks: &mut JoinSet<()>,
    mut stream: TcpStream,
    backend_cookie: SocketCookie,
    cluster_idx: u32,
    pool_idx: u32,
    addr: SocketAddr,
) -> AbortHandle {
    tasks.spawn(async move {
        let mut buf = [0u8; 1 << 6];
        loop {
            // TODO: add max reconnect attempt limit if it was an error response
            // ; maybe an error counter to stop reconnecting when it overflows
            let res = stream.read(&mut buf).await;

            if let Ok(0) | Err(_) = res {
                if let Err(err) = res {
                    debug!("[{addr}] connection closed: {err}");
                } else {
                    debug!("[{addr}] connection closed (eof)");
                }

                let _ = event_tx.send(ManagerEvent::Disconnect {
                    backend_cookie: Some(backend_cookie),
                    cluster_idx,
                    pool_idx,
                    addr,
                });

                break;
            }
        }
    })
}

pub fn handle_disconnect(
    event_tx: UnboundedSender<ManagerEvent>,
    tasks: &mut JoinSet<()>,
    cluster_idx: u32,
    pool_idx: u32,
    addr: SocketAddr,
) {
    tasks.spawn(async move {
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
                if let Ok(cookie) = get_socket_cookie(stream.as_raw_fd()) {
                    let _ = stream.set_nodelay(true);
                    let _ = event_tx.send(ManagerEvent::Reconnected {
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
