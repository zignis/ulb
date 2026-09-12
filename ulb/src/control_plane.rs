use std::{
    net::SocketAddr,
    num::NonZero,
    thread::available_parallelism,
};

use anyhow::anyhow;
use log::info;
use tokio::{
    io::AsyncReadExt,
    net::{
        TcpListener,
        TcpSocket,
    },
    task::JoinSet,
};
use tokio_util::sync::CancellationToken;
use ulb_common::ir::LISTEN_BACKLOG_QUEUE_SIZE;

use crate::config::canonical::UlbConfig;

pub struct ControlPlane {
    tasks: JoinSet<()>,
    shutdown_token: CancellationToken,
}

impl ControlPlane {
    pub fn new(shutdown_token: CancellationToken) -> Self {
        Self {
            tasks: JoinSet::new(),
            shutdown_token,
        }
    }

    pub fn start(&mut self, cfg: &UlbConfig) -> anyhow::Result<()> {
        let num_cores = available_parallelism().map_or(4, NonZero::get);
        info!("starting {num_cores} workers per listener");

        for listener_cfg in &cfg.listeners {
            let addr = listener_cfg.addr;

            for _ in 0..num_cores {
                let listener = bind_port(addr)?;
                let shutdown_token = self.shutdown_token.clone();

                // TODO: reduce nesting inside the task
                self.tasks.spawn(async move {
                    loop {
                        tokio::select! {
                            Ok((stream, _)) = listener.accept() => {
                                let _ = stream.set_nodelay(true);
                                let task_shutdown = shutdown_token.clone();

                                // EOF detection task
                                tokio::spawn(async move {
                                    let mut stream = stream;
                                    let mut buf = [0u8; 1];

                                    loop {
                                        tokio::select! {
                                            () = task_shutdown.cancelled() => {
                                                break;
                                            }

                                            res = stream.read(&mut buf) => {
                                                if let Ok(0) | Err(_) = res {
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                });
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

        Ok(())
    }

    pub async fn shutdown(&mut self) {
        while self.tasks.join_next().await.is_some() {}
    }
}

fn bind_port(addr: SocketAddr) -> anyhow::Result<TcpListener> {
    let socket = if addr.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };

    socket
        .set_reuseport(true)
        .map_err(|err| anyhow!("failed to set `reuseport` opt: {err}"))?;
    socket.bind(addr)?;

    Ok(socket.listen(LISTEN_BACKLOG_QUEUE_SIZE)?)
}
