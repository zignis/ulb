use std::net::SocketAddr;

use tokio::net::TcpStream;
use ulb_common::session::SocketCookie;

#[derive(Debug)]
pub enum ManagerEvent {
    Disconnect {
        cluster_idx: u32,
        pool_idx: u32,
        addr: SocketAddr,
    },
    Reconnected {
        cluster_idx: u32,
        pool_idx: u32,
        addr: SocketAddr,
        new_cookie: SocketCookie,
        stream: TcpStream,
    },
}
