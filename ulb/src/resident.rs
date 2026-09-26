use std::net::SocketAddr;

use log::{
    debug,
    error,
};
use tokio::{
    io::copy_bidirectional,
    net::TcpStream,
};
use tokio_util::sync::CancellationToken;

// TODO: use splice(2) syscall

pub async fn handle_resident_session(
    mut client_stream: TcpStream,
    backend_addr: SocketAddr,
    shutdown_token: CancellationToken,
) {
    let mut backend_stream = match TcpStream::connect(backend_addr).await {
        Ok(x) => x,
        Err(err) => {
            error!("failed to connect to {backend_addr}: {err}");
            return;
        }
    };

    let _ = client_stream.set_nodelay(true);
    let _ = backend_stream.set_nodelay(true);

    tokio::select! {
        res = copy_bidirectional(&mut client_stream, &mut backend_stream) => {
            if let Err(err) = res {
                debug!("connection closed: {err}");
            }
        }

        _ = shutdown_token.cancelled() => {
            debug!("session cancelled");
        }
    }
}
