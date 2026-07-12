use aya::{
    maps::SockMap,
    programs::SkSkb,
};
use log::error;
use tokio::{
    net::TcpListener,
    signal,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/ulb"
    )))?;

    #[cfg(feature = "debug")]
    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => {
            // can happen if there are no log statements in ebpf program
            log::warn!("failed to initialize ebpf logger: {e}");
        }
        Ok(logger) => {
            let mut logger =
                tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;

            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }

    let mut conn_map: SockMap<_> = SockMap::try_from(ebpf.take_map("CONN_MAP").unwrap())?;

    let parser: &mut SkSkb = ebpf.program_mut("stream_parser").unwrap().try_into()?;
    parser.load()?;
    parser.attach(conn_map.fd())?;

    let verdict: &mut SkSkb = ebpf.program_mut("stream_verdict").unwrap().try_into()?;
    verdict.load()?;
    verdict.attach(conn_map.fd())?;

    let listener = TcpListener::bind("0.0.0.0:8082").await?;
    println!("listening on http://localhost:8082");

    loop {
        tokio::select! {
            res = listener.accept() => {
                let (mut stream, peer_addr) = res?;
                println!("accepted {}", peer_addr);

                if let Err(err) = conn_map.set(0, &stream, 0) {
                    error!("failed to insert fd: {}", err);
                }

                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt};
                    let mut buf = [0u8; 1024];
                    let _ = stream.read(&mut buf).await;
                });
            }

            _ = signal::ctrl_c() => {
                println!("received SIGINT");
                break;
            }
        }
    }

    Ok(())
}
