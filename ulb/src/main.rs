use aya::{
    maps::{
        ProgramArray,
        SockMap,
    },
    programs::SkSkb,
};
use log::error;
use tokio::{
    net::TcpListener,
    signal,
};
use ulb_common::JMP_PROG_ROUTING;

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

    let mut connection_map: SockHash<_, SocketCookie> = SockHash::try_from(
        ebpf.take_map("CONNECTION_MAP")
            .ok_or_else(|| anyhow!("missing `CONNECTION_MAP`"))?,
    )?;

    let mut backend_map: SockHash<_, SocketCookie> = SockHash::try_from(
        ebpf.take_map("BACKEND_MAP")
            .ok_or_else(|| anyhow!("missing `BACKEND_MAP`"))?,
    )?;

    let parser: &mut SkSkb = ebpf
        .program_mut("stream_parser")
        .ok_or_else(|| anyhow!("missing `stream_parser` prog"))?
        .try_into()?;
    parser.load()?;
    parser.attach(connection_map.fd())?;
    parser.attach(backend_map.fd())?;

    let verdict: &mut SkSkb = ebpf
        .program_mut("stream_verdict")
        .ok_or_else(|| anyhow!("missing `stream_verdict` prog"))?
        .try_into()?;
    verdict.load()?;
    verdict.attach(connection_map.fd())?;
    verdict.attach(backend_map.fd())?;

    // jump table for tail calls
    let mut jmp_table: ProgramArray<_> = ProgramArray::try_from(
        ebpf.take_map("JMP_TABLE")
            .ok_or_else(|| anyhow!("missing `JMP_TABLE`"))?,
    )?;

    let router: &mut SkSkb = ebpf
        .program_mut("router")
        .ok_or_else(|| anyhow!("missing `router` prog"))?
        .try_into()?;
    router.load()?;

    // jump table for tail calls
    let mut jmp_table: ProgramArray<_> =
        ProgramArray::try_from(ebpf.take_map("JMP_TABLE").unwrap())?;
    jmp_table.set(JMP_PROG_ROUTING, router.fd().unwrap(), 0)?;

    let listener = TcpListener::bind("0.0.0.0:8082").await?;
    println!("listening on http://localhost:8082");

    loop {
        tokio::select! {
            res = listener.accept() => {
                let (mut stream, peer_addr) = res?;
                println!("accepted {}", peer_addr);

                if let Err(err) = connection_map.set(0, &stream, 0) {
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
