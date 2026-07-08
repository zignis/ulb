use anyhow::Context as _;
use clap::Parser;
#[rustfmt::skip]
use log::{debug, warn};
use tokio::signal;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/ulb"
    )))?;

    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => {
            // can happen if there are no log statements in ebpf program
            warn!("failed to initialize ebpf logger: {e}");
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
    
    let sigint = signal::ctrl_c();
    println!("waiting for SIGINT...");
    sigint.await?;
    println!("exiting...");

    Ok(())
}
