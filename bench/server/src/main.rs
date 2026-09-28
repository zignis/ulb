use std::{
    convert::Infallible,
    error::Error,
    net::SocketAddr,
    time::Duration,
};

use clap::Parser;
use http_body_util::{
    BodyExt,
    Full,
};
use hyper::{
    Request,
    Response,
    body::{
        Bytes,
        Incoming,
    },
    header::CONNECTION,
    http::HeaderValue,
    server::conn::http1,
    service::service_fn,
};
use hyper_util::rt::TokioIo;
use mimalloc::MiMalloc;
use tokio::{
    net::TcpSocket,
    time::sleep,
};

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

const BODY_CH: u8 = b'#';
const MAX_HEADERS: usize = 300;
const BACKLOG_QUEUE_SIZE: u32 = 65536;

#[derive(Debug, Parser)]
struct Args {
    #[arg(long, default_value = "0.0.0.0:8095")]
    addr: SocketAddr,
    #[arg(long, default_value_t = 0)]
    res_body_size: usize,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    let body = Bytes::from(vec![BODY_CH; args.res_body_size]);
    let socket = TcpSocket::new_v4()?;
    socket.set_reuseaddr(true)?;
    socket.bind(args.addr)?;
    let listener = socket.listen(BACKLOG_QUEUE_SIZE)?;

    println!(">>> listening on http://{} <<<", args.addr);

    loop {
        let (stream, _) = match listener.accept().await {
            Ok(res) => res,
            Err(err) => {
                eprintln!("accept error: {err}");
                sleep(Duration::from_millis(10)).await;
                continue;
            }
        };

        let _ = stream.set_nodelay(true);
        let body = body.clone();

        tokio::spawn(async move {
            let service = service_fn(move |req: Request<Incoming>| {
                let body = body.clone();
                async move {
                    let mut req_body = req.into_body();
                    while req_body.frame().await.is_some() {}
                    let mut res = Response::new(Full::new(body.clone()));
                    res.headers_mut()
                        .insert(CONNECTION, HeaderValue::from_static("keep-alive"));
                    Ok::<_, Infallible>(res)
                }
            });

            http1::Builder::new()
                .keep_alive(true)
                .max_headers(MAX_HEADERS)
                .serve_connection(TokioIo::new(stream), service)
                .await
                .ok();
        });
    }
}
