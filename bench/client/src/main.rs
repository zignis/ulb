use std::{
    error::Error,
    net::SocketAddr,
    process::exit,
    sync::{
        Arc,
        atomic::{
            AtomicBool,
            Ordering,
        },
    },
    time::{
        Duration,
        Instant,
    },
};

use clap::Parser;
use hdrhistogram::Histogram;
use http_body_util::{
    BodyExt,
    Full,
};
use hyper::{
    Request,
    body::Bytes,
    client::conn::http1,
    header::{
        CONNECTION,
        HOST,
        HeaderName,
        HeaderValue,
    },
};
use hyper_util::rt::TokioIo;
use tokio::{
    net::TcpStream,
    time::sleep,
};

const HIST_UPPER_BOUND: u64 = 10_000_000;
const BODY_CH: u8 = b'#';
const MIN_HEADERS: usize = 2;
const NUM_SAMPLES: usize = 5;
const HOST_HEADER: &str = "bench.local";
const BENCH_HDR_KEY_PREFIX: &str = "x-bench-hdr";
const BENCH_HDR_VAL_PREFIX: &str = "bench-hdr-val";

#[derive(Debug, Parser, Clone)]
struct Args {
    #[arg(long, default_value = "127.0.0.1:8085")]
    addr: SocketAddr,
    #[arg(long, default_value_t = 15)]
    duration: u64,
    #[arg(long, default_value_t = 0)]
    req_body_size: usize,
    #[arg(long, default_value_t = 1)]
    workers: usize,
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    keep_alive: bool,
    #[arg(long, default_value_t = 2)]
    header_count: usize,
    #[arg(long)]
    plain_output: bool,
}

fn build_request(
    body: &Bytes,
    keep_alive: bool,
    headers: &[(HeaderName, HeaderValue)],
) -> Request<Full<Bytes>> {
    let mut builder = Request::post("/")
        .header(HOST, HOST_HEADER)
        .header(CONNECTION, if keep_alive { "keep-alive" } else { "close" });

    for (key, val) in headers {
        builder = builder.header(key, val);
    }

    builder.body(Full::new(body.clone())).unwrap()
}

async fn worker(
    stop: Arc<AtomicBool>,
    addr: SocketAddr,
    req_body_size: usize,
    keep_alive: bool,
    headers: Arc<Vec<(HeaderName, HeaderValue)>>,
) -> (Histogram<u64>, u64, u64) {
    let mut hist = Histogram::<u64>::new_with_bounds(1, HIST_UPPER_BOUND, 3).unwrap();
    let mut reqs = 0;
    let mut errs = 0;
    let body = Bytes::from(vec![BODY_CH; req_body_size]);
    let req = build_request(&body, keep_alive, &headers);

    while !stop.load(Ordering::Relaxed) {
        let stream = match TcpStream::connect(addr).await {
            Ok(stream) => {
                let _ = stream.set_nodelay(true);
                stream
            }
            Err(_) => {
                errs += 1;
                sleep(Duration::from_millis(1)).await;
                continue;
            }
        };

        let (mut sender, conn) = match http1::handshake(TokioIo::new(stream)).await {
            Ok(conn) => conn,
            Err(_) => {
                errs += 1;
                sleep(Duration::from_millis(1)).await;
                continue;
            }
        };

        tokio::spawn(async move {
            let _ = conn.await;
        });

        loop {
            if stop.load(Ordering::Relaxed) {
                break;
            }

            if sender.ready().await.is_err() {
                errs += 1;
                sleep(Duration::from_millis(1)).await;
                break;
            }

            let req_clone = req.clone();
            let now = Instant::now();

            match sender.send_request(req_clone).await {
                Ok(mut res) => {
                    if !res.status().is_success() {
                        errs += 1;
                        sleep(Duration::from_millis(1)).await;
                        break;
                    }

                    let mut ok = true;
                    while let Some(frame) = res.body_mut().frame().await {
                        if frame.is_err() {
                            ok = false;
                            break;
                        }
                    }

                    if ok {
                        let elapsed = now.elapsed().as_micros() as u64;
                        if elapsed > 0 {
                            let _ = hist.record(elapsed);
                        }
                        reqs += 1;
                    } else {
                        errs += 1;
                        sleep(Duration::from_millis(1)).await;
                        break;
                    }
                }

                Err(_) => {
                    errs += 1;
                    sleep(Duration::from_millis(1)).await;
                    break;
                }
            }

            if !keep_alive {
                break;
            }
        }
    }

    (hist, reqs, errs)
}

async fn run_phase(
    args: &Args,
    duration: u64,
    headers: Arc<Vec<(HeaderName, HeaderValue)>>,
) -> (Histogram<u64>, u64, u64, f64) {
    let stop = Arc::new(AtomicBool::new(false));
    let start = Instant::now();
    let mut handles = Vec::new();

    for _ in 0..args.workers {
        handles.push(tokio::spawn(worker(
            stop.clone(),
            args.addr,
            args.req_body_size,
            args.keep_alive,
            headers.clone(),
        )));
    }

    sleep(Duration::from_secs(duration)).await;
    stop.store(true, Ordering::Relaxed);
    let elapsed = start.elapsed().as_secs_f64();
    sleep(Duration::from_secs(5)).await; // grace

    for handle in &handles {
        handle.abort();
    }

    let mut merged_hist = Histogram::<u64>::new_with_bounds(1, HIST_UPPER_BOUND, 3).unwrap();
    let mut total_reqs = 0;
    let mut total_errs = 0;

    for handle in handles {
        if let Ok((hist, reqs, errs)) = handle.await {
            merged_hist.add(hist).unwrap();
            total_reqs += reqs;
            total_errs += errs;
        }
    }

    (merged_hist, total_reqs, total_errs, elapsed)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    if args.header_count < MIN_HEADERS {
        eprintln!("`header_count` must be at least {MIN_HEADERS}");
        exit(1);
    }

    let mut headers = Vec::new();

    for i in 0..(args.header_count - MIN_HEADERS) {
        let key = HeaderName::from_bytes(format!("{BENCH_HDR_KEY_PREFIX}-{}", i + 1).as_bytes())?;
        let val = HeaderValue::from_bytes(format!("{BENCH_HDR_VAL_PREFIX}-{}", i + 1).as_bytes())?;
        headers.push((key, val));
    }

    let headers = Arc::new(headers);

    if !args.plain_output {
        println!(">>> warmup (10s) <<<");
    }

    let _ = run_phase(&args, 10, headers.clone()).await;

    if !args.plain_output {
        println!();
        println!(">>> benchmark ({} workers) <<<", args.workers);
    }

    let mut total_rps = 0.0;
    let mut global_hist = Histogram::<u64>::new_with_bounds(1, HIST_UPPER_BOUND, 3)?;
    let mut global_reqs = 0;
    let mut global_errs = 0;

    for run in 1..=NUM_SAMPLES {
        if !args.plain_output {
            println!(">>> run {run}/5 ({}s)...", args.duration);
        }

        let (hist, reqs, errs, elapsed) = run_phase(&args, args.duration, headers.clone()).await;
        let rps = reqs as f64 / elapsed;
        total_rps += rps;
        global_reqs += reqs;
        global_errs += errs;
        global_hist.add(hist)?;

        if !args.plain_output {
            println!(">>> rps: {rps:.2} | reqs: {reqs} | errs: {errs}");
        }
    }

    let avg_rps = (total_rps / NUM_SAMPLES as f64).round() as u64;
    let p99_lat = global_hist.value_at_percentile(99.0);

    if args.plain_output {
        println!("{avg_rps}|{p99_lat}|{global_reqs}|{global_errs}");
    } else {
        println!();
        println!(">>> results <<<");
        println!(">>> avg rps: {avg_rps}");
        println!(">>> p99 lat: {p99_lat} (us)");
        println!(">>> total reqs: {global_reqs}");
        println!(">>> total errs: {global_errs}");
    }

    Ok(())
}
