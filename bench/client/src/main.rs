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
use rand::{
    RngExt,
    distr::OpenClosed01,
};
use tokio::{
    net::TcpStream,
    time::{
        sleep,
        timeout,
    },
};

const HIST_UPPER_BOUND: u64 = 10_000_000;
const BODY_CH: u8 = b'#';
const MIN_HEADERS: usize = 3; // host, connection, content-length
const NUM_SAMPLES: usize = 5;
const WARMUP_SECS: u64 = 10;
const DEFAULT_TIMEOUT: u64 = 10_000; // ms
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
    #[arg(long, default_value_t = MIN_HEADERS)]
    header_count: usize,
    /// mean think time in sec (closeloop: sleep after each response; openloop:
    /// mean inter-arrival time per worker)
    #[arg(long, default_value_t = 0.0)]
    think_time: f64,
    /// openloop arrivals
    #[arg(long)]
    open_loop: bool,
    /// target aggregate rps
    #[arg(long)]
    rps: Option<u64>,
    /// per req timeout
    #[arg(long, default_value_t = DEFAULT_TIMEOUT)]
    timeout: u64,
    #[arg(long)]
    plain_output: bool,
}

#[derive(Debug, Clone, Copy)]
struct Mode {
    think_time: f64,
    open_loop: bool,
}

#[derive(Debug)]
struct PhaseResult {
    hist: Histogram<u64>,
    reqs: u64,
    errs: u64,
    elapsed: f64,
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

async fn sleep_unless_stopped(dur: Duration, stop: &AtomicBool) {
    let deadline = Instant::now() + dur;

    loop {
        if stop.load(Ordering::Relaxed) {
            return;
        }

        let now = Instant::now();
        if now >= deadline {
            return;
        }

        sleep((deadline - now).min(Duration::from_millis(20))).await;
    }
}

async fn backoff_after_conn_error(mode: Mode, next_intended_start: &mut Instant) {
    if mode.open_loop {
        let now = Instant::now();
        while *next_intended_start <= now {
            *next_intended_start += exp_wait(mode.think_time);
        }
    }

    sleep(Duration::from_millis(1)).await;
}

async fn worker(
    stop: Arc<AtomicBool>,
    addr: SocketAddr,
    req_body_size: usize,
    keep_alive: bool,
    mode: Mode,
    req_timeout: Duration,
    headers: Arc<Vec<(HeaderName, HeaderValue)>>,
) -> (Histogram<u64>, u64, u64) {
    let mut hist = Histogram::<u64>::new_with_bounds(1, HIST_UPPER_BOUND, 3).unwrap();
    let mut reqs: u64 = 0;
    let mut errs: u64 = 0;
    let body = Bytes::from(vec![BODY_CH; req_body_size]);
    let req = build_request(&body, keep_alive, &headers);
    let mut next_intended_start = Instant::now()
        + if mode.open_loop {
            exp_wait(mode.think_time)
        } else {
            Duration::ZERO
        }; // prevent bursty connections on boot

    while !stop.load(Ordering::Relaxed) {
        if mode.open_loop && !keep_alive {
            let now = Instant::now();
            if now < next_intended_start {
                sleep_unless_stopped(next_intended_start - now, &stop).await;
                if stop.load(Ordering::Relaxed) {
                    break;
                }
            }
        }

        let conn_start = Instant::now();
        let stream = match timeout(req_timeout, TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => {
                let _ = stream.set_nodelay(true);
                stream
            }
            _ => {
                errs += 1;
                backoff_after_conn_error(mode, &mut next_intended_start).await;
                continue;
            }
        };

        let (mut sender, conn) =
            match timeout(req_timeout, http1::handshake(TokioIo::new(stream))).await {
                Ok(Ok(conn)) => conn,
                _ => {
                    errs += 1;
                    backoff_after_conn_error(mode, &mut next_intended_start).await;
                    continue;
                }
            };

        tokio::spawn(async move {
            let _ = conn.await;
        });

        let mut first_on_conn = true;

        loop {
            if stop.load(Ordering::Relaxed) {
                break;
            }

            if sender.ready().await.is_err() {
                errs += 1;
                sleep(Duration::from_millis(1)).await;
                break;
            }

            // wait until the intended send time
            if mode.open_loop {
                let now = Instant::now();
                if now < next_intended_start {
                    sleep_unless_stopped(next_intended_start - now, &stop).await;
                    if stop.load(Ordering::Relaxed) {
                        break;
                    }
                }
            }

            let start_time = if mode.open_loop {
                let start = next_intended_start;
                next_intended_start += exp_wait(mode.think_time);
                start
            } else if !keep_alive && first_on_conn {
                conn_start
            } else {
                Instant::now()
            };

            first_on_conn = false;

            let req_clone = req.clone();
            let result = timeout(req_timeout, async {
                let mut res = sender.send_request(req_clone).await.map_err(|_| ())?;
                let status = res.status();

                while let Some(frame) = res.body_mut().frame().await {
                    frame.map_err(|_| ())?;
                }

                Ok::<_, ()>(status)
            })
            .await;

            match result {
                Ok(Ok(status)) => {
                    if status.is_success() {
                        let elapsed = start_time.elapsed().as_micros() as u64;
                        hist.saturating_record(elapsed.max(1));
                        reqs += 1;
                    } else {
                        // conn still healthy
                        errs += 1;
                    }

                    if !mode.open_loop && mode.think_time > 0.0 {
                        sleep_unless_stopped(exp_wait(mode.think_time), &stop).await;
                    }
                }

                Ok(Err(_)) | Err(_) => {
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
    mode: Mode,
    headers: Arc<Vec<(HeaderName, HeaderValue)>>,
) -> PhaseResult {
    let stop = Arc::new(AtomicBool::new(false));
    let req_timeout = Duration::from_millis(args.timeout);
    let start = Instant::now();
    let mut handles = Vec::with_capacity(args.workers);

    for _ in 0..args.workers {
        handles.push(tokio::spawn(worker(
            stop.clone(),
            args.addr,
            args.req_body_size,
            args.keep_alive,
            mode,
            req_timeout,
            headers.clone(),
        )));
    }

    sleep(Duration::from_secs(duration)).await;
    stop.store(true, Ordering::Relaxed);

    let mut hist = Histogram::<u64>::new_with_bounds(1, HIST_UPPER_BOUND, 3).unwrap();
    let mut reqs = 0;
    let mut errs = 0;

    for handle in handles {
        if let Ok((h, r, e)) = handle.await {
            hist.add(h).unwrap();
            reqs += r;
            errs += e;
        }
    }

    let elapsed = start.elapsed().as_secs_f64();

    PhaseResult {
        hist,
        reqs,
        errs,
        elapsed,
    }
}

#[inline(always)]
fn exp_wait(think_time: f64) -> Duration {
    let u: f64 = rand::rng().sample(OpenClosed01);
    let wait = (-think_time * u.ln()).max(0.0);
    Duration::from_secs_f64(wait)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    if args.header_count < MIN_HEADERS {
        eprintln!("`header_count` must be at least {MIN_HEADERS}");
        exit(1);
    }

    if args.workers == 0 {
        eprintln!("`workers` must be at least 1");
        exit(1);
    }

    if args.think_time < 0.0 {
        eprintln!("`think_time` must not be negative");
        exit(1);
    }

    if args.rps.is_some() && args.think_time > 0.0 {
        eprintln!("`rps` and `think_time` are mutually exclusive");
        exit(1);
    }

    let mut mode = Mode {
        think_time: args.think_time,
        open_loop: args.open_loop,
    };

    if let Some(rps) = args.rps {
        if rps == 0 {
            eprintln!("`rps` must be greater than 0");
            exit(1);
        }

        mode.think_time = args.workers as f64 / rps as f64;
        mode.open_loop = true;
    }

    if mode.open_loop && mode.think_time <= 0.0 {
        eprintln!("`open_loop` needs `think_time` > 0 or `rps` opt");
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
        println!(">>> warmup ({WARMUP_SECS}s) <<<");
    }

    let _ = run_phase(&args, WARMUP_SECS, mode, headers.clone()).await;

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
            println!(">>> run {run}/{NUM_SAMPLES} ({}s)...", args.duration);
        }

        let phase = run_phase(&args, args.duration, mode, headers.clone()).await;
        let rps = phase.reqs as f64 / phase.elapsed;
        total_rps += rps;
        global_reqs += phase.reqs;
        global_errs += phase.errs;
        global_hist.add(phase.hist)?;

        if !args.plain_output {
            println!(
                ">>> rps: {rps:.2} | reqs: {} | errs: {}",
                phase.reqs, phase.errs
            );
        }
    }

    let avg_rps = (total_rps / NUM_SAMPLES as f64).round() as u64;
    let p50_lat = global_hist.value_at_percentile(50.0);
    let p75_lat = global_hist.value_at_percentile(75.0);
    let p99_lat = global_hist.value_at_percentile(99.0);
    let p999_lat = global_hist.value_at_percentile(99.9);

    if args.plain_output {
        println!("{avg_rps}|{p50_lat}|{p75_lat}|{p99_lat}|{p999_lat}|{global_reqs}|{global_errs}");
    } else {
        println!();
        println!(">>> results <<<");

        if let Some(target) = args.rps {
            println!(">>> target rps: {target}");
        }

        println!(">>> avg rps: {avg_rps}");
        println!(">>> p50 lat: {p50_lat} (us)");
        println!(">>> p75 lat: {p75_lat} (us)");
        println!(">>> p99 lat: {p99_lat} (us)");
        println!(">>> p99.9 lat: {p999_lat} (us)");
        println!(">>> total reqs: {global_reqs}");
        println!(">>> total errs: {global_errs}");
    }

    Ok(())
}
