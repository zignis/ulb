run:
    cargo run --release

run_debug:
    RUST_LOG=debug cargo run --release --features=debug

build:
    cargo build --release

build_debug:
    cargo build --release --features=debug

fmt:
    cargo +nightly fmt

clippy:
    cargo clippy --workspace --exclude ulb-ebpf --all-targets --all-features -- -D warnings
    cargo +nightly clippy -p ulb-ebpf --target bpfel-unknown-none -Z build-std=core --all-features -- -D warnings

taplo:
    taplo format

gen_schema:
    cargo run --bin gen_schema --features schema > schemas/ulb.schema.json
