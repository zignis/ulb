run:
    cargo run --release

run_debug:
    RUST_LOG=info cargo run --release --features=debug

build:
    cargo build --release

build_debug:
    cargo build --release --features=debug