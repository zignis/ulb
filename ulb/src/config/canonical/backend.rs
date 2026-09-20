use std::net::SocketAddr;

use serde::{
    Deserialize,
    Serialize,
};
use ulb_common::ir::{
    DEFAULT_BACKEND_WEIGHT,
    MAX_BACKEND_CONNECTION_POOL_SIZE,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendConfig {
    pub addr: SocketAddr,
    #[serde(default = "default_pool_size")]
    pub pool_size: usize,
    #[serde(default = "default_weight")]
    pub weight: u32,
}

// https://github.com/serde-rs/serde/issues/368
fn default_pool_size() -> usize {
    MAX_BACKEND_CONNECTION_POOL_SIZE
}

fn default_weight() -> u32 {
    DEFAULT_BACKEND_WEIGHT
}
