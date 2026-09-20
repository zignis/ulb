use std::net::SocketAddr;

use serde::{
    Deserialize,
    Serialize,
};

use crate::config::canonical::VHostConfig;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListenerConfig {
    pub name: String,
    pub addr: SocketAddr,
    pub hosts: Vec<VHostConfig>,
}
