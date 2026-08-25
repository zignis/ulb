use std::{
    collections::HashMap,
    net::SocketAddr,
};

use serde::{
    Deserialize,
    Serialize,
};
use ulb_common::ir::MAX_BACKEND_CONNECTION_POOL_SIZE;

pub type BackendConnectionPoolIdx = u32;

// <cluster name, list of indices into BACKEND_CONNECTION_POOL_TABLE for each
// backend under this cluster>
pub type ClusterConnectionPoolMap = HashMap<String, Vec<BackendConnectionPoolIdx>>;

// <cluster name, idx in CLUSTER_TABLE>
pub type ClusterIdxMap = HashMap<String, u32>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UlbConfig {
    pub listeners: Vec<ListenerConfig>,
    pub clusters: Vec<ClusterConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListenerConfig {
    pub name: String,
    pub addr: SocketAddr,
    pub hosts: Vec<VHostConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VHostConfig {
    pub host: String,
    pub routes: Vec<RouteConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RouteAction {
    Forward { cluster: String },
    Drop,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeaderMatchConfig {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteConfig {
    pub path: String,
    pub methods: Vec<String>,
    #[serde(default)]
    pub headers: Vec<HeaderMatchConfig>,
    pub action: RouteAction,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterConfig {
    pub name: String,
    pub backends: Vec<BackendConfig>,
}

// https://github.com/serde-rs/serde/issues/368
fn default_pool_size() -> usize {
    MAX_BACKEND_CONNECTION_POOL_SIZE
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendConfig {
    pub addr: SocketAddr,
    #[serde(default = "default_pool_size")]
    pub pool_size: usize,
}
