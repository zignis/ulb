use std::{
    collections::HashMap,
    net::SocketAddr,
};

use serde::{
    Deserialize,
    Serialize,
};
use ulb_common::ir::{
    LoadBalancingPolicy,
    MAX_BACKEND_CONNECTION_POOL_SIZE,
};

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
pub struct HeaderMatchConfig {
    pub name: String,
    pub value: String,
    #[serde(default)]
    pub case_insensitive: bool,
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
    pub policy: Option<LoadBalancingPolicy>,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(try_from = "RouteActionParser")]
pub enum RouteAction {
    Forward(String /* cluster name */),
    Drop,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum RouteActionParser {
    Map(HashMap<String, String>),
    Str(String),
}

impl TryFrom<RouteActionParser> for RouteAction {
    type Error = String;

    fn try_from(helper: RouteActionParser) -> Result<Self, Self::Error> {
        if let RouteActionParser::Map(ref map) = helper
            && let Some(cluster) = map.get("forward")
        {
            return Ok(RouteAction::Forward(cluster.clone()));
        }

        if let RouteActionParser::Str(x) = helper
            && x.to_lowercase() == "drop"
        {
            return Ok(RouteAction::Drop);
        }

        Err("invalid route action".to_string())
    }
}
