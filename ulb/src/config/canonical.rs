use serde::{
    Deserialize,
    Serialize,
};
use ulb_common::ir::RouteMatchType;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UlbConfig {
    pub listeners: Vec<ListenerConfig>,
    pub clusters: Vec<ClusterConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListenerConfig {
    pub name: String,
    pub addr: String,
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
pub struct RouteConfig {
    pub path: String,
    pub match_type: RouteMatchType,
    pub methods: Vec<String>,
    pub action: RouteAction,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterConfig {
    pub name: String,
    pub endpoints: Vec<EndpointConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointConfig {
    pub addr: String,
}
