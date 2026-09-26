use std::net::SocketAddr;

#[cfg(feature = "schema")]
use schemars::JsonSchema;
use serde::{
    Deserialize,
    Serialize,
};

use crate::config::canonical::VHostConfig;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct ListenerConfig {
    pub name: String,
    pub addr: SocketAddr,
    pub backlog: Option<u32>,
    pub hosts: Vec<VHostConfig>,
}
