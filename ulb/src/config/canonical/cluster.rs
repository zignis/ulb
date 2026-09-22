#[cfg(feature = "schema")]
use schemars::JsonSchema;
use serde::{
    Deserialize,
    Serialize,
};
use ulb_common::ir::LoadBalancingPolicy;

use crate::config::canonical::BackendConfig;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct ClusterConfig {
    pub name: String,
    pub backends: Vec<BackendConfig>,
    pub policy: Option<LoadBalancingPolicy>,
}
