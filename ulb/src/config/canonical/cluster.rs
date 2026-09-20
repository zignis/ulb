use serde::{
    Deserialize,
    Serialize,
};
use ulb_common::ir::LoadBalancingPolicy;

use crate::config::canonical::BackendConfig;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterConfig {
    pub name: String,
    pub backends: Vec<BackendConfig>,
    pub policy: Option<LoadBalancingPolicy>,
}
