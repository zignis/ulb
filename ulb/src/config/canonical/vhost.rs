use serde::{
    Deserialize,
    Serialize,
};

use crate::config::canonical::RouteConfig;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VHostConfig {
    pub host: String,
    pub routes: Vec<RouteConfig>,
}
