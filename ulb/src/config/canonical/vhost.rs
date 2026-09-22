#[cfg(feature = "schema")]
use schemars::JsonSchema;
use serde::{
    Deserialize,
    Serialize,
};

use crate::config::canonical::RouteConfig;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct VHostConfig {
    pub host: String,
    pub routes: Vec<RouteConfig>,
}
