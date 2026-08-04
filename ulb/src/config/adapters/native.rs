use anyhow::{
    Context,
    Result,
};

use crate::config::{
    adapters::ConfigAdapter,
    canonical::UlbConfig,
};

pub struct NativeAdapter;

impl ConfigAdapter for NativeAdapter {
    fn parse(content: String) -> Result<UlbConfig> {
        serde_yaml::from_str(&content).context("failed to parse config file")
    }
}
