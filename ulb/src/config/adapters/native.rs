use anyhow::Context;

use crate::config::{
    adapters::ConfigAdapter,
    canonical::UlbConfig,
};

pub struct NativeAdapter;

impl ConfigAdapter for NativeAdapter {
    fn parse(content: String) -> anyhow::Result<UlbConfig> {
        yaml_serde::from_str(&content).context("failed to parse config file")
    }
}
