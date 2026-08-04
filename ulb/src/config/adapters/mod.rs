pub mod native;

use std::{
    fs,
    path::Path,
};

use anyhow::{
    Context,
    Result,
};

use crate::config::canonical::UlbConfig;

pub trait ConfigAdapter {
    fn load_file<P>(path: P) -> Result<String>
    where
        P: AsRef<Path>,
    {
        fs::read_to_string(&path)
            .with_context(|| format!("failed to read config file: {}", path.as_ref().display()))
    }

    fn parse(content: String) -> Result<UlbConfig>;
}

pub fn load_config<T, P>(path: P) -> Result<UlbConfig>
where
    T: ConfigAdapter,
    P: AsRef<Path>,
{
    let cfg = T::parse(T::load_file(path)?)?;
    Ok(cfg)
}
