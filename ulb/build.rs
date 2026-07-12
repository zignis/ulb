use anyhow::{
    Context as _,
    anyhow,
};
use aya_build::Toolchain;

fn main() -> anyhow::Result<()> {
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_DEBUG");

    let cargo_metadata::Metadata { packages, .. } = cargo_metadata::MetadataCommand::new()
        .no_deps()
        .exec()
        .context("MetadataCommand::exec")?;

    let ebpf_package = packages
        .into_iter()
        .find(|cargo_metadata::Package { name, .. }| name.as_str() == "ulb-ebpf")
        .ok_or_else(|| anyhow!("ulb-ebpf package not found"))?;

    let cargo_metadata::Package {
        name,
        manifest_path,
        ..
    } = ebpf_package;

    let features = if std::env::var_os("CARGO_FEATURE_DEBUG").is_some() {
        vec!["debug"]
    } else {
        Vec::new()
    };

    let ebpf_package = aya_build::Package {
        name: name.as_str(),
        root_dir: manifest_path
            .parent()
            .ok_or_else(|| anyhow!("no parent for {manifest_path}"))?
            .as_str(),
        features: &features,
        ..Default::default()
    };

    aya_build::build_ebpf([ebpf_package], Toolchain::default())
}
