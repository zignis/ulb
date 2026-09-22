use ulb::config::canonical::UlbConfig;
use serde_json::to_string_pretty;

fn main() {
    let schema = schemars::schema_for!(UlbConfig);
    let json = to_string_pretty(&schema).expect("pretty json failed");
    println!("{json}");
}
