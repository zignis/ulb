use std::collections::HashMap;

#[cfg(feature = "schema")]
use schemars::JsonSchema;
use serde::{
    Deserialize,
    Deserializer,
    Serialize,
    de,
};
use ulb_common::http::HttpMethod;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct RouteConfig {
    pub path: String,
    #[serde(default, deserialize_with = "deserialize_methods")]
    pub methods: Option<Vec<HttpMethod>>,
    #[serde(default)]
    pub headers: Vec<HeaderMatchConfig>,
    pub action: RouteAction,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(try_from = "RouteActionParser")]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[cfg_attr(feature = "schema", schemars(with = "RouteActionParser"))]
pub enum RouteAction {
    Forward(String /* cluster name */),
    Drop,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
enum RouteActionParser {
    Map(HashMap<String, String>),
    Str(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct HeaderMatchConfig {
    pub name: String,
    pub value: String,
    #[serde(default)]
    pub case_insensitive: bool,
}

impl TryFrom<RouteActionParser> for RouteAction {
    type Error = String;

    fn try_from(helper: RouteActionParser) -> Result<Self, Self::Error> {
        if let RouteActionParser::Map(ref map) = helper
            && let Some(cluster) = map.get("forward")
        {
            return Ok(RouteAction::Forward(cluster.clone()));
        }

        if let RouteActionParser::Str(x) = helper
            && x.to_lowercase() == "drop"
        {
            return Ok(RouteAction::Drop);
        }

        Err("invalid route action".to_string())
    }
}

fn deserialize_methods<'de, D>(deserializer: D) -> Result<Option<Vec<HttpMethod>>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Methods {
        Single(String),
        Multiple(Vec<String>),
    }

    match Option::<Methods>::deserialize(deserializer)? {
        Some(Methods::Single(method)) => {
            let method = HttpMethod::try_from(method.as_str())
                .map_err(|_| de::Error::custom(format!("invalid HTTP method `{method}`")))?;
            Ok(Some(vec![method]))
        }

        Some(Methods::Multiple(methods_str)) => {
            let mut methods = Vec::new();

            for method in methods_str {
                let method = HttpMethod::try_from(method.as_str())
                    .map_err(|_| de::Error::custom(format!("invalid HTTP method `{method}`")))?;
                methods.push(method);
            }

            Ok(Some(methods))
        }

        None => Ok(None),
    }
}
