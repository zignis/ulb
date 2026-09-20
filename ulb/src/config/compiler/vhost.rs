use std::collections::HashMap;

use anyhow::{
    anyhow,
    bail,
};
use ulb_common::{
    containers::BoundedStr,
    http::{
        HTTP_HDR_KEY_MAX_LEN,
        HTTP_HDR_VAL_MAX_LEN,
        HTTP_URI_MAX_LEN,
    },
    ir::{
        HDR_RULE_SENTINEL,
        HeaderRule,
        HeaderValueMatchType,
        MAX_ROUTES,
        MAX_ROUTES_PER_VHOST,
        ROUTE_ACTION_DROP,
        RouteMatchType,
        RouteValue,
        VHostKey,
        VHostValue,
    },
};

use crate::config::canonical::{
    ClusterIdxMap,
    RouteAction,
    RouteConfig,
    UlbConfig,
    VHostConfig,
};

#[derive(Debug)]
pub struct CompiledVHosts {
    pub vhost_map: HashMap<VHostKey, VHostValue>,
    pub route_table: Vec<RouteValue>,
    pub header_rule_table: Vec<HeaderRule>,
    pub header_key_map: HashMap<[u8; HTTP_HDR_KEY_MAX_LEN], u64>,
}

pub fn compile_vhosts(
    cfg: &UlbConfig,
    cluster_idx_map: ClusterIdxMap,
) -> anyhow::Result<CompiledVHosts> {
    let mut vhost_map = HashMap::new();
    let mut route_table = Vec::new();
    let mut header_rule_table: Vec<HeaderRule> = Vec::new();
    let mut header_key_map = HashMap::new();

    for listener in &cfg.listeners {
        let port = listener.addr.port();
        let hosts_fallback = vec![VHostConfig {
            host: "".to_string(),
            routes: Vec::new(),
        }];
        let hosts = if listener.hosts.is_empty() {
            &hosts_fallback
        } else {
            &listener.hosts
        };

        for vhost in hosts {
            let routes_fallback = vec![RouteConfig {
                path: "*".to_string(),
                methods: None,
                headers: Vec::new(),
                action: RouteAction::Drop,
            }];
            let routes = if vhost.routes.is_empty() {
                &routes_fallback
            } else {
                &vhost.routes
            };

            let route_start = route_table.len() as u32;
            let route_count = routes.len() as u32;

            if route_count > MAX_ROUTES_PER_VHOST {
                bail!("exceeded maximum routes per vhost ({route_count}/{MAX_ROUTES_PER_VHOST})");
            }

            if route_start + route_count > MAX_ROUTES {
                bail!(
                    "exceeded maximum routes ({}/{MAX_ROUTES})",
                    route_start + route_count
                );
            }

            vhost_map.insert(
                VHostKey {
                    port: port as u64,
                    host: BoundedStr::try_from(vhost.host.as_str()).map_err(|_| {
                        anyhow!(
                            "host `{}` is too long ({}/{HTTP_HDR_VAL_MAX_LEN})",
                            vhost.host,
                            vhost.host.len()
                        )
                    })?,
                },
                VHostValue {
                    route_start,
                    route_count,
                },
            );

            for route_cfg in routes {
                let (path, match_type) = match route_cfg.path.strip_suffix("*") {
                    Some(prefix) => (prefix, RouteMatchType::Prefix),
                    None => (route_cfg.path.as_str(), RouteMatchType::Exact),
                };

                let mut route = RouteValue {
                    path: BoundedStr::try_from(path).map_err(|_| {
                        anyhow!(
                            "resolved path `{path}` is too long ({}/{HTTP_URI_MAX_LEN})",
                            path.len()
                        )
                    })?,
                    method_mask: 0,
                    match_type,
                    action: ROUTE_ACTION_DROP,
                    required_headers_mask: 0,
                };

                for (i, hdr_cfg) in route_cfg.headers.iter().enumerate() {
                    route.required_headers_mask |= 1 << i;

                    let (val, match_type) = match hdr_cfg.value.as_str() {
                        "*" => ("", HeaderValueMatchType::Any),
                        x if x.ends_with("*") && !x.ends_with("\\*") => {
                            (&x[..x.len() - 1], HeaderValueMatchType::Prefix)
                        }
                        x if x.starts_with("*") => (&x[1..], HeaderValueMatchType::Suffix),
                        x => (x, HeaderValueMatchType::Exact),
                    };
                    let val = val.replace("\\*", "*"); // escape seq

                    let mut rule = HeaderRule {
                        value: BoundedStr::try_from(val.as_str()).map_err(|_| {
                            anyhow!(
                                "header value pattern `{}` is too long ({}/{HTTP_HDR_VAL_MAX_LEN})",
                                hdr_cfg.value,
                                val.len()
                            )
                        })?,
                        match_type,
                        case_insensitive: u32::from(hdr_cfg.case_insensitive),
                        route_idx: route_table.len() as u32,
                        route_bit_idx: i as u32,
                        next_rule_idx: HDR_RULE_SENTINEL,
                    };

                    if hdr_cfg.case_insensitive {
                        rule.value.make_ascii_lowercase();
                    }

                    let rule_idx = header_rule_table.len() as u64;
                    let mut hash = [0_u8; HTTP_HDR_KEY_MAX_LEN];
                    let lower = hdr_cfg.name.to_ascii_lowercase();

                    if lower.len() > HTTP_HDR_KEY_MAX_LEN {
                        bail!(
                            "header name `{}` is too long ({}/{HTTP_HDR_KEY_MAX_LEN})",
                            hdr_cfg.name,
                            lower.len()
                        );
                    }

                    hash[..lower.len()].copy_from_slice(lower.as_bytes());

                    if let Some(&prev_idx) = header_key_map.get(&hash) {
                        rule.next_rule_idx = prev_idx;
                    }

                    header_key_map.insert(hash, rule_idx);
                    header_rule_table.push(rule);
                }

                if let Some(methods) = &route_cfg.methods {
                    for &method in methods {
                        route.method_mask |= method as u32;
                    }
                } else {
                    route.method_mask = 0;
                }

                if let RouteAction::Forward(cluster) = &route_cfg.action {
                    route.action = *cluster_idx_map.get(cluster).ok_or_else(|| {
                        anyhow!(
                            "route `{}` forwards to unknown cluster `{cluster}`",
                            route.path,
                        )
                    })?;
                }

                route_table.push(route);
            }
        }
    }

    Ok(CompiledVHosts {
        vhost_map,
        route_table,
        header_rule_table,
        header_key_map,
    })
}
