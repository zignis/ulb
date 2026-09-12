use std::collections::HashMap;

use anyhow::{
    anyhow,
    bail,
};
use ulb_common::{
    HTTP_HDR_KEY_MAX_LEN,
    HTTP_HDR_VAL_MAX_LEN,
    HttpMethod,
    containers::BoundedStr,
    ir::{
        HeaderMatch,
        HeaderMatchType,
        MAX_ROUTES,
        MAX_ROUTES_PER_VHOST,
        PATH_MAX_LEN,
        RouteMatchType,
        RouteValue,
        VHostKey,
        VHostValue,
    },
};

use crate::config::canonical::{
    ClusterIdxMap,
    RouteAction,
    UlbConfig,
};

pub fn compile_vhosts(
    cfg: &UlbConfig,
    cluster_idx_map: ClusterIdxMap,
) -> anyhow::Result<(HashMap<VHostKey, VHostValue>, Vec<RouteValue>)> {
    let mut vhost_map = HashMap::new();
    let mut route_table = Vec::new();

    for listener in &cfg.listeners {
        let port = listener.addr.port();

        for vhost in &listener.hosts {
            let route_start = route_table.len() as u32;
            let route_count = vhost.routes.len() as u32;

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

            for route_cfg in &vhost.routes {
                let (path, match_type) = if let Some(prefix) = route_cfg.path.strip_suffix("*") {
                    (prefix.to_string(), RouteMatchType::Prefix)
                } else {
                    (route_cfg.path.clone(), RouteMatchType::Exact)
                };

                let mut route = RouteValue {
                    path: BoundedStr::try_from(path.as_str()).map_err(|_| {
                        anyhow!(
                            "resolved path `{path}` is too long ({}/{PATH_MAX_LEN})",
                            path.len()
                        )
                    })?,
                    method_mask: 0,
                    match_type,
                    action: ulb_common::ir::RouteAction::Drop,
                    headers: Default::default(),
                };

                for hdr_cfg in &route_cfg.headers {
                    let (value, match_type) = if hdr_cfg.value == "*" {
                        ("".to_string(), HeaderMatchType::Present)
                    } else if let Some(prefix) = hdr_cfg.value.strip_suffix("*") {
                        (prefix.to_string(), HeaderMatchType::Prefix)
                    } else {
                        (hdr_cfg.value.clone(), HeaderMatchType::Exact)
                    };

                    let hdr = HeaderMatch {
                        name: BoundedStr::try_from(hdr_cfg.name.as_str()).map_err(|_| {
                            anyhow!(
                                "header name `{}` is too long ({}/{HTTP_HDR_KEY_MAX_LEN})",
                                hdr_cfg.name,
                                hdr_cfg.name.len()
                            )
                        })?,
                        value: BoundedStr::try_from(value.as_str()).map_err(|_| {
                            anyhow!(
                                "resolved header value `{value}` is too long ({}/{HTTP_HDR_VAL_MAX_LEN})",
                                value.len()
                            )
                        })?,
                        match_type,
                    };

                    if route.headers.push(hdr).is_err() {
                        bail!("infallible");
                    }
                }

                for method_val in &route_cfg.methods {
                    let method = HttpMethod::try_from(method_val.as_str())
                        .map_err(|_| anyhow!("unknown http method: `{method_val}`"))?;
                    route.method_mask |= method as u16;
                }

                if let RouteAction::Forward { cluster } = &route_cfg.action {
                    route.action = ulb_common::ir::RouteAction::Forward {
                        cluster_idx: *cluster_idx_map.get(cluster).ok_or(anyhow!(
                            "route `{}` forwards to unknown cluster `{cluster}`",
                            route.path,
                        ))?,
                    }
                }

                route_table.push(route);
            }
        }
    }

    Ok((vhost_map, route_table))
}
