use std::collections::HashMap;

use anyhow::{
    anyhow,
    bail,
};
use ulb_common::{
    HTTP_HDR_VAL_MAX_LEN,
    HttpMethod,
    containers::BoundedStr,
    ir::{
        MAX_ROUTES,
        MAX_ROUTES_PER_VHOST,
        MAX_VHOSTS,
        PATH_MAX_LEN,
        RouteValue,
        VHostKey,
        VHostValue,
    },
};

use crate::config::canonical::{
    RouteAction,
    UlbConfig,
};

pub fn compile_vhosts(
    cfg: &UlbConfig,
    cluster_idx_map: HashMap<String, u32>,
) -> anyhow::Result<(HashMap<VHostKey, VHostValue>, Vec<RouteValue>)> {
    let mut vhost_map = HashMap::new();
    let mut route_table = Vec::new();

    for listener in &cfg.listeners {
        if listener.hosts.len() >= MAX_VHOSTS as usize {
            bail!(
                "exceeded maximum vhosts ({}/{MAX_VHOSTS})",
                listener.hosts.len()
            );
        }

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
                    port: port as u32,
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
                let mut route = RouteValue {
                    path: BoundedStr::try_from(route_cfg.path.as_str()).map_err(|_| {
                        anyhow!(
                            "path `{}` is too long ({}/{PATH_MAX_LEN})",
                            route_cfg.path,
                            route_cfg.path.len()
                        )
                    })?,
                    method_mask: 0,
                    match_type: route_cfg.match_type,
                    action: ulb_common::ir::RouteAction::Drop,
                };

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
