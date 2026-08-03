use std::collections::HashMap;

use anyhow::{
    anyhow,
    bail,
};
use ulb_common::{
    HttpMethod,
    containers::BoundedStr,
    ir::{
        MAX_ROUTES,
        MAX_ROUTES_PER_VHOST,
        MAX_VHOSTS,
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
                "exceeded MAX_VHOSTS ({}/{MAX_VHOSTS})",
                listener.hosts.len()
            );
        }

        for vhost_cfg in &listener.hosts {
            let route_start = route_table.len() as u32;
            let route_count = vhost_cfg.routes.len() as u32;

            if route_count > MAX_ROUTES_PER_VHOST {
                bail!("exceeded MAX_ROUTES_PER_VHOST ({route_count}/{MAX_ROUTES_PER_VHOST})");
            }

            if route_start + route_count > MAX_ROUTES {
                bail!(
                    "exceeded MAX_ROUTES ({}/{MAX_ROUTES})",
                    route_start + route_count
                );
            }

            vhost_map.insert(
                VHostKey {
                    host: BoundedStr::try_from(vhost_cfg.host.as_str())
                        .map_err(|_| anyhow!("host too long"))?,
                },
                VHostValue {
                    route_start,
                    route_count,
                },
            );

            for route_cfg in &vhost_cfg.routes {
                let mut route = RouteValue {
                    path: BoundedStr::try_from(route_cfg.path.as_str())
                        .map_err(|_| anyhow!("path too long"))?,
                    method_mask: 0,
                    match_type: route_cfg.match_type,
                    action: ulb_common::ir::RouteAction::Drop,
                };

                for method_str in &route_cfg.methods {
                    let method = HttpMethod::try_from(method_str.as_str())
                        .map_err(|_| anyhow!("invalid method"))?;
                    route.method_mask |= method as u16;
                }

                if let RouteAction::Forward { cluster } = route_cfg.action {
                    route.action = ulb_common::ir::RouteAction::Forward {
                        cluster_idx: *cluster_idx_map.get(&cluster).expect("unknown cluster"),
                    }
                }

                route_table.push(route);
            }
        }
    }

    Ok((vhost_map, route_table))
}
