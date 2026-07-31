use aya_ebpf::{
    bindings::sk_action::{
        SK_DROP,
        SK_PASS,
    },
    programs::SkBuffContext,
};
#[cfg(feature = "debug")]
use aya_log_ebpf::info;
use ulb_common::ir::RouteAction;

use crate::{
    BACKEND_MAP,
    http::get_http_buf,
};

mod cluster;
mod route;
mod vhost;

pub fn route_req(ctx: &SkBuffContext) -> Result<u32, ()> {
    let req = get_http_buf().ok_or(())?;

    let vhost = match vhost::resolve_vhost(req) {
        Some(x) => x,
        None => {
            #[cfg(feature = "debug")]
            info!(&ctx, "no vhost match");
            return Ok(SK_PASS);
        }
    };

    let route = match route::match_route(req, vhost) {
        Some(x) => x,
        None => {
            #[cfg(feature = "debug")]
            info!(&ctx, "no route match");
            return Ok(SK_PASS);
        }
    };

    match route.action {
        RouteAction::Forward { cluster_idx } => {
            #[cfg(feature = "debug")]
            info!(&ctx, "routing to cluster {idx}");

            let endpoint = cluster::select_backend(cluster_idx)?;

            // TODO: insert client-backend mapping for future pkt
            if unsafe { BACKEND_MAP.redirect_skb(&ctx, endpoint, 0) } >= 0 {
                return Ok(SK_PASS);
            }

            #[cfg(feature = "debug")]
            info!(&ctx, "routing failure");
        }

        RouteAction::Drop => {
            #[cfg(feature = "debug")]
            info!(&ctx, "req dropped due to drop action");
        }
    }

    Ok(SK_DROP)
}
