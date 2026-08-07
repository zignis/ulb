use aya_ebpf::{
    bindings::sk_action::{
        SK_DROP,
        SK_PASS,
    },
    cty::c_void,
    helpers::bpf_get_socket_cookie,
    programs::SkBuffContext,
};
#[cfg(feature = "debug")]
use aya_log_ebpf::info;
use ulb_common::{
    SESSION_ENTRY_BACKEND,
    SESSION_ENTRY_CLIENT,
    SocketCookie,
    ir::RouteAction,
};

use crate::{
    BACKEND_MAP,
    SESSION_MAP,
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
            debug!(&ctx, "no vhost matched");
            return Ok(SK_PASS);
        }
    };

    let route = match route::match_route(req, vhost) {
        Some(x) => x,
        None => {
            debug!(&ctx, "no route matched");
            return Ok(SK_PASS);
        }
    };

    match route.action {
        RouteAction::Forward { cluster_idx } => {
            debug!(&ctx, "routing to cluster {}", cluster_idx);

            let mut backend_cookie = cluster::select_backend(cluster_idx)?;
            let client_cookie =
                unsafe { bpf_get_socket_cookie(ctx.skb.skb as *mut c_void) } as SocketCookie;

            #[allow(unused_variables)]
            if let Err(eno) =
                SESSION_MAP.insert(&client_cookie, &[backend_cookie, SESSION_ENTRY_BACKEND], 0)
            {
                debug!(&ctx, "failed to insert client->backend session ({})", eno);
                return Err(());
            }

            #[allow(unused_variables)]
            if let Err(eno) =
                SESSION_MAP.insert(&backend_cookie, &[client_cookie, SESSION_ENTRY_CLIENT], 0)
            {
                debug!(&ctx, "failed to insert backend->client session ({})", eno);
                return Err(());
            }

            if BACKEND_MAP.redirect_skb(ctx, &mut backend_cookie, 0) == (SK_PASS as i64) {
                return Ok(SK_PASS);
            }

            debug!(&ctx, "routing failed");
        }

        RouteAction::Drop => {
            debug!(&ctx, "dropped due to drop action");
        }
    }

    Ok(SK_DROP)
}
