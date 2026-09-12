use aya_ebpf::{
    bindings::sk_action::{
        SK_DROP,
        SK_PASS,
    },
    cty::c_void,
    helpers::bpf_get_socket_cookie,
    programs::SkBuffContext,
};
use ulb_common::{
    SocketCookie,
    ir::RouteAction,
};

use crate::{
    BPF_SKB_EGRESS,
    debug,
    maps::{
        BACKEND_CONNECTION_MAP,
        SESSION_MAP,
    },
    utils::get_http_buf,
};

mod cluster;
mod route;
mod vhost;

pub fn route_req(ctx: &SkBuffContext) -> Result<u32, ()> {
    let req = get_http_buf().ok_or(())?;
    let local_port = ctx.skb.local_port();

    let vhost = match resolve_vhost(req, local_port as u64) {
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

            let client_cookie =
                unsafe { bpf_get_socket_cookie(ctx.skb.skb as *mut c_void) } as SocketCookie;

            let mut backend_cookie = cluster::select_backend(ctx, cluster_idx, client_cookie)?;

            #[allow(unused_variables)]
            if let Err(eno) = SESSION_MAP.insert(client_cookie, backend_cookie, 0) {
                debug!(&ctx, "failed to insert client->backend session ({})", eno);
                let _ = SESSION_MAP.remove(backend_cookie); // remove mapping inserted by cluster::select_backend
                return Err(());
            }

            if BACKEND_CONNECTION_MAP.redirect_skb(ctx, &mut backend_cookie, BPF_SKB_EGRESS)
                == (SK_PASS as i64)
            {
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
