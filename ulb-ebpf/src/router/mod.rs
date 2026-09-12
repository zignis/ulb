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
    ir::ROUTE_ACTION_DROP,
};

use crate::{
    BPF_SKB_EGRESS,
    debug,
    error,
    maps::{
        BACKEND_CONNECTION_MAP,
        SESSION_MAP,
    },
    router::{
        cluster::select_backend,
        route::match_route,
        vhost::resolve_vhost,
    },
    utils::get_http_buf,
};

mod cluster;
mod route;
mod vhost;

pub fn route_req(ctx: &SkBuffContext) -> u32 {
    let local_port = ctx.skb.local_port();
    let Some(req) = get_http_buf() else {
        return SK_DROP;
    };

    let vhost = match resolve_vhost(req, local_port as u64) {
        Some(x) => x,
        None => {
            debug!(&ctx, "[D:2] no vhost matched");
            return SK_PASS;
        }
    };

    let route = match match_route(req, vhost) {
        Some(x) => x,
        None => {
            debug!(&ctx, "[D:2] no route matched");
            return SK_PASS;
        }
    };

    match route.action {
        ROUTE_ACTION_DROP => {
            debug!(&ctx, "[D:2] dropped due to drop action");
            SK_DROP
        }

        cluster_idx => {
            debug!(&ctx, "[D:2] routing to cluster {}", cluster_idx);

            let client_cookie =
                unsafe { bpf_get_socket_cookie(ctx.skb.skb as *mut c_void) } as SocketCookie;

            let Ok(mut backend_cookie) = select_backend(ctx, cluster_idx, client_cookie) else {
                return SK_DROP;
            };

            #[allow(unused_variables)]
            if let Err(eno) = SESSION_MAP.insert(client_cookie, backend_cookie, 0) {
                error!(
                    &ctx,
                    "[E:2] failed to insert client->backend session ({})", eno
                );
                let _ = SESSION_MAP.remove(backend_cookie); // remove mapping inserted by select_backend
                return SK_DROP;
            }

            BACKEND_CONNECTION_MAP.redirect_skb(ctx, &mut backend_cookie, BPF_SKB_EGRESS) as u32
        }
    }
}
