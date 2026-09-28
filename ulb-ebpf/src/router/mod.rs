use aya_ebpf::{
    bindings::{
        BPF_EXIST,
        sk_action::{
            SK_DROP,
            SK_PASS,
        },
    },
    cty::c_void,
    helpers::bpf_get_socket_cookie,
    programs::SkBuffContext,
};
use ulb_common::{
    ir::ROUTE_ACTION_DROP,
    session::{
        ResidentTarget,
        SessionTarget,
        SocketCookie,
    },
};

use crate::{
    BPF_SKB_EGRESS,
    debug,
    error,
    maps::{
        BACKEND_CONNECTION_MAP,
        BACKEND_CONNECTION_POOL_TABLE,
        RESIDUAL_CONNECTION_MAP,
        SESSION_MAP,
    },
    router::{
        cluster::{
            ResolveBackendError,
            resolve_backend,
        },
        route::{
            RouteError,
            match_route,
        },
        vhost::resolve_vhost,
    },
    utils::{
        HTTP_403_FORBIDDEN,
        HTTP_404_NOT_FOUND,
        HTTP_405_METHOD_NOT_ALLOWED,
        HTTP_500_INTERNAL_SERVER_ERROR,
        HTTP_503_SERVICE_UNAVAILABLE,
        decr_pool_active_connections,
        get_http_buf,
        remove_session_mapping,
        send_client_response,
    },
};

mod cluster;
mod route;
mod vhost;

#[inline(always)]
pub fn route_req(ctx: &SkBuffContext) -> u32 {
    let local_port = ctx.skb.local_port();
    let Some(req) = get_http_buf() else {
        return SK_DROP;
    };

    let vhost = match resolve_vhost(req, local_port as u64) {
        Some(x) => x,
        None => {
            debug!(&ctx, "[D:2] no vhost matched");
            return send_client_response(ctx, HTTP_404_NOT_FOUND);
        }
    };

    let route = match match_route(req, vhost) {
        Ok(x) => x,
        Err(RouteError::NotFound) => {
            debug!(&ctx, "[D:2] no route matched");
            return send_client_response(ctx, HTTP_404_NOT_FOUND);
        }
        Err(RouteError::MethodNotAllowed) => {
            debug!(&ctx, "[D:2] method not allowed");
            return send_client_response(ctx, HTTP_405_METHOD_NOT_ALLOWED);
        }
    };

    match route.action {
        ROUTE_ACTION_DROP => {
            debug!(&ctx, "[D:2] dropped due to drop action");
            send_client_response(ctx, HTTP_403_FORBIDDEN)
        }

        cluster_idx => {
            debug!(&ctx, "[D:2] routing to cluster {}", cluster_idx);

            let client_cookie =
                unsafe { bpf_get_socket_cookie(ctx.skb.skb as *mut c_void) } as SocketCookie;

            let (mut backend_cookie, pool_idx, update_active_connections) =
                match resolve_backend(ctx, cluster_idx, client_cookie) {
                    Ok(x) => x,

                    Err(ResolveBackendError::PoolExhausted { backend_idx }) => {
                        if RESIDUAL_CONNECTION_MAP
                            .insert(
                                client_cookie,
                                ResidentTarget::new(cluster_idx, backend_idx),
                                0,
                            )
                            .is_err()
                        {
                            return send_client_response(ctx, HTTP_503_SERVICE_UNAVAILABLE); // map overflow
                        }

                        debug!(&ctx, "[D:2] request handed off to userspace");

                        return SK_PASS;
                    }

                    _ => return send_client_response(ctx, HTTP_503_SERVICE_UNAVAILABLE),
                };

            #[allow(unused_variables)]
            if let Err(eno) = SESSION_MAP.insert(
                client_cookie,
                SessionTarget::new(backend_cookie, pool_idx, update_active_connections, true),
                0,
            ) {
                error!(
                    &ctx,
                    "[E:2] failed to insert client->backend session ({})", eno
                );

                if update_active_connections {
                    decr_pool_active_connections(pool_idx);
                }

                if let Some(queue) = BACKEND_CONNECTION_POOL_TABLE.get(pool_idx) {
                    // TODO: error handling
                    let _ = queue.push(backend_cookie, BPF_EXIST as u64);
                }

                let _ = SESSION_MAP.remove(backend_cookie); // remove mapping inserted by select_backend
                return send_client_response(ctx, HTTP_500_INTERNAL_SERVER_ERROR);
            }

            let ret = BACKEND_CONNECTION_MAP.redirect_skb(ctx, &mut backend_cookie, BPF_SKB_EGRESS)
                as u32;

            if ret == SK_DROP {
                debug!(&ctx, "[E:2] redirect failure; removing session");
                remove_session_mapping(&client_cookie);
            }

            ret
        }
    }
}
