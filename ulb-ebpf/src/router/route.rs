use ulb_common::{
    HttpRequest,
    ir::{
        MAX_ROUTES_PER_VHOST,
        PATH_MAX_LEN,
        RouteMatchType,
        RouteValue,
        VHostValue,
    },
};

use crate::ROUTE_TABLE;

pub fn match_route(req: &HttpRequest, vhost: &VHostValue) -> Option<&'static RouteValue> {
    let start = vhost.route_start;
    let count = vhost.route_count;

    // TODO: bpf_loop helper impl: if MAX_ROUTES_PER_VHOST exceeds verifier limits,
    // we can replace this with bpf_loop.
    for i in 0..MAX_ROUTES_PER_VHOST {
        if i >= count {
            break;
        }

        if let Some(route) = ROUTE_TABLE.get(start + i) {
            if !req.method.match_mask(route.method_mask) {
                continue;
            }

            let uri_len = req.uri.len as usize;
            let path_len = route.path.len as usize;

            if matches!(route.match_type, RouteMatchType::Exact) {
                if uri_len != path_len {
                    continue;
                }
            } else {
                if uri_len < path_len {
                    continue;
                }
            }

            let mut matched = true;

            for j in 0..PATH_MAX_LEN {
                if j >= path_len {
                    break;
                }

                if j >= uri_len || req.uri.data[j] != route.path.data[j] {
                    matched = false;
                    break;
                }
            }

            if matched {
                return Some(route);
            }
        }
    }

    None
}
