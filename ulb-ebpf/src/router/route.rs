use core::ffi::{
    c_long,
    c_void,
};

use aya_ebpf::helpers::bpf_loop;
use ulb_common::{
    containers::BoundedStr,
    http::{
        HTTP_URI_MAX_LEN,
        HttpRequest,
    },
    ir::{
        MAX_ROUTES,
        MAX_ROUTES_PER_VHOST,
        RouteMatchType,
        RouteValue,
        VHostValue,
    },
};

use crate::{
    BPF_LOOP_NEXT,
    BPF_LOOP_STOP,
    maps::ROUTE_TABLE,
};

#[derive(Debug)]
pub enum RouteError {
    NotFound,
    MethodNotAllowed, // TODO: send a list of allowed methods
}

struct RouteLoopCtx<'a> {
    req: &'a HttpRequest,
    vhost: &'a VHostValue,
    matched_route: Option<&'a RouteValue>,
    method_denied: bool,
}

#[inline(never)]
fn match_path(
    req_path: &BoundedStr<HTTP_URI_MAX_LEN>,
    route_path: &BoundedStr<HTTP_URI_MAX_LEN>,
    match_type: RouteMatchType,
) -> bool {
    match match_type {
        RouteMatchType::Exact => req_path.matches_exact(route_path, false),
        RouteMatchType::Prefix => req_path.matches_prefix(route_path, false),
    }
}

extern "C" fn route_loop_cb(idx: u32, ctx_ptr: *mut c_void) -> c_long {
    let ctx = unsafe { &mut *(ctx_ptr as *mut RouteLoopCtx) };

    if idx >= ctx.vhost.route_count || idx >= MAX_ROUTES_PER_VHOST {
        return BPF_LOOP_STOP;
    }

    let route_idx = ctx.vhost.route_start + idx;
    let route = match ROUTE_TABLE.get(route_idx) {
        Some(x) => x,
        None => return BPF_LOOP_STOP,
    };

    // TODO: longest prefix match; make compiler reorder longer path prefixes
    // earlier in the route table
    if match_path(&ctx.req.uri, &route.path, route.match_type) {
        if !ctx.req.method.match_mask(route.method_mask) {
            ctx.method_denied = true;
            return BPF_LOOP_NEXT;
        }

        // & is used to derive the bounds for verifier
        let route_idx = route_idx & (MAX_ROUTES - 1);

        if ctx.req.satisfied_rule_masks[route_idx as usize] != route.required_headers_mask {
            return BPF_LOOP_NEXT;
        }

        ctx.matched_route = Some(route);
        return BPF_LOOP_STOP;
    }

    BPF_LOOP_NEXT
}

#[inline(always)]
pub fn match_route<'a>(
    req: &'a HttpRequest,
    vhost: &'a VHostValue,
) -> Result<&'a RouteValue, RouteError> {
    let mut ctx = RouteLoopCtx {
        req,
        vhost,
        matched_route: None,
        method_denied: false,
    };

    unsafe {
        bpf_loop(
            vhost.route_count,
            route_loop_cb as *mut c_void,
            &mut ctx as *mut _ as *mut c_void,
            0,
        );
    }

    match ctx.matched_route {
        Some(x) => Ok(x),
        None if ctx.method_denied => Err(RouteError::MethodNotAllowed),
        None => Err(RouteError::NotFound),
    }
}
