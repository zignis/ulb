use core::ffi::{
    c_long,
    c_void,
};

use aya_ebpf::helpers::bpf_loop;
use ulb_common::{
    HTTP_HDR_KEY_MAX_LEN,
    HTTP_HDR_VAL_MAX_LEN,
    HTTP_MAX_HEADERS,
    HttpRequest,
    ir::{
        HeaderMatch,
        HeaderMatchType,
        MAX_HEADER_RULES_PER_ROUTE,
        MAX_ROUTES_PER_VHOST,
        PATH_MAX_LEN,
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

// TODO: temporary nested bpf_loop, big room for improvement

struct RouteLoopCtx<'a> {
    req: &'a HttpRequest,
    vhost: &'a VHostValue,
    matched_route: Option<&'static RouteValue>,
}

pub fn match_route(req: &HttpRequest, vhost: &VHostValue) -> Option<&'static RouteValue> {
    let mut ctx = RouteLoopCtx {
        req,
        vhost,
        matched_route: None,
    };

    unsafe {
        bpf_loop(
            MAX_ROUTES_PER_VHOST,
            route_loop_cb as *mut c_void,
            &mut ctx as *mut RouteLoopCtx as *mut c_void,
            0,
        )
    };

    ctx.matched_route
}

extern "C" fn route_loop_cb(idx: usize, ctx: *mut c_void) -> c_long {
    let ctx = unsafe { &mut *(ctx as *mut RouteLoopCtx) };

    if idx >= ctx.vhost.route_count as usize {
        return BPF_LOOP_STOP;
    }

    if let Some(route) = ROUTE_TABLE.get(ctx.vhost.route_start + idx as u32) {
        if !ctx.req.method.match_mask(route.method_mask) {
            return BPF_LOOP_NEXT;
        }

        let uri_len = ctx.req.uri.len as usize;
        let path_len = route.path.len as usize;

        if matches!(route.match_type, RouteMatchType::Exact) {
            if uri_len != path_len {
                return BPF_LOOP_NEXT;
            }
        } else if uri_len < path_len {
            return BPF_LOOP_NEXT;
        }

        let mut matched = true;

        for j in 0..PATH_MAX_LEN {
            if j >= path_len {
                break;
            }

            if j >= uri_len || ctx.req.uri.data[j] != route.path.data[j] {
                matched = false;
                break;
            }
        }

        if matched {
            let mut headers_ctx = HeadersLoopCtx {
                req: ctx.req,
                route,
                matching: true,
            };

            unsafe {
                bpf_loop(
                    MAX_HEADER_RULES_PER_ROUTE as u32,
                    headers_loop_cb as *mut c_void,
                    &mut headers_ctx as *mut HeadersLoopCtx as *mut c_void,
                    0,
                )
            };

            if headers_ctx.matching {
                ctx.matched_route = Some(route);
                return BPF_LOOP_STOP;
            }
        }
    }

    BPF_LOOP_NEXT
}

struct HeadersLoopCtx<'a> {
    req: &'a HttpRequest,
    route: &'a RouteValue,
    matching: bool,
}

extern "C" fn headers_loop_cb(idx: usize, ctx: *mut c_void) -> c_long {
    let ctx = unsafe { &mut *(ctx as *mut HeadersLoopCtx) };

    if idx >= ctx.route.headers.len as usize {
        return BPF_LOOP_STOP;
    }

    let rule = match ctx.route.headers.get(idx) {
        Some(x) => x,
        None => return BPF_LOOP_STOP,
    };

    let mut inner_ctx = InnerHeaderCtx {
        req: ctx.req,
        rule,
        rule_matched: false,
    };

    unsafe {
        bpf_loop(
            HTTP_MAX_HEADERS as u32,
            inner_header_loop_cb as *mut c_void,
            &mut inner_ctx as *mut InnerHeaderCtx as *mut c_void,
            0,
        )
    };

    if !inner_ctx.rule_matched {
        ctx.matching = false;
        return BPF_LOOP_STOP;
    }

    BPF_LOOP_NEXT
}

struct InnerHeaderCtx<'a> {
    req: &'a HttpRequest,
    rule: &'a HeaderMatch,
    rule_matched: bool,
}

extern "C" fn inner_header_loop_cb(idx: usize, ctx_ptr: *mut c_void) -> c_long {
    let ctx = unsafe { &mut *(ctx_ptr as *mut InnerHeaderCtx) };
    let rule = ctx.rule;

    if idx >= ctx.req.headers.len as usize {
        return BPF_LOOP_STOP;
    }

    let hdr = match ctx.req.headers.get(idx) {
        Some(x) => x,
        None => return BPF_LOOP_STOP,
    };

    if hdr.key.len != rule.name.len {
        return BPF_LOOP_NEXT;
    }

    for i in 0..HTTP_HDR_KEY_MAX_LEN {
        if i >= rule.name.len as usize {
            break;
        }

        if hdr.key.data[i] != rule.name.data[i] {
            return BPF_LOOP_NEXT;
        }
    }

    // match value

    if matches!(rule.match_type, HeaderMatchType::Present) {
        ctx.rule_matched = true;
        return BPF_LOOP_STOP;
    }

    let value_len = rule.value.len as usize;
    let hdr_value_len = hdr.value.len as usize;

    if matches!(rule.match_type, HeaderMatchType::Exact) {
        if hdr_value_len != value_len {
            return BPF_LOOP_NEXT;
        }
    } else if hdr_value_len < value_len {
        return BPF_LOOP_NEXT;
    }

    for i in 0..HTTP_HDR_VAL_MAX_LEN {
        if i >= value_len {
            break;
        }

        if hdr.value.data[i] != rule.value.data[i] {
            return BPF_LOOP_NEXT;
        }
    }

    ctx.rule_matched = true;

    BPF_LOOP_STOP
}
