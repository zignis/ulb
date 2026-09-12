use core::ffi::{
    c_long,
    c_void,
};

use ulb_common::{
    HTTP_HDR_VAL_MAX_LEN,
    HttpHeader,
    HttpRequest,
    containers::BoundedStr,
    ir::{
        HDR_RULE_SENTINEL,
        HeaderRule,
        HeaderValueMatchType,
        MAX_ROUTES,
    },
};

use crate::{
    BPF_LOOP_NEXT,
    BPF_LOOP_STOP,
    maps::HEADER_RULE_TABLE,
};

#[derive(Debug)]
pub(super) struct UpdateRuleMaskCtx<'a> {
    pub(crate) idx: u64,
    pub(super) hdr: &'a HttpHeader,
    pub(super) req: &'a mut HttpRequest,
}

impl<'a> UpdateRuleMaskCtx<'a> {
    pub(super) fn new(idx: u64, hdr: &'a HttpHeader, req: &'a mut HttpRequest) -> Self {
        Self { idx, hdr, req }
    }
}

pub(super) extern "C" fn update_rule_mask(_idx: u32, ctx: *mut c_void) -> c_long {
    let ctx = unsafe { &mut *(ctx as *mut UpdateRuleMaskCtx) };

    if ctx.idx == HDR_RULE_SENTINEL {
        return BPF_LOOP_STOP;
    }

    let rule = match HEADER_RULE_TABLE.get(ctx.idx as u32) {
        Some(x) => x,
        None => return BPF_LOOP_STOP,
    };

    if match_val(rule, &ctx.hdr.val) {
        let route_idx = rule.route_idx as usize;

        if route_idx < MAX_ROUTES as usize {
            ctx.req.satisfied_rule_masks[route_idx] |= 1u32 << rule.route_bit_idx;
            ctx.req.mark_route_dirty(route_idx);
        }
    }

    ctx.idx = rule.next_rule_idx;
    BPF_LOOP_NEXT
}

fn match_val(rule: &HeaderRule, hdr_val: &BoundedStr<HTTP_HDR_VAL_MAX_LEN>) -> bool {
    let ci = rule.case_insensitive == 1;
    match rule.match_type {
        HeaderValueMatchType::Any => true,
        HeaderValueMatchType::Exact => hdr_val.matches_exact(&rule.value, ci),
        HeaderValueMatchType::Prefix => hdr_val.matches_prefix(&rule.value, ci),
        HeaderValueMatchType::Suffix => hdr_val.matches_suffix(&rule.value, ci),
    }
}
