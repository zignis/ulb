//! Parses request headers
//! https://www.rfc-editor.org/rfc/rfc9112.html#name-field-syntax

mod key;
mod rule_mask;
mod val;

use core::ffi::{
    c_long,
    c_void,
};

use aya_ebpf::{
    bindings::sk_action::SK_DROP,
    helpers::{
        bpf_loop,
        bpf_skb_load_bytes,
    },
    programs::SkBuffContext,
};
use ulb_common::{
    JmpProg,
    http::{
        HTTP_HDR_KEY_MAX_LEN,
        HTTP_HDR_VAL_MAX_LEN,
        HTTP_MAX_HEADERS,
        HTTP_REQ_MAX_SCRATCH_SIZE,
        HttpHeader,
        HttpRequest,
        HttpVersion,
    },
    ir::{
        HDR_RULE_SENTINEL,
        MAX_HEADER_RULES,
    },
};

use crate::{
    BPF_LOOP_NEXT,
    BPF_LOOP_STOP,
    chars::{
        CH_CR,
        CH_LF,
    },
    debug,
    error,
    http::headers::{
        key::{
            ParseKeyCtx,
            parse_key,
        },
        rule_mask::{
            UpdateRuleMaskCtx,
            update_rule_mask,
        },
        val::{
            ParseValCtx,
            parse_val,
        },
    },
    maps::{
        HEADER_KEY_MAP,
        JMP_TABLE,
    },
    utils::{
        HTTP_400_BAD_REQUEST,
        HTTP_431_REQUEST_HEADER_FIELDS_TOO_LARGE,
        SkbData,
        get_http_buf,
        send_client_response,
    },
};

const HOST: &[u8] = b"host";

struct ParseHdrCtx<'a> {
    skb_ctx: &'a SkBuffContext,
    req: &'a mut HttpRequest,
    hdr: &'a mut HttpHeader,
    err: bool,
}

#[inline(always)]
pub fn parse_headers(ctx: &SkBuffContext) -> u32 {
    let mut hdr = HttpHeader::default();
    let req = match get_http_buf() {
        Some(x) => x,
        None => return SK_DROP,
    };

    req.host.reset();
    req.reset_rule_masks();

    let mut hdr_ctx = ParseHdrCtx {
        skb_ctx: ctx,
        hdr: &mut hdr,
        req,
        err: false,
    };

    let loop_ret = unsafe {
        bpf_loop(
            HTTP_MAX_HEADERS as u32,
            parse_hdr as *mut c_void,
            &mut hdr_ctx as *mut ParseHdrCtx as *mut c_void,
            0,
        )
    };

    if loop_ret < 0 {
        return SK_DROP;
    }

    if hdr_ctx.req.offset() >= HTTP_REQ_MAX_SCRATCH_SIZE {
        debug!(ctx, "[W:2] header overflow");
        return send_client_response(ctx, HTTP_431_REQUEST_HEADER_FIELDS_TOO_LARGE);
    }

    if hdr_ctx.err {
        debug!(ctx, "[W:2] bad headers");
        return send_client_response(ctx, HTTP_400_BAD_REQUEST);
    }

    debug!(&ctx, "[D:2] parsed {} headers", loop_ret - 1);

    // host header is mandatory in http/1.1
    if matches!(hdr_ctx.req.version, HttpVersion::V1P1) && hdr_ctx.req.host.empty() {
        debug!(ctx, "[W:2] missing host header for HTTP/1.1 request");
        return send_client_response(ctx, HTTP_400_BAD_REQUEST);
    }

    unsafe {
        JMP_TABLE.tail_call(ctx, JmpProg::Router as u32);
    }

    error!(ctx, "[E:2] tail call to router failed");

    SK_DROP
}

extern "C" fn parse_hdr(_idx: u32, ctx: *mut c_void) -> c_long {
    let ctx = unsafe { &mut *(ctx as *mut ParseHdrCtx) };
    let data = SkbData::from_ctx(ctx.skb_ctx);
    ctx.hdr.reset();

    if ctx.req.offset() >= HTTP_REQ_MAX_SCRATCH_SIZE {
        return BPF_LOOP_STOP;
    }

    if matches!(data.at(ctx.req.offset()), Some(CH_CR) | Some(CH_LF) | None) {
        return BPF_LOOP_STOP;
    }

    if parse_header_line(data, ctx).is_err() {
        return BPF_LOOP_STOP;
    }

    if ctx.hdr.key.len == HOST.len() as u64 && (&ctx.hdr.key[..4] == HOST) {
        if !ctx.req.host.empty() {
            // request cannot have multiple host headers
            // https://www.rfc-editor.org/rfc/rfc9112.html#section-3.2-6
            ctx.err = true;
            return BPF_LOOP_STOP;
        }

        ctx.req.host.clear_and_copy(&ctx.hdr.val);
    }

    // update rule mask

    let rule_idx = match unsafe { HEADER_KEY_MAP.get(ctx.hdr.key.data).copied() } {
        Some(HDR_RULE_SENTINEL) | None => return BPF_LOOP_NEXT,
        Some(x) => x,
    };

    let mut rule_mask_ctx = UpdateRuleMaskCtx::new(rule_idx, ctx.hdr, ctx.req);

    if unsafe {
        bpf_loop(
            MAX_HEADER_RULES,
            update_rule_mask as *mut c_void,
            &mut rule_mask_ctx as *mut UpdateRuleMaskCtx as *mut c_void,
            0,
        )
    } < 0
    {
        return BPF_LOOP_STOP;
    }

    //

    BPF_LOOP_NEXT
}

#[inline(always)]
fn parse_header_line(data: SkbData, ctx: &mut ParseHdrCtx) -> Result<(), ()> {
    // key

    let mut key_ctx = ParseKeyCtx::new(data, ctx.req.offset());

    let key_ret = unsafe {
        bpf_loop(
            HTTP_HDR_KEY_MAX_LEN as u32,
            parse_key as *mut c_void,
            &mut key_ctx as *mut ParseKeyCtx as *mut c_void,
            0,
        )
    };

    if key_ret < 0 || key_ctx.err || key_ctx.len == 0 {
        ctx.err = key_ctx.err;
        return Err(());
    }

    // & is used to re-derive the bounds for verifier
    let key_len = (key_ctx.len & (HTTP_HDR_KEY_MAX_LEN as u32 - 1)).max(1);

    if unsafe {
        bpf_skb_load_bytes(
            ctx.skb_ctx.skb.skb as *const c_void,
            ctx.req.offset() as u32,
            ctx.hdr.key.as_mut_ptr() as *mut c_void,
            key_len,
        )
    } < 0
    {
        return Err(());
    }

    ctx.hdr.key[key_len as usize] = 0;
    ctx.hdr.key.len = key_len as u64;
    ctx.hdr.key.clear_remaining(); // hdr key is used as hash key, need to zero-out bytes
    ctx.hdr.key.make_ascii_lowercase(); // keys are always ascii and case-insensitive: https://www.rfc-editor.org/rfc/rfc9112.html#name-field-syntax
    ctx.req.advance_offset(key_len as usize + 1); // +1 for colon

    // value

    let mut val_ctx = ParseValCtx::new(data, ctx.req.offset());

    let val_ret = unsafe {
        bpf_loop(
            HTTP_HDR_VAL_MAX_LEN as u32,
            parse_val as *mut c_void,
            &mut val_ctx as *mut ParseValCtx as *mut c_void,
            0,
        )
    };

    if val_ret < 0 || val_ctx.err || !val_ctx.eol_found {
        ctx.err = val_ctx.err;
        return Err(());
    }

    // & is used to re-derive the bounds for verifier
    let val_len = val_ctx.len & (HTTP_HDR_VAL_MAX_LEN as u32 - 1);

    #[allow(clippy::collapsible_if)]
    if val_len > 0 {
        if unsafe {
            bpf_skb_load_bytes(
                ctx.skb_ctx.skb.skb as *const c_void,
                ctx.req.offset() as u32 + val_ctx.start,
                ctx.hdr.val.as_mut_ptr() as *mut c_void,
                val_len,
            )
        } < 0
        {
            return Err(());
        }
    }

    ctx.hdr.val[val_len as usize] = 0;
    ctx.hdr.val.len = val_len as u64;
    ctx.req.advance_offset(val_ctx.total_len as usize);

    Ok(())
}

#[cfg(test)]
mod tests {}
