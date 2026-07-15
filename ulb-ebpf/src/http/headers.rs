use core::ffi::{
    c_long,
    c_void,
};

#[cfg(feature = "debug")]
use aya_ebpf::bpf_printk;
use aya_ebpf::{
    helpers::{
        bpf_loop,
        bpf_skb_load_bytes,
    },
    programs::SkBuffContext,
};
use ulb_common::{
    HTTP_HDR_KEY_MAX_SIZE,
    HTTP_HDR_VAL_MAX_SIZE,
    HTTP_MAX_HEADERS,
    HTTP_REQ_MAX_SCRATCH_SIZE,
    HttpHeader,
    HttpRequest,
};

use crate::http::{
    HttpParseError,
    skb_data::SkbData,
};

struct LoopContext<'a> {
    ctx: &'a SkBuffContext,
    req: &'a mut HttpRequest,
    data: SkbData,
    error: Option<HttpParseError>,
}

pub fn parse_headers(ctx: &SkBuffContext, req: &mut HttpRequest) -> Result<u32, HttpParseError> {
    let data = SkbData::from_ctx(ctx);
    let mut loop_ctx = LoopContext {
        ctx,
        req,
        data,
        error: None,
    };

    unsafe {
        bpf_loop(
            HTTP_MAX_HEADERS as u32,
            callback as *mut c_void,
            &mut loop_ctx as *mut LoopContext as *mut c_void,
            0,
        )
    };

    #[cfg(feature = "debug")]
    unsafe {
        bpf_printk!(c"[hdr][total]: %d", loop_ctx.req._hdr_count);
    }

    loop_ctx.error.map_or(Ok(req._hdr_count), Err)
}

extern "C" fn callback(idx: usize, ctx: *mut c_void) -> c_long {
    let loop_ctx = unsafe { &mut *(ctx as *mut LoopContext) };
    let hdr = match loop_ctx.req.headers.get_mut(idx) {
        Some(hdr) => hdr,
        None => return 1,
    };

    match parse_header(
        loop_ctx.ctx,
        &loop_ctx.data,
        loop_ctx.req._offset as usize,
        hdr,
    ) {
        Ok(consumed) => {
            if consumed == 0 {
                // end of headers
                return 1;
            }

            loop_ctx.req._offset += consumed;
            loop_ctx.req._hdr_count += 1;

            0
        }
        Err(err) => {
            loop_ctx.error = Some(err);
            1
        }
    }
}

#[inline(never)]
fn parse_header(
    ctx: &SkBuffContext,
    data: &SkbData,
    offset: usize,
    hdr: &mut HttpHeader,
) -> Result<u32, HttpParseError> {
    if offset > HTTP_REQ_MAX_SCRATCH_SIZE {
        return Ok(0);
    }

    match data.at(offset) {
        Some(b'\r') | Some(b'\n') | None => return Ok(0),
        _ => {}
    }

    // key
    let mut colon_pos: usize = 0;

    for i in 0..HTTP_HDR_KEY_MAX_SIZE {
        match data.at(offset + i) {
            Some(b':') => {
                colon_pos = i;
                break;
            }
            Some(_) => {}
            None => return Ok(0),
        }
    }

    if colon_pos == 0 {
        return Ok(0);
    }

    if unsafe {
        bpf_skb_load_bytes(
            ctx.skb.skb as *const c_void,
            offset as u32,
            hdr.key.as_mut_ptr() as *mut c_void,
            colon_pos as u32,
        )
    } < 0
    {
        return Err(HttpParseError::Internal);
    }

    hdr.key[colon_pos] = 0;
    hdr.key.len = colon_pos as u32;

    // value
    let mut value_len: usize = 0;
    let mut value_start = offset + colon_pos + 1;

    // space after colon
    if data.at(value_start) == Some(b' ') {
        value_start += 1;
    }

    for i in 0..HTTP_HDR_VAL_MAX_SIZE {
        match data.at(value_start + i) {
            Some(b'\r') | Some(b'\n') => {
                value_len = i;
                break;
            }
            Some(_) => {}
            None => return Ok(0),
        }
    }

    if value_len == 0 {
        return Ok(0);
    }

    if unsafe {
        bpf_skb_load_bytes(
            ctx.skb.skb as *const c_void,
            value_start as u32,
            hdr.value.as_mut_ptr() as *mut c_void,
            value_len as u32,
        )
    } < 0
    {
        return Err(HttpParseError::Internal);
    }

    hdr.value[value_len] = 0;
    hdr.value.len = value_len as u32;

    #[cfg(feature = "debug")]
    unsafe {
        bpf_printk!(c"---> [hdr] %s: %s", hdr.key.as_ptr(), hdr.value.as_ptr());
    }

    let last_char = unsafe { data.at_unchecked(value_start + value_len) };
    let delimiter_size = 1 + (last_char == b'\r') as usize;

    Ok((value_start + value_len + delimiter_size - offset) as u32)
}
