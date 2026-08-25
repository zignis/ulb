use core::ffi::{
    c_long,
    c_void,
};

use aya_ebpf::{
    helpers::{
        bpf_loop,
        bpf_skb_load_bytes,
        bpf_skb_store_bytes,
    },
    programs::SkBuffContext,
};
use ulb_common::{
    HTTP_HDR_KEY_MAX_LEN,
    HTTP_HDR_VAL_MAX_LEN,
    HTTP_MAX_HEADERS,
    HTTP_REQ_MAX_SCRATCH_SIZE,
    HttpHeader,
    HttpRequest,
};

use crate::{
    BPF_LOOP_NEXT,
    BPF_LOOP_STOP,
    debug,
    http::{
        CH_COLON,
        CH_CR,
        CH_LF,
        CH_SP,
        HttpParseError,
    },
    utils::SkbData,
};

struct LoopContext<'a> {
    ctx: &'a SkBuffContext,
    req: &'a mut HttpRequest,
    data: SkbData,
    error: Option<HttpParseError>,
}

pub fn parse_headers(ctx: &SkBuffContext, req: &mut HttpRequest) -> Result<u32, HttpParseError> {
    req.reset_headers();

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

    debug!(&ctx, "total headers parsed: {}", loop_ctx.req.headers.len);

    loop_ctx.error.map_or(Ok(req.headers.len), Err)
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
                return BPF_LOOP_STOP;
            }

            // TODO: impl case-insensitive matching for host header
            if hdr.key.len == 4 && (&hdr.key[..4] == b"host" || &hdr.key[..4] == b"Host") {
                // host bytes must be zeroed out for valid hashing
                loop_ctx.req.host.clear_and_copy(hdr.value);
            }

            // TODO: temporary fix to ignore client's keepalive preference
            if hdr.key.len == 10
                && (&hdr.key[..10] == b"Connection" || &hdr.key[..10] == b"connection")
            {
                // TODO: no need to replace if hdr value is `keepalive`
                let offset = loop_ctx.req._offset;
                let filler = b"x-ulb-fill";

                let status = unsafe {
                    bpf_skb_store_bytes(
                        loop_ctx.ctx.skb.skb as *mut _,
                        offset,
                        filler.as_ptr() as *const c_void,
                        filler.len() as u32,
                        0,
                    )
                };

                // need to refresh pointers that were invalidated by bpf_skb_store_bytes
                // https://docs.ebpf.io/linux/helper-function/bpf_skb_store_bytes
                loop_ctx.data = SkbData::from_ctx(loop_ctx.ctx);

                if status < 0 {
                    loop_ctx.error = Some(HttpParseError::Internal);
                    return BPF_LOOP_STOP;
                }
            }

            loop_ctx.req._offset += consumed;
            loop_ctx.req.headers.len += 1;

            BPF_LOOP_NEXT
        }

        Err(err) => {
            loop_ctx.error = Some(err);

            BPF_LOOP_STOP
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
        Some(CH_CR) | Some(CH_LF) | None => return Ok(0),
        _ => {}
    }

    // key
    let mut colon_pos: usize = 0;

    for i in 0..HTTP_HDR_KEY_MAX_LEN {
        match data.at(offset + i) {
            Some(CH_COLON) => {
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

    // zero out the remaining bits in the first 8 bytes for integer tag matching
    if colon_pos < size_of::<u64>() {
        for i in colon_pos..size_of::<u64>() {
            hdr.key[i] = 0;
        }
    }

    // value
    let mut value_len: usize = 0;
    let mut value_start = offset + colon_pos + 1;

    // space after colon
    if data.at(value_start) == Some(CH_SP) {
        value_start += 1;
    }

    for i in 0..HTTP_HDR_VAL_MAX_LEN {
        match data.at(value_start + i) {
            Some(CH_CR) | Some(CH_LF) => {
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

    // zero out the remaining bits in the first 8 bytes for integer tag matching
    if value_len < size_of::<u64>() {
        for i in value_len..size_of::<u64>() {
            hdr.value[i] = 0;
        }
    }

    let last_char = unsafe { data.at_unchecked(value_start + value_len) };
    let delimiter_size = 1 + (last_char == CH_CR) as usize;

    Ok((value_start + value_len + delimiter_size - offset) as u32)
}
