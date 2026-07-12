use core::ffi::c_void;

#[cfg(feature = "debug")]
use aya_ebpf::bpf_printk;
use aya_ebpf::{
    helpers::bpf_skb_load_bytes,
    programs::SkBuffContext,
};
use ulb_common::{
    HTTP_HDR_MAX_KEY_SIZE,
    HTTP_HDR_MAX_VAL_SIZE,
    HTTP_MAX_HEADERS,
    HttpHeader,
    HttpRequest,
};

use crate::http::{
    HttpParseError,
    skb_data::SkbData,
};

// max practical size of http headers section
const MAX_HEADERS_SIZE: usize = 8192;

pub fn parse_headers(ctx: &SkBuffContext, req: &mut HttpRequest) -> Result<u32, HttpParseError> {
    let data = SkbData::from_ctx(ctx);

    for i in 0..HTTP_MAX_HEADERS {
        if req._hdr_count >= HTTP_MAX_HEADERS as u32 {
            break;
        }

        let hdr = &mut req.headers[i];
        let consumed = parse_header(ctx, &data, req._offset as usize, hdr);

        // end of headers
        if consumed == 0 {
            break;
        }

        req._offset += consumed;
        req._hdr_count += 1;
    }

    Ok(req._hdr_count)
}

#[inline(never)]
fn parse_header(ctx: &SkBuffContext, data: &SkbData, offset: usize, hdr: &mut HttpHeader) -> u32 {
    if offset > MAX_HEADERS_SIZE {
        return 0;
    }

    match data.at(offset) {
        Some(b'\r') | Some(b'\n') | None => return 0,
        _ => {}
    }

    // key
    let mut colon_pos: usize = 0;

    for i in 0..HTTP_HDR_MAX_KEY_SIZE {
        match data.at(offset + i) {
            Some(b':') => {
                colon_pos = i;
                break;
            }
            Some(_) => {}
            None => return 0,
        }
    }

    if colon_pos == 0 {
        return 0;
    }

    hdr.key_len = colon_pos as u32;

    unsafe {
        bpf_skb_load_bytes(
            ctx.skb.skb as *const c_void,
            offset as u32,
            hdr.key.as_mut_ptr() as *mut c_void,
            colon_pos as u32,
        );
    }

    hdr.key[colon_pos] = 0;

    // value
    let mut value_len: usize = 0;
    let mut value_start = offset + colon_pos + 1;

    // space after colon
    if data.at(value_start) == Some(b' ') {
        value_start += 1;
    }

    for i in 0..HTTP_HDR_MAX_VAL_SIZE {
        match data.at(value_start + i) {
            Some(b'\r') | Some(b'\n') => {
                value_len = i;
                break;
            }
            Some(_) => {}
            None => return 0,
        }
    }

    if value_len == 0 {
        return 0;
    }

    hdr.value_len = value_len as u32;

    unsafe {
        bpf_skb_load_bytes(
            ctx.skb.skb as *const c_void,
            value_start as u32,
            hdr.value.as_mut_ptr() as *mut c_void,
            value_len as u32,
        );
    }

    hdr.value[value_len] = 0;

    #[cfg(feature = "debug")]
    unsafe {
        bpf_printk!(c"---> [hdr] %s: %s", hdr.key.as_ptr(), hdr.value.as_ptr());
    }

    let last_char = unsafe { data.at_unchecked(value_start + value_len) };
    let delimiter_size = 1 + (last_char == b'\r') as usize;

    (value_start + value_len + delimiter_size - offset) as u32
}
