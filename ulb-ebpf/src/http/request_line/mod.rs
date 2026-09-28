//! Parses HTTP request line from an HTTP request
//! https://www.rfc-editor.org/rfc/rfc9112.html#name-request-line

mod method;
mod uri;
mod version;

use aya_ebpf::{
    cty::c_void,
    helpers::bpf_skb_load_bytes,
    programs::SkBuffContext,
};
use ulb_common::http::HttpRequest;

use crate::{
    chars::{
        CH_CR,
        CH_LF,
    },
    http::{
        HttpParseError,
        request_line::{
            method::parse_method,
            uri::parse_uri_len,
            version::parse_http_version,
        },
    },
    utils::SkbData,
};

// TODO: SP can be multiple whitespaces: https://www.rfc-editor.org/rfc/rfc9112.html#section-3-3
#[inline(always)]
pub fn parse_request_line(
    ctx: &SkBuffContext,
    req: &mut HttpRequest,
) -> Result<(), HttpParseError> {
    let data = SkbData::from_ctx(ctx);
    let (method, method_len) = parse_method(data, req.offset())?;
    req.method = method;
    req.advance_offset(method_len + 1); // +1 for SP

    let uri_start = req.offset();
    let uri_len = parse_uri_len(data, uri_start)?;
    req.uri.len = uri_len as u64;
    req.advance_offset(uri_len + 1); // +1 for SP

    if unsafe {
        bpf_skb_load_bytes(
            ctx.skb.skb as *const c_void,
            uri_start as u32,
            req.uri.as_mut_ptr() as *mut c_void,
            uri_len as u32,
        )
    } < 0
    {
        return Err(HttpParseError::Internal);
    }

    let (version, ver_len) = parse_http_version(data, req.offset())?;
    req.version = version;
    req.advance_offset(ver_len);

    // end of req line
    let delimiter = match data
        .at(req.offset())
        .ok_or(HttpParseError::InvalidVersion)?
    {
        CH_CR => 2, // HTTP/0.0\r\n (standard)
        CH_LF => 1, // HTTP/0.0\n
        _ => return Err(HttpParseError::InvalidVersion),
    };

    req.advance_offset(delimiter);

    Ok(())
}

#[cfg(test)]
mod tests {}
