use aya_ebpf::{
    cty::c_void,
    helpers::bpf_skb_load_bytes,
    programs::SkBuffContext,
};
use ulb_common::{
    HTTP_URI_MAX_LEN,
    HttpMethod,
    HttpRequest,
    HttpVersion,
};

use crate::{
    http::{
        CH_CR,
        CH_LF,
        CH_SP,
        HttpParseError,
    },
    utils::{
        SkbData,
        b16,
        b32,
    },
};

const GET_SP: u32 = b32(b"GET ");
const PUT_SP: u32 = b32(b"PUT ");
const POST: u32 = b32(b"POST");
const HEAD: u32 = b32(b"HEAD");
// PATCH
const PATC: u32 = b32(b"PATC");
const H_SP: u16 = b16(b"H ");
// TRACE
const TRAC: u32 = b32(b"TRAC");
const E_SP: u16 = b16(b"E ");
// QUERY
const QUER: u32 = b32(b"QUER");
const Y_SP: u16 = b16(b"Y ");
// DELETE
const DELE: u32 = b32(b"DELE");
const TE: u16 = b16(b"TE");
// OPTIONS
const OPTI: u32 = b32(b"OPTI");
const ONS_SP: u32 = b32(b"ONS ");
// CONNECT
const CONN: u32 = b32(b"CONN");
const ECT_SP: u32 = b32(b"ECT ");

fn parse_method(data: SkbData) -> Result<(HttpMethod, usize), HttpParseError> {
    let prefix = data.read_u32(0).ok_or(HttpParseError::InvalidMethod)?;
    match prefix {
        //
        GET_SP => Ok((HttpMethod::Get, 3)),
        PUT_SP => Ok((HttpMethod::Put, 3)),
        //
        POST if data.match_u8(4, CH_SP) => Ok((HttpMethod::Post, 4)),
        HEAD if data.match_u8(4, CH_SP) => Ok((HttpMethod::Head, 4)),
        //
        PATC if data.match_u16(4, H_SP) => Ok((HttpMethod::Patch, 5)),
        TRAC if data.match_u16(4, E_SP) => Ok((HttpMethod::Trace, 5)),
        QUER if data.match_u16(4, Y_SP) => Ok((HttpMethod::Query, 5)),
        //
        DELE if data.match_u16(4, TE) && data.match_u8(6, CH_SP) => Ok((HttpMethod::Delete, 6)),
        //
        OPTI if data.match_u32(4, ONS_SP) => Ok((HttpMethod::Options, 7)),
        CONN if data.match_u32(4, ECT_SP) => Ok((HttpMethod::Connect, 7)),
        //
        _ => Err(HttpParseError::InvalidMethod),
    }
}

//

#[inline(never)]
fn parse_uri_len(data: SkbData, uri_start: usize) -> Result<usize, HttpParseError> {
    for i in 0..HTTP_URI_MAX_LEN {
        match data.at(uri_start + i) {
            Some(CH_SP) => {
                return if i == 0 {
                    Err(HttpParseError::InvalidUri)
                } else {
                    Ok(i)
                };
            }
            Some(_) => {}
            None => break,
        }
    }

    Err(HttpParseError::InvalidUri)
}

//

const HTTP_VERSION_CRLF: usize = 10; // HTTP/0.0\r\n
const HTTP: u32 = b32(b"HTTP");
const V1P0: u32 = b32(b"/1.0");
const V1P1: u32 = b32(b"/1.1");

fn parse_version(
    data: SkbData,
    version_start: usize,
) -> Result<(HttpVersion, usize), HttpParseError> {
    if data.is_length_out_of_bounds(version_start + HTTP_VERSION_CRLF) {
        return Err(HttpParseError::InvalidVersion);
    }

    if unsafe { !data.match_u32_unchecked(version_start, HTTP) } {
        return Err(HttpParseError::InvalidVersion);
    }

    let version_offset = version_start + size_of::<u32>();

    let version = if unsafe { data.match_u32_unchecked(version_offset, V1P0) } {
        HttpVersion::V1P0
    } else if unsafe { data.match_u32_unchecked(version_offset, V1P1) } {
        HttpVersion::V1P1
    } else {
        return Err(HttpParseError::InvalidVersion);
    };

    let line_end = version_start + size_of::<u32>() + size_of::<u32>();

    match unsafe { data.at_unchecked(line_end) } {
        CH_CR => Ok((version, line_end + 2)), // HTTP/0.0\r\n (standard)
        CH_LF => Ok((version, line_end + 1)), // HTTP/0.0\n
        _ => Err(HttpParseError::InvalidVersion),
    }
}

#[inline(never)]
pub fn parse_request_line(
    ctx: &SkBuffContext,
    req: &mut HttpRequest,
) -> Result<(), HttpParseError> {
    let data = SkbData::from_ctx(ctx);
    let (method, method_end) = parse_method(data)?;
    req.method = method;

    let uri_start = method_end + 1;
    let uri_len = parse_uri_len(data, uri_start)?;
    req.uri.len = uri_len as u64;

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

    let version_start = uri_start + uri_len + 1;
    let (version, line_end) = parse_version(data, version_start)?;
    req.version = version;
    req._offset = line_end as u32;

    Ok(())
}
