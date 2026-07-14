use aya_ebpf::{
    cty::c_void,
    helpers::bpf_skb_load_bytes,
    programs::SkBuffContext,
};
use ulb_common::{
    HTTP_URI_MAX_SIZE,
    HttpMethod,
    HttpRequest,
    HttpVersion,
};

use crate::http::{
    HttpParseError,
    skb_data::SkbData,
};

const METHOD_MAX_LEN: usize = 7; // `OPTIONS` & `CONNECT` are the longest methods
const HTTP_VERSION_MIN_LEN: usize = 10; // HTTP/1.1\r\n
const HTTP_VERSION_PREFIX_LEN: usize = 7; // HTTP/1.

// TODO: http/2 parsing

fn parse_method(data: SkbData) -> Result<(HttpMethod, usize), HttpParseError> {
    let mut space = 0;

    for i in 0..(METHOD_MAX_LEN + 1) {
        match data.at(i) {
            Some(b' ') => {
                space = i;
                break;
            }
            Some(_) => {}
            None => return Err(HttpParseError::InvalidMethod),
        }
    }

    if space == 0 {
        return Err(HttpParseError::InvalidMethod);
    }

    let method = match space {
        3 if data.slice(0) == Some(b"GET") => HttpMethod::Get,
        3 if data.slice(0) == Some(b"PUT") => HttpMethod::Put,
        4 if data.slice(0) == Some(b"HEAD") => HttpMethod::Head,
        4 if data.slice(0) == Some(b"POST") => HttpMethod::Post,
        5 if data.slice(0) == Some(b"PATCH") => HttpMethod::Patch,
        5 if data.slice(0) == Some(b"TRACE") => HttpMethod::Trace,
        5 if data.slice(0) == Some(b"QUERY") => HttpMethod::Query,
        6 if data.slice(0) == Some(b"DELETE") => HttpMethod::Delete,
        7 if data.slice(0) == Some(b"CONNECT") => HttpMethod::Connect,
        7 if data.slice(0) == Some(b"OPTIONS") => HttpMethod::Options,
        _ => return Err(HttpParseError::InvalidMethod),
    };

    Ok((method, space))
}

#[inline(never)]
fn parse_uri_len(data: SkbData, uri_start: usize) -> Result<usize, HttpParseError> {
    for i in 0..HTTP_URI_MAX_SIZE {
        match data.at(uri_start + i) {
            Some(b' ') => {
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

fn parse_version(
    data: SkbData,
    version_start: usize,
) -> Result<(HttpVersion, usize), HttpParseError> {
    if data.is_length_out_of_bounds(version_start + HTTP_VERSION_MIN_LEN) {
        return Err(HttpParseError::InvalidVersion);
    }

    if unsafe { data.slice_unchecked(version_start) } != b"HTTP/1." {
        return Err(HttpParseError::InvalidVersion);
    }

    let version = match unsafe { data.at_unchecked(version_start + HTTP_VERSION_PREFIX_LEN) } {
        b'0' => HttpVersion::V1P0,
        b'1' => HttpVersion::V1P1,
        _ => return Err(HttpParseError::InvalidVersion),
    };

    let line_end = version_start + HTTP_VERSION_PREFIX_LEN + 1;

    match unsafe { data.at_unchecked(line_end) } {
        b'\r' => Ok((version, line_end + 2)), // standard crlf eol
        b'\n' => Ok((version, line_end + 1)), // eol with only lf
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
    req.uri.len = uri_len as u32;

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
