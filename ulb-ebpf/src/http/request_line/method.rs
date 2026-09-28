//! Parses HTTP method name
//! https://www.rfc-editor.org/rfc/rfc9112.html#name-method

use ulb_common::http::HttpMethod;

use crate::{
    chars::CH_SP,
    http::HttpParseError,
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

#[inline(always)]
pub(super) fn parse_method(
    data: SkbData,
    offset: usize,
) -> Result<(HttpMethod, usize), HttpParseError> {
    let prefix = data.read_u32(offset).ok_or(HttpParseError::InvalidMethod)?;
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

#[cfg(test)]
mod tests {}
