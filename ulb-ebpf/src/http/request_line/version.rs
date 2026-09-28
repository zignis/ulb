//! Parses HTTP version
//! https://www.rfc-editor.org/rfc/rfc9112.html#name-http-version

use ulb_common::http::HttpVersion;

use crate::{
    http::HttpParseError,
    utils::{
        SkbData,
        b32,
    },
};

const HTTP_VERSION_LEN: usize = 8; // HTTP/0.0
const HTTP: u32 = b32(b"HTTP");
const V1P0: u32 = b32(b"/1.0");
const V1P1: u32 = b32(b"/1.1");

#[inline(always)]
pub(super) fn parse_http_version(
    data: SkbData,
    offset: usize,
) -> Result<(HttpVersion, usize), HttpParseError> {
    if data.is_length_out_of_bounds(offset + HTTP_VERSION_LEN) {
        return Err(HttpParseError::InvalidVersion);
    }

    if unsafe { !data.match_u32_unchecked(offset, HTTP) } {
        return Err(HttpParseError::InvalidVersion);
    }

    let version_offset = offset + size_of::<u32>();
    let version = if unsafe { data.match_u32_unchecked(version_offset, V1P0) } {
        HttpVersion::V1P0
    } else if unsafe { data.match_u32_unchecked(version_offset, V1P1) } {
        HttpVersion::V1P1
    } else {
        return Err(HttpParseError::InvalidVersion);
    };

    Ok((version, HTTP_VERSION_LEN))
}

#[cfg(test)]
mod tests {}
