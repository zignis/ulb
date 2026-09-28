//! Parses HTTP URI length in the request line
//! https://www.rfc-editor.org/rfc/rfc9112.html#name-request-target

use ulb_common::http::HTTP_URI_MAX_LEN;

use crate::{
    chars::CH_SP,
    http::HttpParseError,
    utils::SkbData,
};

#[inline(always)]
pub(super) fn parse_uri_len(data: SkbData, offset: usize) -> Result<usize, HttpParseError> {
    for i in 0..HTTP_URI_MAX_LEN {
        match data.at(offset + i) {
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

#[cfg(test)]
mod tests {}
