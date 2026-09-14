use core::ffi::{
    c_long,
    c_void,
};

use ulb_common::http::HTTP_REQ_MAX_SCRATCH_SIZE;

use crate::{
    BPF_LOOP_NEXT,
    BPF_LOOP_STOP,
    http::{
        CH_CR,
        CH_HTAB,
        CH_LF,
        CH_NUL,
        CH_SP,
    },
    utils::SkbData,
};

#[derive(Debug)]
pub(super) struct ParseValCtx {
    pub(super) data: SkbData,
    pub(super) offset: usize,
    pub(super) start: u32,
    pub(super) len: u32,
    pub(super) advance_by: u32,
    pub(super) eol_found: bool,
    pub(super) err: bool,
    reading: bool,
}

impl ParseValCtx {
    pub(super) fn new(data: SkbData, offset: usize) -> Self {
        Self {
            data,
            offset,
            start: 0,
            len: 0,
            advance_by: 0,
            eol_found: false,
            err: false,
            reading: false,
        }
    }
}

// hdr value parser: https://www.rfc-editor.org/info/rfc9110/#name-field-values
// only supports singleton fields for now (https://www.rfc-editor.org/info/rfc9110/#section-5.5-7)
pub(super) extern "C" fn parse_val(itr: u32, ctx: *mut c_void) -> c_long {
    let ctx = unsafe { &mut *(ctx as *mut ParseValCtx) };
    let idx = ctx.offset + itr as usize;

    if idx >= HTTP_REQ_MAX_SCRATCH_SIZE {
        return BPF_LOOP_STOP;
    }

    match ctx.data.at(idx) {
        // end of header
        Some(CH_CR) => {
            if idx + 1 >= HTTP_REQ_MAX_SCRATCH_SIZE || ctx.data.at(idx + 1) != Some(CH_LF) {
                ctx.eol_found = false;
                ctx.err = true; // bare CR
                return BPF_LOOP_STOP;
            }

            // illegal obs line fold: https://www.rfc-editor.org/rfc/rfc9112.html#name-obsolete-line-folding
            if idx + 2 < HTTP_REQ_MAX_SCRATCH_SIZE
                && matches!(ctx.data.at(idx + 2), Some(CH_SP) | Some(CH_HTAB))
            {
                ctx.eol_found = false;
                ctx.err = true;
                return BPF_LOOP_STOP;
            }

            ctx.eol_found = true;
            ctx.len -= ctx.start;
            ctx.advance_by = itr + 2; // crlf

            BPF_LOOP_STOP
        }

        // illegal chars: https://www.rfc-editor.org/info/rfc9110/#section-5.5-5
        Some(CH_LF) | Some(CH_NUL) => {
            ctx.eol_found = false;
            ctx.err = true;
            BPF_LOOP_STOP
        }

        // skip OWS: https://www.rfc-editor.org/info/rfc9110/#section-5.5-3
        Some(CH_SP) | Some(CH_HTAB) => {
            ctx.reading = false;
            BPF_LOOP_NEXT
        }

        Some(_) => {
            // first non-OWS char
            if ctx.len == 0 {
                ctx.start = itr;
            }

            ctx.reading = true;
            ctx.len = itr + 1;
            BPF_LOOP_NEXT
        }

        None => BPF_LOOP_STOP,
    }
}
