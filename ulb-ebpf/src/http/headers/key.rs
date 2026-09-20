use core::ffi::{
    c_long,
    c_void,
};

use ulb_common::http::HTTP_REQ_MAX_SCRATCH_SIZE;

use crate::{
    BPF_LOOP_NEXT,
    BPF_LOOP_STOP,
    http::{
        CH_COLON,
        CH_CR,
        CH_NUL,
        CH_SP,
    },
    utils::SkbData,
};

#[derive(Debug)]
pub(super) struct ParseKeyCtx {
    pub(super) data: SkbData,
    pub(super) offset: usize,
    pub(super) len: u32,
    pub(super) err: bool,
}

impl ParseKeyCtx {
    #[inline(always)]
    pub(super) fn new(data: SkbData, offset: usize) -> Self {
        Self {
            data,
            offset,
            len: 0,
            err: false,
        }
    }
}

pub(super) extern "C" fn parse_key(itr: u32, ctx: *mut c_void) -> c_long {
    let ctx = unsafe { &mut *(ctx as *mut ParseKeyCtx) };
    let idx = ctx.offset + itr as usize;

    if idx >= HTTP_REQ_MAX_SCRATCH_SIZE {
        return BPF_LOOP_STOP;
    }

    match ctx.data.at(idx) {
        Some(CH_COLON) => {
            ctx.len = itr;
            BPF_LOOP_STOP
        }

        // illegal SP before colon: https://www.rfc-editor.org/rfc/rfc9112.html#section-5.1-2; or illegal chars
        Some(CH_SP) | Some(CH_CR) | Some(CH_NUL) => {
            ctx.err = true;
            BPF_LOOP_STOP
        }

        Some(_) => BPF_LOOP_NEXT,

        None => BPF_LOOP_STOP,
    }
}
