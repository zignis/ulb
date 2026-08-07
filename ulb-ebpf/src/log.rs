use aya_ebpf::{
    macros::map,
    maps::PerCpuArray,
};
use ulb_common::RequestTrace;

#[map]
pub static REQ_TRACE_CTX: PerCpuArray<RequestTrace> = PerCpuArray::with_max_entries(1, 0);

pub fn get_req_trace<'a>() -> Option<&'a RequestTrace> {
    REQ_TRACE_CTX.get(0)
}

pub fn get_req_trace_mut<'a>() -> Option<&'a mut RequestTrace> {
    let ptr = REQ_TRACE_CTX.get_ptr_mut(0)?;
    Some(unsafe { &mut *ptr })
}

#[macro_export]
macro_rules! debug {
    ($ctx:expr, $msg:literal, $($arg:tt)*) => {
        #[cfg(feature = "debug")]
        {
            if let Some(trace) = crate::log::get_req_trace() {
                // TODO:
                let cookie = "0";
                let uri = "/test";
                let method = "GET";

                if trace.parsed {
                    aya_log_ebpf::info!(
                        $ctx,
                        "[{}][{} {}] {}" ,
                        cookie,
                        uri,
                        method,
                        format_args!($msg $(,$arg)*)
                    );
                } else {
                    aya_log_ebpf::info!(
                        $ctx,
                        "[{}] {}",
                        cookie,
                        format_args!($msg $(,$arg)*)
                    );
                }
            } else {
                aya_log_ebpf::info!($ctx, $msg, $($arg)*);
            }
        }
    };
}
