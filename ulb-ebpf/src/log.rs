#[cfg(feature = "debug")]
use aya_ebpf::{
    macros::map,
    maps::PerCpuArray,
};
#[cfg(feature = "debug")]
use ulb_common::RequestTrace;

#[cfg(feature = "debug")]
#[map]
pub static REQ_TRACE_CTX: PerCpuArray<RequestTrace> = PerCpuArray::with_max_entries(1, 0);

#[cfg(feature = "debug")]
pub fn get_req_trace<'a>() -> Option<&'a RequestTrace> {
    REQ_TRACE_CTX.get(0)
}

#[cfg(feature = "debug")]
pub fn get_req_trace_mut<'a>() -> Option<&'a mut RequestTrace> {
    let ptr = REQ_TRACE_CTX.get_ptr_mut(0)?;
    Some(unsafe { &mut *ptr })
}

#[macro_export]
macro_rules! debug {
    ($ctx:expr, $msg:literal $(, $arg:expr)*) => {
        #[cfg(feature = "debug")]
        {
            use core::str;

            if let Some(trace) = $crate::log::get_req_trace() {
                if trace.parsed {
                    let method = unsafe { str::from_utf8_unchecked(trace.method.as_c_str().to_bytes()) };
                    let uri = unsafe { str::from_utf8_unchecked(trace.uri.as_slice()) };

                    aya_log_ebpf::info!(
                        $ctx,
                        "[{}][{} {}]",
                        trace.cookie,
                        uri,
                        method
                    );
                } else {
                    aya_log_ebpf::info!(
                        $ctx,
                        "[{}]",
                        trace.cookie
                    );
                }
            } else {
                aya_log_ebpf::info!(
                    $ctx,
                    $msg
                    $(, $arg)*
                );
            }
        }
    };
}
