#[macro_export]
macro_rules! debug {
    ($ctx:expr, $msg:literal $(, $arg:expr)*) => {
        #[cfg(not(feature = "debug"))]
        let _ = $ctx; // to avoid lint warnings
        #[cfg(feature = "debug")]
        aya_log_ebpf::debug!($ctx, $msg $(, $arg)*);
    };
}

#[macro_export]
macro_rules! warn {
    ($ctx:expr, $msg:literal $(, $arg:expr)*) => {
        #[cfg(not(feature = "debug"))]
        let _ = $ctx; // to avoid lint warnings
        #[cfg(feature = "debug")]
        aya_log_ebpf::warn!($ctx, $msg $(, $arg)*);
    };
}

#[macro_export]
macro_rules! error {
    ($ctx:expr, $msg:literal $(, $arg:expr)*) => {
        #[cfg(not(feature = "debug"))]
        let _ = $ctx; // to avoid lint warnings
        #[cfg(feature = "debug")]
        aya_log_ebpf::error!($ctx, $msg $(, $arg)*);
    };
}
