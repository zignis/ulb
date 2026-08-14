#[macro_export]
macro_rules! debug {
    ($ctx:expr, $msg:literal $(, $arg:expr)*) => {
        #[cfg(not(feature = "debug"))]
        let _ = $ctx; // to avoid lint warnings
        #[cfg(feature = "debug")]
        aya_log_ebpf::info!($ctx, $msg $(, $arg)*);
    };
}
