#![no_std]
#![no_main]

use core::ffi::c_long;

mod http;
mod log;
mod maps;
mod programs;
mod router;
mod utils;

// bpf_loop return values
pub const BPF_LOOP_NEXT: c_long = 0;
pub const BPF_LOOP_STOP: c_long = 1;

// skb_redirect helper flags
pub const BPF_SKB_EGRESS: u64 = 0;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
