#![no_std]

#[cfg(feature = "user")]
extern crate alloc;

pub mod containers;
pub mod http;
pub mod ir;
pub mod session;
pub mod utils;

// total programs available for tail call
pub const JMP_PROG_COUNT: u32 = 2;

// prog idx for tail calls
pub const JMP_PROG_ROUTER: u32 = 0;
pub const JMP_PROG_HEADER_PARSER: u32 = 1;
