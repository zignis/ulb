#![no_std]
#![feature(variant_count)]

use core::mem::variant_count;

#[cfg(feature = "user")]
extern crate alloc;

pub mod containers;
pub mod http;
pub mod ir;
pub mod session;
pub mod utils;

#[repr(u32)]
pub enum JmpProg {
    Router,
    HdrParser,
}

pub const JMP_PROG_COUNT: u32 = variant_count::<JmpProg>() as u32;
