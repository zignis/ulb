use core::arch::asm;

/// Atomically adds `val` to the `u64` value at `*ptr`.
///
/// # Safety
///
/// `ptr` must be 8-byte aligned.
#[inline(always)]
pub unsafe fn atomic_add_u64(ptr: *mut u64, val: u64) {
    unsafe {
        asm!(
            "lock *(u64 *)({dst} + 0) += {val}",
            dst = in(reg) ptr,
            val = in(reg) val,
            options(nostack),
        );
    }
}

/// Atomically adds `val` to the `i64` value at `*ptr`.
///
/// # Safety
///
/// `ptr` must be 8-byte aligned.
#[inline(always)]
pub unsafe fn atomic_add_i64(ptr: *mut i64, val: i64) {
    unsafe {
        asm!(
            "lock *(u64 *)({dst} + 0) += {val}",
            dst = in(reg) ptr,
            val = in(reg) val,
            options(nostack),
        );
    }
}
