use core::ffi::c_void;

use aya_ebpf::helpers::{
    bpf_map_lookup_elem,
    bpf_sk_release,
};

#[inline(always)]
pub fn bpf_map_exists_key(map: *mut c_void, key: *const c_void) -> bool {
    let value = unsafe { bpf_map_lookup_elem(map, key) };

    if value.is_null() {
        return false;
    }

    unsafe {
        bpf_sk_release(value);
    }

    true
}
