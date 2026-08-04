#[cfg(target_os = "linux")]
use core::ffi::c_void;
use std::os::fd::RawFd;

#[cfg(target_os = "linux")]
use libc::{
    SO_COOKIE,
    SOL_SOCKET,
    getsockopt,
    socklen_t,
};
use ulb_common::SocketCookie;

#[cfg(target_os = "linux")]
pub fn get_socket_cookie(fd: RawFd) -> anyhow::Result<SocketCookie> {
    let mut cookie: SocketCookie = 0;
    let mut optlen = size_of::<SocketCookie>() as socklen_t;

    if unsafe {
        getsockopt(
            fd,
            SOL_SOCKET,
            SO_COOKIE,
            &mut cookie as *mut _ as *mut c_void,
            &mut optlen,
        )
    } == 0
    {
        Ok(cookie)
    } else {
        Err(anyhow::anyhow!("`get_socket_cookie` failed"))
    }
}

#[cfg(not(target_os = "linux"))]
pub fn get_socket_cookie(_fd: RawFd) -> anyhow::Result<SocketCookie> {
    unimplemented!("`get_socket_cookie`: SO_COOKIE is only available on Linux");
}
