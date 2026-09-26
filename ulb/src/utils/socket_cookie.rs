use core::ffi::c_void;
use std::{
    io::Error,
    os::fd::RawFd,
};

use libc::{
    SO_COOKIE,
    SOL_SOCKET,
    getsockopt,
    socklen_t,
};
use ulb_common::session::SocketCookie;

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
    } < 0
    {
        Err(anyhow::anyhow!(
            "failed to get socket cookie: {}",
            Error::last_os_error()
        ))
    } else {
        Ok(cookie)
    }
}
