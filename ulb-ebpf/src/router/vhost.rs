use ulb_common::{
    HttpRequest,
    ir::{
        VHostKey,
        VHostValue,
    },
};

use crate::maps::VHOST_MAP;

pub fn resolve_vhost(req: &HttpRequest, port: u32) -> Option<&'static VHostValue> {
    if req.host.len == 0 {
        return None;
    }

    unsafe {
        VHOST_MAP.get(&VHostKey {
            port,
            host: req.host,
        })
    }
}
