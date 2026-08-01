use ulb_common::{
    HttpRequest,
    ir::{
        VHostKey,
        VHostValue,
    },
};

use crate::VHOST_MAP;

pub fn resolve_vhost(req: &HttpRequest) -> Option<&'static VHostValue> {
    if req.host.len == 0 {
        return None;
    }

    unsafe { VHOST_MAP.get(&VHostKey { host: req.host }) }
}
