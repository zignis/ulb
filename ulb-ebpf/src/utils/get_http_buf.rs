use ulb_common::http::HttpRequest;

use crate::maps::HTTP_REQ_BUF;

pub fn get_http_buf<'a>() -> Option<&'a mut HttpRequest> {
    let ptr = HTTP_REQ_BUF.get_ptr_mut(0)?;
    Some(unsafe { &mut *ptr })
}
