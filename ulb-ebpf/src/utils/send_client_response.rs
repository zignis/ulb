use core::ffi::c_void;

use aya_ebpf::{
    bindings::sk_action::SK_DROP,
    helpers::{
        bpf_get_socket_cookie,
        bpf_skb_change_tail,
        bpf_skb_store_bytes,
    },
    programs::SkBuffContext,
};
use ulb_common::SocketCookie;

use crate::{
    BPF_SKB_EGRESS,
    maps::CLIENT_CONNECTION_MAP,
};

pub fn send_client_response(ctx: &SkBuffContext, response: &[u8]) -> u32 {
    let mut cookie = unsafe { bpf_get_socket_cookie(ctx.skb.skb as *mut c_void) } as SocketCookie;
    let len = response.len() as u32;

    if unsafe { bpf_skb_change_tail(ctx.skb.skb, len, 0) } != 0 {
        return SK_DROP;
    }

    if unsafe { bpf_skb_store_bytes(ctx.skb.skb, 0, response.as_ptr() as *const c_void, len, 0) }
        != 0
    {
        return SK_DROP;
    }

    CLIENT_CONNECTION_MAP.redirect_skb(ctx, &mut cookie, BPF_SKB_EGRESS) as u32
}

/// https://www.rfc-editor.org/rfc/rfc9110.html#name-400-bad-request
pub const HTTP_400_BAD_REQUEST: &[u8] = b"HTTP/1.1 400 Bad Request\r\n\
    Connection: close\r\n\
    Content-Length: 0\r\n\
    \r\n";

/// https://www.rfc-editor.org/rfc/rfc9110.html#name-403-forbidden
pub const HTTP_403_FORBIDDEN: &[u8] = b"HTTP/1.1 403 Forbidden\r\n\
    Connection: close\r\n\
    Content-Length: 0\r\n\
    \r\n";

/// https://www.rfc-editor.org/rfc/rfc9110.html#name-404-not-found
pub const HTTP_404_NOT_FOUND: &[u8] = b"HTTP/1.1 404 Not Found\r\n\
    Connection: close\r\n\
    Content-Length: 0\r\n\
    \r\n";

// TODO: add `Allow` header for the list of allowed headers based on config
/// https://www.rfc-editor.org/rfc/rfc9110.html#name-405-method-not-allowed
pub const HTTP_405_METHOD_NOT_ALLOWED: &[u8] = b"HTTP/1.1 405 Method Not Allowed\r\n\
    Connection: close\r\n\
    Content-Length: 0\r\n\
    \r\n";

/// https://www.rfc-editor.org/rfc/rfc9110.html#name-414-uri-too-long
pub const HTTP_414_URI_TOO_LONG: &[u8] = b"HTTP/1.1 414 URI Too Long\r\n\
    Connection: close\r\n\
    Content-Length: 0\r\n\
    \r\n";

/// https://www.rfc-editor.org/rfc/rfc6585.html#section-5
pub const HTTP_431_REQUEST_HEADER_FIELDS_TOO_LARGE: &[u8] =
    b"HTTP/1.1 431 Request Header Fields Too Large\r\n\
    Connection: close\r\n\
    Content-Length: 0\r\n\
    \r\n";

/// https://www.rfc-editor.org/rfc/rfc9110.html#name-500-internal-server-error
pub const HTTP_500_INTERNAL_SERVER_ERROR: &[u8] = b"HTTP/1.1 500 Internal Server Error\r\n\
    Connection: close\r\n\
    Content-Length: 0\r\n\
    \r\n";

/// https://www.rfc-editor.org/rfc/rfc9110.html#name-501-not-implemented
pub const HTTP_501_NOT_IMPLEMENTED: &[u8] = b"HTTP/1.1 501 Not Implemented\r\n\
    Connection: close\r\n\
    Content-Length: 0\r\n\
    \r\n";

/// https://www.rfc-editor.org/rfc/rfc9110.html#name-503-service-unavailable
pub const HTTP_503_SERVICE_UNAVAILABLE: &[u8] = b"HTTP/1.1 503 Service Unavailable\r\n\
    Connection: close\r\n\
    Content-Length: 0\r\n\
    \r\n";

/// https://www.rfc-editor.org/rfc/rfc9110.html#name-505-http-version-not-suppor
pub const HTTP_505_HTTP_VERSION_NOT_SUPPORTED: &[u8] =
    b"HTTP/1.1 505 HTTP Version Not Supported\r\n\
    Content-Type: text/plain\r\n\
    Connection: close\r\n\
    Content-Length: 50\r\n\
    \r\n\
    Unsupported HTTP version. Use HTTP/1.0 or HTTP/1.1";
