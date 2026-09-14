use crate::{
    containers::BoundedStr,
    http::HTTP_HDR_VAL_MAX_LEN,
};

/// end of linked list
pub const HDR_RULE_SENTINEL: u64 = u64::MAX;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub enum HeaderValueMatchType {
    Any,
    Exact,
    Prefix,
    Suffix,
}

/// a single header matching rule in the inverted index
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct HeaderRule {
    // 8B align
    pub value: BoundedStr<HTTP_HDR_VAL_MAX_LEN>,
    // 8B align
    pub match_type: HeaderValueMatchType,
    pub case_insensitive: u32, // logically a bool value
    // 8B align
    pub route_idx: u32,     // route that this rule belongs to
    pub route_bit_idx: u32, // the bit in route's required_headers_mask that ths rule satisfies
    // 8B align
    pub next_rule_idx: u64, // linked list for multiple rules on same hdr key
}

impl Default for HeaderRule {
    fn default() -> Self {
        Self {
            value: BoundedStr::default(),
            match_type: HeaderValueMatchType::Any,
            case_insensitive: 0,
            route_idx: 0,
            route_bit_idx: 0,
            next_rule_idx: HDR_RULE_SENTINEL,
        }
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for HeaderRule {}
