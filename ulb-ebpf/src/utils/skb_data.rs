use aya_ebpf::programs::{
    SkBuffContext,
    sk_buff::SkBuff,
};

#[derive(Debug, Copy, Clone)]
pub struct SkbData {
    start: *const u8,
    end: *const u8,
}

impl SkbData {
    #[inline(always)]
    pub fn from_ctx(ctx: &SkBuffContext) -> Self {
        Self::from_skb(&ctx.skb)
    }

    #[inline(always)]
    pub fn from_skb(sk_buff: &SkBuff) -> Self {
        let skb = unsafe { *sk_buff.skb };
        Self {
            start: skb.data as *const u8,
            end: skb.data_end as *const u8,
        }
    }

    #[inline(always)]
    pub fn is_length_out_of_bounds(&self, len: usize) -> bool {
        unsafe { self.start.add(len) > self.end }
    }

    #[inline(always)]
    pub fn at(&self, index: usize) -> Option<u8> {
        let ptr = unsafe { self.start.add(index) };

        if unsafe { ptr.add(1) > self.end } {
            None
        } else {
            Some(unsafe { *ptr })
        }
    }

    #[inline(always)]
    pub unsafe fn at_unchecked(&self, index: usize) -> u8 {
        unsafe { *self.start.add(index) }
    }

    #[inline(always)]
    pub fn slice<const N: usize>(&self, offset: usize) -> Option<&[u8; N]> {
        let ptr = unsafe { self.start.add(offset) };

        if unsafe { ptr.add(N) > self.end } {
            None
        } else {
            Some(unsafe { &*(ptr as *const [u8; N]) })
        }
    }

    #[inline(always)]
    pub unsafe fn slice_unchecked<const N: usize>(&self, offset: usize) -> &[u8; N] {
        unsafe { &*(self.start.add(offset) as *const [u8; N]) }
    }

    // u8

    #[inline(always)]
    pub fn match_u8_unchecked(&self, offset: usize, value: u8) -> bool {
        let bytes = unsafe { self.slice_unchecked::<{ size_of::<u8>() }>(offset) };
        u8::from_ne_bytes(*bytes) == value
    }

    #[inline(always)]
    pub fn match_u8(&self, offset: usize, value: u8) -> bool {
        if self.is_length_out_of_bounds(offset + size_of::<u8>()) {
            return false;
        }

        self.match_u8_unchecked(offset, value)
    }

    #[inline(always)]
    pub fn read_u8(&self, offset: usize) -> Option<u8> {
        if self.is_length_out_of_bounds(offset + size_of::<u8>()) {
            return None;
        }

        let bytes = unsafe { self.slice_unchecked::<{ size_of::<u8>() }>(offset) };
        Some(u8::from_ne_bytes(*bytes))
    }

    // u16

    #[inline(always)]
    pub fn match_u16_unchecked(&self, offset: usize, value: u16) -> bool {
        let bytes = unsafe { self.slice_unchecked::<{ size_of::<u16>() }>(offset) };
        u16::from_ne_bytes(*bytes) == value
    }

    #[inline(always)]
    pub fn match_u16(&self, offset: usize, value: u16) -> bool {
        if self.is_length_out_of_bounds(offset + size_of::<u16>()) {
            return false;
        }

        self.match_u16_unchecked(offset, value)
    }

    #[inline(always)]
    pub fn read_u16(&self, offset: usize) -> Option<u16> {
        if self.is_length_out_of_bounds(offset + size_of::<u16>()) {
            return None;
        }

        let bytes = unsafe { self.slice_unchecked::<{ size_of::<u16>() }>(offset) };
        Some(u16::from_ne_bytes(*bytes))
    }

    // u32

    #[inline(always)]
    pub fn match_u32_unchecked(&self, offset: usize, value: u32) -> bool {
        let bytes = unsafe { self.slice_unchecked::<{ size_of::<u32>() }>(offset) };
        u32::from_ne_bytes(*bytes) == value
    }

    #[inline(always)]
    pub fn match_u32(&self, offset: usize, value: u32) -> bool {
        if self.is_length_out_of_bounds(offset + size_of::<u32>()) {
            return false;
        }

        self.match_u32_unchecked(offset, value)
    }

    #[inline(always)]
    pub fn read_u32(&self, offset: usize) -> Option<u32> {
        if self.is_length_out_of_bounds(offset + size_of::<u32>()) {
            return None;
        }

        let bytes = unsafe { self.slice_unchecked::<{ size_of::<u32>() }>(offset) };
        Some(u32::from_ne_bytes(*bytes))
    }
}
