// TODO: add instructions to docs about building for arch with different
// endianness

pub const fn b8(bytes: &[u8; 1]) -> u8 {
    u8::from_ne_bytes(*bytes)
}

pub const fn b16(bytes: &[u8; 2]) -> u16 {
    u16::from_ne_bytes(*bytes)
}

pub const fn b32(bytes: &[u8; 4]) -> u32 {
    u32::from_ne_bytes(*bytes)
}
