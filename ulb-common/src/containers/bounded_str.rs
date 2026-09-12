#[cfg(feature = "user")]
use alloc::string::String;
#[cfg(feature = "user")]
use core::fmt::{
    Display,
    Formatter,
};
use core::{
    ops::{
        Deref,
        DerefMut,
    },
    slice,
};

use crate::make_word_ascii_lowercase;

macro_rules! words {
    ($sz:expr) => {
        ($sz / core::mem::size_of::<u64>())
    };
}

/// make sure `MAX_SIZE` is always a multiple of 8.
///
/// this struct needs to be 8-byte aligned since we load and read u64 from the
/// data.
#[repr(C, align(8))]
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "user", derive(PartialEq, Eq, Hash))]
pub struct BoundedStr<const MAX_SIZE: usize> {
    pub len: u64,
    pub data: [u8; MAX_SIZE],
}

impl<const MAX_SIZE: usize> Default for BoundedStr<MAX_SIZE> {
    fn default() -> Self {
        #[allow(clippy::let_unit_value)]
        let _ = Self::CHECK_PWR_TWO;
        #[allow(clippy::let_unit_value)]
        let _ = Self::CHECK_ALIGNED;

        Self {
            len: 0,
            data: [0; MAX_SIZE],
        }
    }
}

impl<const MAX_SIZE: usize> Deref for BoundedStr<MAX_SIZE> {
    type Target = [u8; MAX_SIZE];

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl<const MAX_SIZE: usize> DerefMut for BoundedStr<MAX_SIZE> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.data
    }
}

#[cfg(feature = "user")]
impl<const MAX_SIZE: usize> Display for BoundedStr<MAX_SIZE> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        let bytes = self.data.get(..self.len as usize).ok_or(core::fmt::Error)?;
        f.write_str(str::from_utf8(bytes).map_err(|_| core::fmt::Error)?)
    }
}

#[cfg(feature = "user")]
impl<const MAX_SIZE: usize> TryFrom<&str> for BoundedStr<MAX_SIZE> {
    type Error = ();

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let bytes = value.as_bytes();
        let len = bytes.len();

        if len > MAX_SIZE {
            return Err(());
        }

        let mut data = [0; MAX_SIZE];
        data[..len].copy_from_slice(bytes);

        Ok(Self {
            len: len as u64,
            data,
        })
    }
}

#[cfg(feature = "user")]
impl<const MAX_SIZE: usize> TryFrom<String> for BoundedStr<MAX_SIZE> {
    type Error = ();

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.as_str().try_into()
    }
}

#[cfg(feature = "user")]
unsafe impl<const MAX_SIZE: usize> aya::Pod for BoundedStr<MAX_SIZE> {}

impl<const MAX_SIZE: usize> BoundedStr<MAX_SIZE> {
    const CHECK_PWR_TWO: () = assert!(MAX_SIZE.is_power_of_two(), "MAX_SIZE must be a power of 2");
    const CHECK_ALIGNED: () = assert!(
        MAX_SIZE.is_multiple_of(8),
        "MAX_SIZE must be a multiple of 8"
    );

    /// just sets the len to 0
    pub fn reset(&mut self) {
        self.len = 0;
    }

    /// zeros out bytes past len
    pub fn clear_remaining(&mut self) {
        let len = self.len as usize;
        if len <= MAX_SIZE {
            self.data[len..].fill(0);
        }
    }

    pub fn clear_and_copy(&mut self, src: &BoundedStr<MAX_SIZE>) {
        let len = src.len as usize;
        self.len = src.len;

        if len <= MAX_SIZE {
            self.data[..len].copy_from_slice(&src.data[..len]);
            self.data[len..].fill(0);
        }
    }

    pub fn make_ascii_lowercase(&mut self) {
        let valid_words = self.len.div_ceil(8);
        let words = unsafe {
            slice::from_raw_parts_mut(self.data.as_mut_ptr() as *mut u64, words!(MAX_SIZE))
        };

        #[allow(clippy::needless_range_loop)]
        for i in 0..words!(MAX_SIZE) {
            if i >= valid_words as usize {
                break;
            }

            make_word_ascii_lowercase(&mut words[i]);
        }
    }

    pub fn empty(&self) -> bool {
        self.len == 0
    }

    pub fn matches_exact(self, other: &BoundedStr<MAX_SIZE>, ci: bool) -> bool {
        if self.len != other.len {
            return false;
        }

        self.matches_prefix(other, ci)
    }

    pub fn matches_prefix(self, prefix: &BoundedStr<MAX_SIZE>, ci: bool) -> bool {
        if self.len < prefix.len {
            return false;
        }

        let full_words = (prefix.len / 8) as usize;
        let rem = prefix.len & 7;
        let self_words =
            unsafe { slice::from_raw_parts(self.data.as_ptr() as *const u64, words!(MAX_SIZE)) };
        let prefix_words =
            unsafe { slice::from_raw_parts(prefix.data.as_ptr() as *const u64, words!(MAX_SIZE)) };

        for i in 0..words!(MAX_SIZE) {
            if i < full_words {
                let mut self_word = self_words[i];

                if ci {
                    make_word_ascii_lowercase(&mut self_word);
                }

                if self_word != prefix_words[i] {
                    return false;
                }
            } else if i == full_words && rem != 0 {
                let mut self_word = self_words[i];
                let mask = tail_mask(prefix.len);

                if ci {
                    make_word_ascii_lowercase(&mut self_word);
                }

                if (self_word & mask) != (prefix_words[i] & mask) {
                    return false;
                }

                break;
            } else {
                break;
            }
        }

        true
    }

    pub fn matches_suffix(self, suffix: &BoundedStr<MAX_SIZE>, ci: bool) -> bool {
        if self.len < suffix.len {
            return false;
        }

        if self.len == suffix.len {
            return self.matches_exact(suffix, ci);
        }

        // TODO: byte level comparison for now

        let offset = (self.len - suffix.len) as usize;

        for i in 0..MAX_SIZE {
            if i >= suffix.len as usize {
                break;
            }

            let idx = (offset + i) & (MAX_SIZE - 1);
            let mut self_byte = self.data[idx];

            if ci {
                self_byte.make_ascii_lowercase();
            }

            if self_byte != suffix.data[i] {
                return false;
            }
        }

        true
    }
}

// remainder byte mask in final u64 word
#[inline(always)]
const fn tail_mask(len: u64) -> u64 {
    match len & 7 {
        0 => u64::MAX,
        #[cfg(target_endian = "little")]
        rem_bytes => (1u64 << (rem_bytes * 8)) - 1,
        #[cfg(target_endian = "big")]
        rem_bytes => u64::MAX << (u64::BITS - (rem_bytes * 8) as u32),
    }
}
