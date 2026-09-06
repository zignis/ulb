#[cfg(feature = "user")]
use alloc::string::String;
#[cfg(feature = "user")]
use core::fmt::{
    Display,
    Formatter,
};
use core::ops::{
    Deref,
    DerefMut,
};

#[repr(C)]
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "user", derive(PartialEq, Eq, Hash))]
pub struct BoundedStr<const MAX_SIZE: usize> {
    pub len: u64,
    pub data: [u8; MAX_SIZE],
}

impl<const MAX_SIZE: usize> BoundedStr<MAX_SIZE> {
    pub fn clear_and_copy(&mut self, src: BoundedStr<MAX_SIZE>) {
        let len = src.len as usize;
        self.len = src.len;

        if len <= MAX_SIZE {
            self.data[..len].copy_from_slice(&src.data[..len]);
            self.data[len..].fill(0);
        }
    }
}

impl<const MAX_SIZE: usize> Default for BoundedStr<MAX_SIZE> {
    fn default() -> Self {
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
