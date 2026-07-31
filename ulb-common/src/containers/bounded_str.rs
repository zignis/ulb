#[cfg(feature = "user")]
use alloc::string::String;
use core::ops::{
    Deref,
    DerefMut,
};

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct BoundedStr<const MAX_SIZE: usize> {
    pub len: u32,
    pub data: [u8; MAX_SIZE],
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
            len: len as u32,
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
