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
