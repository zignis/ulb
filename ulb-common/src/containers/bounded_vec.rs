#[cfg(feature = "user")]
use alloc::vec::Vec;
use core::ops::{
    Deref,
    DerefMut,
};

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct BoundedVec<T, const MAX_SIZE: usize>
where
    T: Copy + Clone + Default,
{
    pub len: u32,
    pub data: [T; MAX_SIZE],
}

impl<T, const MAX_SIZE: usize> Deref for BoundedVec<T, MAX_SIZE>
where
    T: Copy + Clone + Default,
{
    type Target = [T; MAX_SIZE];

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl<T, const MAX_SIZE: usize> DerefMut for BoundedVec<T, MAX_SIZE>
where
    T: Copy + Clone + Default,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.data
    }
}

#[cfg(feature = "user")]
impl<T, const MAX_SIZE: usize> TryFrom<Vec<T>> for BoundedVec<T, MAX_SIZE>
where
    T: Copy + Clone + Default,
{
    type Error = ();

    fn try_from(value: Vec<T>) -> Result<Self, Self::Error> {
        let len = value.len();

        if len > MAX_SIZE {
            return Err(());
        }

        let mut data = [T::default(); MAX_SIZE];
        data[..len].copy_from_slice(&value);

        Ok(Self {
            len: len as u32,
            data,
        })
    }
}

#[cfg(feature = "user")]
unsafe impl<T, const MAX_SIZE: usize> aya::Pod for BoundedVec<T, MAX_SIZE> where
    T: aya::Pod + Copy + Clone + Default
{
}
