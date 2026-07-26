use core::ops::{
    Deref,
    DerefMut,
};

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct BoundedVec<T, const MAX_SIZE: usize> {
    pub len: u32,
    pub data: [T; MAX_SIZE],
}

impl<T, const MAX_SIZE: usize> Deref for BoundedVec<T, MAX_SIZE>
where
    T: Copy + Clone,
{
    type Target = [T; MAX_SIZE];

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl<T, const MAX_SIZE: usize> DerefMut for BoundedVec<T, MAX_SIZE>
where
    T: Copy + Clone,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.data
    }
}
