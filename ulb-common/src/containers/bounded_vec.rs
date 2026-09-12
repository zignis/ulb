#[cfg(feature = "user")]
use alloc::vec::Vec;
use core::{
    ops::{
        Deref,
        DerefMut,
    },
    slice::{
        Iter,
        IterMut,
    },
};

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct BoundedVec<T, const MAX_SIZE: usize>
where
    T: Copy + Clone + Default,
{
    pub len: u64,
    pub data: [T; MAX_SIZE],
}

impl<T, const MAX_SIZE: usize> BoundedVec<T, MAX_SIZE>
where
    T: Copy + Clone + Default,
{
    // only sets the len to 0
    pub fn reset(&mut self) {
        self.len = 0;
    }

    #[allow(clippy::result_unit_err)]
    #[cfg(feature = "user")]
    pub fn push(&mut self, element: T) -> Result<(), ()> {
        if self.len as usize >= MAX_SIZE {
            return Err(());
        }

        self.data[self.len as usize] = element;
        self.len += 1;

        Ok(())
    }

    #[cfg(feature = "user")]
    pub fn remove(&mut self, idx: usize) -> Option<T> {
        if idx >= self.len as usize {
            return None;
        }

        let prev = self.data[idx];

        self.len -= 1;
        self.data[idx] = self.data[self.len as usize];

        Some(prev)
    }
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

impl<'a, T, const MAX_SIZE: usize> IntoIterator for &'a BoundedVec<T, MAX_SIZE>
where
    T: Copy + Clone + Default,
{
    type Item = &'a T;
    type IntoIter = Iter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.data[..self.len as usize].iter()
    }
}

impl<'a, T, const MAX_SIZE: usize> IntoIterator for &'a mut BoundedVec<T, MAX_SIZE>
where
    T: Copy + Clone + Default,
{
    type Item = &'a mut T;
    type IntoIter = IterMut<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.data[..self.len as usize].iter_mut()
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
            len: len as u64,
            data,
        })
    }
}

#[cfg(feature = "user")]
impl<T, const MAX_SIZE: usize> Default for BoundedVec<T, MAX_SIZE>
where
    T: Copy + Clone + Default,
{
    fn default() -> Self {
        Self {
            len: 0,
            data: [T::default(); MAX_SIZE],
        }
    }
}

#[cfg(feature = "user")]
unsafe impl<T, const MAX_SIZE: usize> aya::Pod for BoundedVec<T, MAX_SIZE> where
    T: aya::Pod + Copy + Clone + Default
{
}
