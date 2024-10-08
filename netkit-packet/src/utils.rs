//! Utilitie types and functions for netkit-packet.

pub mod field;
pub mod test_enum;

pub use field::*;

pub(crate) fn cast_from_bytes<T>(s: &[u8]) -> &T {
    unsafe { &*(s.as_ptr() as *const T) }
}

pub(crate) fn cast_from_bytes_mut<T>(s: &mut [u8]) -> &mut T {
    unsafe { &mut *(s.as_mut_ptr() as *mut T) }
}

macro_rules! layer_impl {
    ($name : ident) => {
        impl<T> AsRef<[u8]> for $name<T>
        where
            T: AsRef<[u8]>,
        {
            fn as_ref(&self) -> &[u8] {
                self.data.as_ref()
            }
        }

        impl<T> AsMut<[u8]> for $name<T>
        where
            T: AsRef<[u8]> + AsMut<[u8]>,
        {
            fn as_mut(&mut self) -> &mut [u8] {
                self.data.as_mut()
            }
        }

        impl<T> AsRef<T> for $name<T>
        where
            T: AsRef<[u8]>,
        {
            fn as_ref(&self) -> &T {
                &self.data
            }
        }

        impl<T> AsMut<T> for $name<T>
        where
            T: AsRef<[u8]> + AsMut<[u8]>,
        {
            fn as_mut(&mut self) -> &mut T {
                &mut self.data
            }
        }
    };
}
pub(crate) use layer_impl;
