//! Utilitie types and functions for netkit-packet.

use std::ptr;

pub mod field;
pub mod test_enum;

pub use field::*;

/// Read an underlay value using unaligned pointer access.
///
/// This is safe for any alignment and compiles to efficient code on x86/x64.
pub(crate) fn read_unaligned<U: Underlay>(bytes: &[u8]) -> U {
    unsafe { ptr::read_unaligned(bytes.as_ptr() as *const U) }
}

/// Write an underlay value using unaligned pointer access.
///
/// This is safe for any alignment and compiles to efficient code on x86/x64.
pub(crate) fn write_unaligned<U: Underlay>(bytes: &mut [u8], value: U) {
    unsafe { ptr::write_unaligned(bytes.as_mut_ptr() as *mut U, value) }
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

        impl $name<&[u8]> {
            /// Convert to owned layer.
            pub fn to_owned(&self) -> $name<Vec<u8>> {
                let data = self.data.as_ref().to_vec();
                unsafe { $name::new_unchecked(data) }
            }
        }
    };
}
pub(crate) use layer_impl;
