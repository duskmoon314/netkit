//! Field Accessors
//!
//! This module provides a wrapper to access fields in a packet.

/// Target trait
///
/// This trait is used to convert between the underlay type and the target type.
pub trait Target<U> {
    /// Convert from underlay to target
    fn from_underlay(x: U) -> Self;

    /// Convert from target to underlay
    fn into_underlay(self) -> U;
}

/// Implement the Target trait for given types
///
/// # Arguments
///
/// - `option`: The conversion option, currently supported options are:
///   - `frominto`: Implement `from_underlay` and `into_underlay` using `From` and `Into`
///   - `as`: Implement `from_underlay` and `into_underlay` using `as`
/// - `t`: The target type
/// - `u`: The underlay type
#[macro_export]
macro_rules! impl_target {
    (frominto, $t: ty, $u: ty) => {
        impl $crate::utils::field::Target<$u> for $t {
            fn from_underlay(x: $u) -> Self {
                x.into()
            }
            fn into_underlay(self) -> $u {
                self.into()
            }
        }
    };

    (as, $t: ty, $u: ty) => {
        impl $crate::utils::field::Target<$u> for $t {
            fn from_underlay(x: $u) -> Self {
                x as Self
            }
            fn into_underlay(self) -> $u {
                self as $u
            }
        }
    };
}

impl_target!(frominto, u8, u8);
impl_target!(frominto, u16, u16);
impl_target!(frominto, u32, u32);
impl_target!(frominto, u64, u64);
impl_target!(as, u8, u16);
impl_target!(as, u8, u32);
impl_target!(as, u8, u64);
impl_target!(as, u16, u32);
impl_target!(as, u16, u64);
impl_target!(as, u32, u64);

impl Target<u8> for bool {
    fn from_underlay(x: u8) -> Self {
        x != 0
    }
    fn into_underlay(self) -> u8 {
        if self { 1 } else { 0 }
    }
}

impl Target<u64> for [u8; 8] {
    fn from_underlay(x: u64) -> Self {
        x.to_be_bytes()
    }
    fn into_underlay(self) -> u64 {
        u64::from_be_bytes(self)
    }
}

/// Underlay trait
///
/// This trait marks the types that can be used as underlay for fields and
/// provides methods to operate on them.
pub trait Underlay: Copy {
    /// Convert from big-endian
    fn from_be(x: Self) -> Self;
    /// Convert from little-endian
    fn from_le(x: Self) -> Self;
    /// Convert to big-endian
    fn to_be(self) -> Self;
    /// Convert to little-endian
    fn to_le(self) -> Self;

    /// Shift left
    fn shl(self, shift: u8) -> Self;
    /// Shift right
    fn shr(self, shift: u8) -> Self;
    /// Mask
    ///
    /// This method is like `bitand` but it takes a `u64` as argument
    fn mask(self, mask: u64) -> Self;
    /// Bitwise and
    fn bitand(self, rhs: Self) -> Self;
    /// Bitwise or
    fn bitor(self, rhs: Self) -> Self;
}

/// Implement the Underlay trait for given types
macro_rules! impl_underlay {
    ($($t:ty),*) => {
        $(
            impl Underlay for $t {
                #[inline]
                fn from_be(x: Self) -> Self {
                    Self::from_be(x)
                }
                #[inline]
                fn from_le(x: Self) -> Self {
                    Self::from_le(x)
                }
                #[inline]
                fn to_be(self) -> Self {
                    Self::to_be(self)
                }
                #[inline]
                fn to_le(self) -> Self {
                    Self::to_le(self)
                }
                #[inline]
                fn shl(self, shift: u8) -> Self {
                    self << shift
                }
                #[inline]
                fn shr(self, shift: u8) -> Self {
                    self >> shift
                }
                #[inline]
                fn mask(self, mask: u64) -> Self {
                    self & mask as Self
                }
                #[inline]
                fn bitand(self, rhs: Self) -> Self {
                    self & rhs
                }
                #[inline]
                fn bitor(self, rhs: Self) -> Self {
                    self | rhs
                }
            }
        )*
    };

    ($($l:literal),*) => {
        $(
            impl Underlay for [u8; $l] {
                #[inline]
                fn from_be(x: Self) -> Self {
                    x
                }
                #[inline]
                fn from_le(x: Self) -> Self {
                    let mut x = x;
                    x.reverse();
                    x
                }
                #[inline]
                fn to_be(self) -> Self {
                    self
                }
                #[inline]
                fn to_le(self) -> Self {
                    let mut x = self;
                    x.reverse();
                    x
                }
                #[inline]
                fn shl(self, shift: u8) -> Self {
                    let mut tmp: [u8; 8] = [0; 8];
                    for i in 8-$l..8 {
                        tmp[i] = self[i-(8-$l)];
                    }
                    let mut tmp = u64::from_be_bytes(tmp);
                    tmp <<= shift;
                    let tmp = tmp.to_be_bytes();
                    let ret = tmp[8-$l..8].try_into().unwrap();
                    ret
                }
                #[inline]
                fn shr(self, shift: u8) -> Self {
                    let mut tmp: [u8; 8] = [0; 8];
                    for i in 8-$l..8 {
                        tmp[i] = self[i-(8-$l)];
                    }
                    let mut tmp = u64::from_be_bytes(tmp);
                    tmp >>= shift;
                    let tmp = tmp.to_be_bytes();
                    let ret = tmp[8-$l..8].try_into().unwrap();
                    ret
                }
                #[inline]
                fn mask(self, mask: u64) -> Self {
                    let mut ret = [0; $l];
                    let mask = mask.to_be_bytes();
                    for i in 0..$l {
                        ret[i] = self[i] & mask[8 - $l + i]
                    }
                    ret
                }
                #[inline]
                fn bitand(self, rhs: Self) -> Self {
                    let mut ret = [0; $l];
                    for i in 0..$l {
                        ret[i] = self[i] & rhs[i];
                    }
                    ret
                }
                #[inline]
                fn bitor(self, rhs: Self) -> Self {
                    let mut ret = [0; $l];
                    for i in 0..$l {
                        ret[i] = self[i] | rhs[i];
                    }
                    ret
                }
            }
        )*
    };
}

impl_underlay!(u8, u16, u32, u64);
impl_underlay!(3, 5, 6, 7);

/// Field specification
///
/// This trait wraps the field specification:
/// - The target type `T`
/// - The underlay type `U`
/// - The mask value `MASK`
/// - The shift value `SHIFT`
pub trait FieldSpec {
    /// The target type
    ///
    /// This is the type of the value that the field represents
    type T: Target<Self::U>;

    /// The underlay type
    ///
    /// This is the type of the value that the field is stored in
    type U: Underlay;

    /// The mask value
    const MASK: u64 = u64::MAX;

    /// The shift value
    const SHIFT: u8 = 0;
}

/// Field specification macro
///
/// This helper macro is used to define a field specification.
///
/// ```ignore
/// field_spec!(MyFieldSpec, u8, u16, 0xFF00, 8);
///           ^^^^^^^^^^^  ^^  ^^^  ^^^^^^  ^
///           |            |   |    |       +-- Shift value (optional, default: 0)
///           |            |   |    +-- Mask value (optional, default: u64::MAX)
///           |            |   +-- Underlay type
///           |            +-- Target type
///           +-- Name of the FieldSpec struct
/// ```
#[macro_export]
macro_rules! field_spec {
    // FieldSpec with only target and underlay
    ($name: ident, $t:ty, $u:ty) => {
        #[doc = concat!("FieldSpec for `", stringify!($name), "` field\n\n")]
        #[doc = concat!("Target type: `", stringify!($t), "`\n")]
        #[doc = concat!("Underlay type: `", stringify!($u), "`\n")]
        #[derive(Debug, Clone, Copy)]
        pub struct $name;
        impl $crate::utils::field::FieldSpec for $name {
            type T = $t;
            type U = $u;
        }
    };

    // FieldSpec with target, underlay and mask
    ($name: ident, $t:ty, $u:ty, $m:expr) => {
        #[doc = concat!("FieldSpec for `", stringify!($name), "` field\n\n")]
        #[doc = concat!("Target type: `", stringify!($t), "`\n")]
        #[doc = concat!("Underlay type: `", stringify!($u), "`\n")]
        #[doc = concat!("Mask: `", stringify!($m), "`\n")]
        #[derive(Debug, Clone, Copy)]
        pub struct $name;
        impl $crate::utils::field::FieldSpec for $name {
            type T = $t;
            type U = $u;
            const MASK: u64 = $m;
        }
    };

    // FieldSpec with target, underlay, mask and shift
    ($name: ident, $t:ty, $u:ty, $m:expr, $s:expr) => {
        #[doc = concat!("FieldSpec for `", stringify!($name), "` field\n\n")]
        #[doc = concat!("Target type: `", stringify!($t), "`\n")]
        #[doc = concat!("Underlay type: `", stringify!($u), "`\n")]
        #[doc = concat!("Mask: `", stringify!($m), "`\n")]
        #[doc = concat!("Shift: `", stringify!($s), "`\n")]
        #[derive(Debug, Clone, Copy)]
        pub struct $name;
        impl $crate::utils::field::FieldSpec for $name {
            type T = $t;
            type U = $u;
            const MASK: u64 = $m;
            const SHIFT: u8 = $s;
        }
    };
}

/// Field accessor that works with unaligned data.
///
/// This accessor uses `ptr::read_unaligned` and (when mutable) `ptr::write_unaligned`
/// internally, making it safe to use with any byte slice regardless of alignment.
/// On x86/x64, this compiles to the same efficient code as aligned access.
///
/// The accessor supports both immutable and mutable access depending on the
/// type parameter `T`:
/// - `T: AsRef<[u8]>` - provides immutable access via `get()`
/// - `T: AsRef<[u8]> + AsMut<[u8]>` - provides both immutable and mutable access via `get()` and `set()`
///
/// # Examples
///
/// ```
/// # use netkit_packet::utils::field::{FieldAccessor, FieldSpec};
/// # use netkit_packet::field_spec;
/// // Define a field specification
/// // Only the high byte of a u16 is used
/// field_spec!(MyFieldSpec, u8, u16, 0xFF00, 8);
///
/// // Immutable access
/// let bytes = &[0x12, 0x34];
/// let field = FieldAccessor::<&[u8], MyFieldSpec>::new(bytes);
/// let value = field.get();
/// assert_eq!(value, 0x12);
///
/// // Mutable access
/// let bytes = &mut [0x12, 0x34];
/// let mut field = FieldAccessor::<&mut [u8], MyFieldSpec>::new(bytes);
/// field.set(42);
/// assert_eq!(field.get(), 42);
/// assert_eq!(bytes, &[42, 0x34]);
/// ```
#[derive(Debug)]
pub struct FieldAccessor<T, F: FieldSpec, const MSB: bool = true> {
    bytes: T,
    _marker: std::marker::PhantomData<F>,
}

impl<T: AsRef<[u8]>, F: FieldSpec, const MSB: bool> FieldAccessor<T, F, MSB> {
    /// Create a new field accessor from a type that can provide byte access.
    #[inline]
    pub fn new(bytes: T) -> Self {
        Self {
            bytes,
            _marker: std::marker::PhantomData,
        }
    }

    /// Get the **raw** value of the field.
    ///
    /// Returns the underlay type value after applying mask and shift operations,
    /// but **without** converting to the target type.
    ///
    /// This is useful when you need the actual underlying value for operations
    /// like hashing or when the target type conversion loses information.
    #[inline]
    pub fn raw(&self) -> F::U {
        use crate::utils::read_unaligned;

        let bytes = self.bytes.as_ref();

        // Read underlay value using unaligned access
        let value = read_unaligned::<F::U>(bytes);

        // Apply endianness conversion
        let value = if MSB {
            F::U::from_be(value)
        } else {
            F::U::from_le(value)
        };

        // Apply mask and shift
        if F::MASK == u64::MAX && F::SHIFT == 0 {
            value
        } else if F::SHIFT == 0 {
            value.mask(F::MASK)
        } else {
            value.mask(F::MASK).shr(F::SHIFT)
        }
    }

    /// Get the value of the field.
    ///
    /// Returns the target type value after applying mask, shift, and type conversion.
    #[inline]
    pub fn get(&self) -> F::T {
        F::T::from_underlay(self.raw())
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>, F: FieldSpec, const MSB: bool> FieldAccessor<T, F, MSB> {
    /// Set the value of the field.
    ///
    /// This method is only available when the underlying storage is mutable.
    #[inline]
    pub fn set(&mut self, value: F::T) {
        use crate::utils::{read_unaligned, write_unaligned};

        let bytes = self.bytes.as_mut();

        // Read current value
        let prev_value = read_unaligned::<F::U>(bytes);
        let prev_value = if MSB {
            F::U::from_be(prev_value)
        } else {
            F::U::from_le(prev_value)
        };

        // Apply mask and shift logic
        let new_value = if F::MASK == u64::MAX && F::SHIFT == 0 {
            value.into_underlay()
        } else if F::SHIFT == 0 {
            prev_value.mask(!F::MASK).bitor(value.into_underlay())
        } else {
            prev_value
                .mask(!F::MASK)
                .bitor(value.into_underlay().shl(F::SHIFT))
        };

        // Apply endianness conversion
        let new_value = if MSB {
            new_value.to_be()
        } else {
            new_value.to_le()
        };

        // Write back using unaligned access
        write_unaligned(bytes, new_value);
    }
}

impl<T: AsRef<[u8]>, F: FieldSpec, const MSB: bool> PartialEq<F::T> for FieldAccessor<T, F, MSB>
where
    F::T: PartialEq,
{
    fn eq(&self, other: &F::T) -> bool {
        self.get() == *other
    }
}

/// Type alias for read-only field accessor
///
/// This is equivalent to `FieldAccessor<&'a [u8], F, MSB>`.
// pub type FieldRef<'a, F, const MSB: bool = true> = FieldAccessor<&'a [u8], F, MSB>;
pub type FieldRef<'a, F, T = &'a [u8], const MSB: bool = true> = FieldAccessor<T, F, MSB>;

/// Type alias for mutable field accessor
///
/// This is equivalent to `FieldAccessor<&'a mut [u8], F, MSB>`.
pub type FieldMut<'a, F, T = &'a mut [u8], const MSB: bool = true> = FieldAccessor<T, F, MSB>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_field_accessor_with_mask_and_shift() {
        field_spec!(TestField, u16, u16, 0x0F00, 8);

        // Test MSB (big-endian) with mask and shift
        let mut bytes = [0x00, 0x00];
        {
            let mut field = FieldAccessor::<_, TestField>::new(&mut bytes[..]);
            assert_eq!(field.get(), 0);
            field.set(0x0F);
            assert_eq!(field.get(), 0x0F);
        }
        assert_eq!(bytes, [0x0F, 0x00]);

        {
            let mut field = FieldAccessor::<_, TestField>::new(&mut bytes[..]);
            field.set(0x0A);
            assert_eq!(field.get(), 0x0A);
        }
        assert_eq!(bytes, [0x0A, 0x00]);

        // Test LSB (little-endian) with mask and shift
        let mut bytes = [0x00, 0x00];
        {
            let mut field = FieldAccessor::<_, TestField, false>::new(&mut bytes[..]);
            assert_eq!(field.get(), 0);
            field.set(0x0F);
            assert_eq!(field.get(), 0x0F);
        }
        assert_eq!(bytes, [0x00, 0x0F]);

        {
            let mut field = FieldAccessor::<_, TestField, false>::new(&mut bytes[..]);
            field.set(0x0A);
            assert_eq!(field.get(), 0x0A);
        }
        assert_eq!(bytes, [0x00, 0x0A]);
    }

    #[test]
    fn test_field_accessor_unified() {
        field_spec!(TestFieldU16, u16, u16);

        // Test with immutable reference (&[u8])
        let bytes = [0x12, 0x34];
        let field = FieldAccessor::<_, TestFieldU16>::new(&bytes[..]);
        assert_eq!(field.get(), 0x1234);

        // Test with mutable reference - write
        let mut bytes = [0x12, 0x34];
        let mut field = FieldAccessor::<_, TestFieldU16>::new(&mut bytes[..]);
        assert_eq!(field.get(), 0x1234);
        field.set(0xABCD);
        assert_eq!(field.get(), 0xABCD);
        assert_eq!(bytes, [0xAB, 0xCD]);
    }

    #[test]
    fn test_field_accessor_with_vec() {
        field_spec!(TestU32Field, u32, u32);

        // Test with Vec<u8> - demonstrates flexibility beyond slices
        let mut data = vec![0x12, 0x34, 0x56, 0x78];
        let mut field = FieldAccessor::<&mut [u8], TestU32Field>::new(&mut data);
        assert_eq!(field.get(), 0x12345678);
        field.set(0xDEADBEEF);
        assert_eq!(field.get(), 0xDEADBEEF);
        assert_eq!(data, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn test_field_accessor_with_bitfields() {
        field_spec!(FlagField, u8, u16, 0x8000, 15); // MSB flag

        let bytes = [0x80, 0x00];
        let field = FieldAccessor::<_, FlagField>::new(&bytes[..]);
        assert_eq!(field.get(), 1);

        let bytes = [0x00, 0x00];
        let field = FieldAccessor::<_, FlagField>::new(&bytes[..]);
        assert_eq!(field.get(), 0);

        let mut bytes = [0x00, 0x00];
        let mut field = FieldAccessor::<_, FlagField>::new(&mut bytes[..]);
        field.set(1);
        assert_eq!(bytes, [0x80, 0x00]);
    }

    #[test]
    fn test_field_accessor_raw() {
        // Test raw() returns underlay type before conversion
        field_spec!(TestRaw, u8, u16, 0xFF00, 8);

        let bytes = [0x12, 0x34];
        let field = FieldAccessor::<_, TestRaw>::new(&bytes[..]);
        assert_eq!(field.raw(), 0x12u16); // Returns u16 (underlay)
        assert_eq!(field.get(), 0x12u8); // Returns u8 (target)

        // Test with full value (no mask/shift)
        field_spec!(TestRawFull, u16, u16);
        let bytes = [0xAB, 0xCD];
        let field = FieldAccessor::<_, TestRawFull>::new(&bytes[..]);
        assert_eq!(field.raw(), 0xABCD);
        assert_eq!(field.get(), 0xABCD);

        // Test raw() with bitfield
        field_spec!(TestRawBit, u8, u16, 0x0F00, 8);
        let bytes = [0x0A, 0x00];
        let field = FieldAccessor::<_, TestRawBit>::new(&bytes[..]);
        assert_eq!(field.raw(), 0x0Au16); // Masked and shifted
        assert_eq!(field.get(), 0x0Au8); // Converted to u8
    }
}
