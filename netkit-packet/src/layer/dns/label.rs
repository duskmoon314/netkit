//! Dns Label

use crate::field_spec;
use crate::prelude::*;

/// Dns Label
///
/// Label is a part of domain name, it can be a normal label or a compressed label.
///
/// ## Format
///
/// ### Normal
///
/// ```text
///   0  1  2  3  4  5  6  7
/// +--+--+--+--+--+--+--+--+---~---+
/// | 0| 0|             LEN | LABEL |
/// +--+--+--+--+--+--+--+--+---~---+
/// ```
///
/// ```
/// # use netkit_packet::layer::dns::DnsLabel;
/// let data: [u8; 8] = [0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e']; // 7example
/// let label = unsafe { DnsLabel::new_unchecked(data) };
/// assert_eq!(label.is_normal(), true);
/// assert_eq!(label.is_compressed(), false);
/// assert_eq!(label.len().unwrap().get(), 7);
/// assert!(label.offset().is_none());
/// assert_eq!(label.label().unwrap(), b"example");
/// ```
///
/// ### Compressed
///
/// ```text
///   0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// | 1| 1|                                  OFFSET |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// ```
///
/// ```
/// # use netkit_packet::layer::dns::DnsLabel;
/// let data: [u8; 2] = [0xC0, 0x0C]; // 0x0C
/// let label = unsafe { DnsLabel::new_unchecked(data) };
/// assert_eq!(label.is_normal(), false);
/// assert_eq!(label.is_compressed(), true);
/// assert!(label.len().is_none());
/// assert_eq!(label.offset().unwrap().get(), 0x0C);
/// assert!(label.label().is_none());
/// ```
#[derive(Clone, Debug)]
pub struct DnsLabel<T> {
    data: T,
}

field_spec!(TypeSpec, u8, u8, 0xC0, 6);
field_spec!(LenSpec, u8, u8, 0x3F);
field_spec!(OffsetSpec, u16, u16, 0x3FFF);

impl<T> DnsLabel<T>
where
    T: AsRef<[u8]>,
{
    /// Create a new DnsLabel without validation
    ///
    /// # Safety
    ///
    /// The caller must ensure the data is a valid DnsLabel
    #[inline]
    pub const unsafe fn new_unchecked(data: T) -> Self {
        DnsLabel { data }
    }

    /// Get the inner data
    #[inline]
    pub const fn inner(&self) -> &T {
        &self.data
    }

    /// Get the accessor of Type
    #[inline]
    pub fn type_(&self) -> &Field<TypeSpec> {
        cast_from_bytes(&self.data.as_ref()[0..1])
    }

    /// Get whether the label is normal
    pub fn is_normal(&self) -> bool {
        *self.type_() == 0
    }

    /// Get whether the label is compressed
    pub fn is_compressed(&self) -> bool {
        *self.type_() == 0x03
    }

    /// Get the length of the normal label
    pub fn len(&self) -> Option<&Field<LenSpec>> {
        if self.is_normal() {
            Some(cast_from_bytes(&self.data.as_ref()[0..1]))
        } else {
            None
        }
    }

    /// Get the offset of the compressed label
    pub fn offset(&self) -> Option<&Field<OffsetSpec>> {
        if self.is_compressed() {
            Some(cast_from_bytes(&self.data.as_ref()[0..2]))
        } else {
            None
        }
    }

    /// Get the label data of the normal one
    pub fn label(&self) -> Option<&[u8]> {
        if self.is_normal() {
            let len = self.data.as_ref()[0] as usize;
            Some(&self.data.as_ref()[1..1 + len])
        } else {
            None
        }
    }

    /// Convert the label to a str
    pub fn as_str(&self) -> Option<&str> {
        self.label()
            .map(|l| unsafe { std::str::from_utf8_unchecked(l) })
    }
}

impl<T> PartialEq<str> for DnsLabel<T>
where
    T: AsRef<[u8]>,
{
    fn eq(&self, other: &str) -> bool {
        self.label().map(|l| l == other.as_bytes()).unwrap_or(false)
    }
}

impl<T> PartialEq<&str> for DnsLabel<T>
where
    T: AsRef<[u8]>,
{
    fn eq(&self, other: &&str) -> bool {
        self.eq(*other)
    }
}
