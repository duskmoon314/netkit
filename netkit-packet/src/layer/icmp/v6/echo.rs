//! ICMPv6 Echo Request/Reply messages.

use crate::{field_spec, prelude::*};

field_spec!(EchoIdSpec, u16, u16);
field_spec!(EchoSequenceSpec, u16, u16);

/// ICMPv6 Echo Request or Echo Reply message.
///
/// Used for ping utility over IPv6. Both request and reply use the same format.
///
/// ```text
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Type      |     Code      |          Checksum             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |           Identifier          |        Sequence Number        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Data ...
/// +-+-+-+-+-
/// ```
///
/// - **Type**: 128 for Echo Request, 129 for Echo Reply
/// - **Code**: Always 0
/// - **Checksum**: ICMPv6 checksum including IPv6 pseudo-header
/// - **Identifier**: Used to match requests with replies
/// - **Sequence Number**: Used to match requests with replies
/// - **Data**: Optional payload data (typically echoed back in reply)
pub struct Icmpv6Echo<T>
where
    T: AsRef<[u8]>,
{
    data: T,
}

impl<T> Icmpv6Echo<T>
where
    T: AsRef<[u8]>,
{
    /// Minimum message length (header only, no data).
    pub const MIN_LENGTH: usize = 8;

    /// Field range for identifier.
    pub const FIELD_IDENTIFIER: core::ops::Range<usize> = 4..6;
    /// Field range for sequence number.
    pub const FIELD_SEQUENCE: core::ops::Range<usize> = 6..8;
    /// Field range for data.
    pub const FIELD_DATA: core::ops::RangeFrom<usize> = 8..;

    /// Create from ICMPv6 packet data (starting from ICMPv6 header).
    ///
    /// # Safety
    ///
    /// Caller must ensure data is at least 8 bytes.
    #[inline]
    pub const unsafe fn new_unchecked(data: T) -> Self {
        Self { data }
    }

    /// Create from ICMPv6 packet data with validation.
    #[inline]
    pub fn new(data: T) -> Option<Self> {
        if data.as_ref().len() >= Self::MIN_LENGTH {
            Some(unsafe { Self::new_unchecked(data) })
        } else {
            None
        }
    }

    /// Get the identifier.
    #[inline]
    pub fn identifier(&self) -> FieldRef<'_, EchoIdSpec> {
        FieldRef::new(&self.as_ref()[Self::FIELD_IDENTIFIER])
    }

    /// Get the sequence number.
    #[inline]
    pub fn sequence(&self) -> FieldRef<'_, EchoSequenceSpec> {
        FieldRef::new(&self.as_ref()[Self::FIELD_SEQUENCE])
    }

    /// Get the data payload.
    #[inline]
    pub fn data(&self) -> &[u8] {
        &self.as_ref()[Self::FIELD_DATA]
    }
}

impl<T> Icmpv6Echo<T>
where
    T: AsRef<[u8]> + AsMut<[u8]>,
{
    /// Get mutable identifier.
    #[inline]
    pub fn identifier_mut(&mut self) -> FieldMut<'_, EchoIdSpec> {
        FieldMut::new(&mut self.as_mut()[Self::FIELD_IDENTIFIER])
    }

    /// Get mutable sequence number.
    #[inline]
    pub fn sequence_mut(&mut self) -> FieldMut<'_, EchoSequenceSpec> {
        FieldMut::new(&mut self.as_mut()[Self::FIELD_SEQUENCE])
    }

    /// Get mutable data payload.
    #[inline]
    pub fn data_mut(&mut self) -> &mut [u8] {
        &mut self.as_mut()[Self::FIELD_DATA]
    }
}

impl<T: AsRef<[u8]>> AsRef<[u8]> for Icmpv6Echo<T> {
    fn as_ref(&self) -> &[u8] {
        self.data.as_ref()
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> AsMut<[u8]> for Icmpv6Echo<T> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.data.as_mut()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_echo_parse() {
        let data = [
            0x80, 0x00, // type (128 = Echo Request), code
            0x00, 0x00, // checksum
            0x12, 0x34, // identifier
            0x00, 0x01, // sequence
            0xAA, 0xBB, // data
        ];

        let echo = Icmpv6Echo::new(&data[..]).unwrap();
        assert_eq!(echo.identifier().get(), 0x1234);
        assert_eq!(echo.sequence().get(), 1);
        assert_eq!(echo.data(), &[0xAA, 0xBB]);
    }

    #[test]
    fn test_echo_mutation() {
        let mut data = [
            0x80, 0x00, // type, code
            0x00, 0x00, // checksum
            0x00, 0x00, // identifier
            0x00, 0x00, // sequence
            0x00, 0x00, // data
        ];

        let mut echo = Icmpv6Echo::new(&mut data[..]).unwrap();
        echo.identifier_mut().set(0x5678);
        echo.sequence_mut().set(42);

        assert_eq!(echo.identifier().get(), 0x5678);
        assert_eq!(echo.sequence().get(), 42);
    }
}
