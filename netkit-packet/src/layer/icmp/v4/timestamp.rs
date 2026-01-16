//! ICMPv4 Timestamp Request and Timestamp Reply messages.

use crate::{field_spec, prelude::*};

field_spec!(TimestampIdSpec, u16, u16);
field_spec!(TimestampSequenceSpec, u16, u16);
field_spec!(TimestampValueSpec, u32, u32);

/// ICMPv4 Timestamp Request (Type 13) and Timestamp Reply (Type 14).
///
/// The timestamp message is used for time synchronization. The Originate Timestamp
/// is the time the sender last touched the message before sending it, the Receive
/// Timestamp is the time the echoer first touched it on receipt, and the Transmit
/// Timestamp is the time the echoer last touched the message on sending it.
///
/// ```text
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Type      |     Code      |          Checksum             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |           Identifier          |        Sequence Number        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                     Originate Timestamp                       |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                      Receive Timestamp                        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                      Transmit Timestamp                       |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// **Type**:
/// - 13 for Timestamp Request
/// - 14 for Timestamp Reply
///
/// **Code**: 0
///
/// **Identifier**: Aid in matching timestamps
///
/// **Sequence Number**: Aid in matching timestamps
///
/// **Timestamps**: Number of milliseconds since midnight UT. If the time is not
/// available in milliseconds or cannot be provided with respect to midnight UT,
/// then any time may be inserted provided the high-order bit is set to 1 to
/// indicate this non-standard value.
///
/// Defined in RFC 792.
pub struct Icmpv4Timestamp<T>
where
    T: AsRef<[u8]>,
{
    data: T,
}

impl<T> Icmpv4Timestamp<T>
where
    T: AsRef<[u8]>,
{
    /// Minimum and fixed message length.
    pub const MIN_LENGTH: usize = 20;

    /// Field range for identifier.
    pub const FIELD_IDENTIFIER: core::ops::Range<usize> = 4..6;
    /// Field range for sequence number.
    pub const FIELD_SEQUENCE: core::ops::Range<usize> = 6..8;
    /// Field range for originate timestamp.
    pub const FIELD_ORIGINATE_TIMESTAMP: core::ops::Range<usize> = 8..12;
    /// Field range for receive timestamp.
    pub const FIELD_RECEIVE_TIMESTAMP: core::ops::Range<usize> = 12..16;
    /// Field range for transmit timestamp.
    pub const FIELD_TRANSMIT_TIMESTAMP: core::ops::Range<usize> = 16..20;

    /// Create from ICMP packet data.
    ///
    /// # Safety
    ///
    /// Caller must ensure data is at least 20 bytes.
    #[inline]
    pub const unsafe fn new_unchecked(data: T) -> Self {
        Self { data }
    }

    /// Create from ICMP packet data with validation.
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
    pub fn identifier(&self) -> FieldRef<'_, TimestampIdSpec> {
        FieldRef::new(&self.as_ref()[Self::FIELD_IDENTIFIER])
    }

    /// Get the sequence number.
    #[inline]
    pub fn sequence(&self) -> FieldRef<'_, TimestampSequenceSpec> {
        FieldRef::new(&self.as_ref()[Self::FIELD_SEQUENCE])
    }

    /// Get the originate timestamp (milliseconds since midnight UT).
    #[inline]
    pub fn originate_timestamp(&self) -> FieldRef<'_, TimestampValueSpec> {
        FieldRef::new(&self.as_ref()[Self::FIELD_ORIGINATE_TIMESTAMP])
    }

    /// Get the receive timestamp (milliseconds since midnight UT).
    #[inline]
    pub fn receive_timestamp(&self) -> FieldRef<'_, TimestampValueSpec> {
        FieldRef::new(&self.as_ref()[Self::FIELD_RECEIVE_TIMESTAMP])
    }

    /// Get the transmit timestamp (milliseconds since midnight UT).
    #[inline]
    pub fn transmit_timestamp(&self) -> FieldRef<'_, TimestampValueSpec> {
        FieldRef::new(&self.as_ref()[Self::FIELD_TRANSMIT_TIMESTAMP])
    }
}

impl<T> Icmpv4Timestamp<T>
where
    T: AsRef<[u8]> + AsMut<[u8]>,
{
    /// Get mutable access to identifier.
    #[inline]
    pub fn identifier_mut(&mut self) -> FieldMut<'_, TimestampIdSpec> {
        FieldMut::new(&mut self.as_mut()[Self::FIELD_IDENTIFIER])
    }

    /// Get mutable access to sequence number.
    #[inline]
    pub fn sequence_mut(&mut self) -> FieldMut<'_, TimestampSequenceSpec> {
        FieldMut::new(&mut self.as_mut()[Self::FIELD_SEQUENCE])
    }

    /// Get mutable access to originate timestamp.
    #[inline]
    pub fn originate_timestamp_mut(&mut self) -> FieldMut<'_, TimestampValueSpec> {
        FieldMut::new(&mut self.as_mut()[Self::FIELD_ORIGINATE_TIMESTAMP])
    }

    /// Get mutable access to receive timestamp.
    #[inline]
    pub fn receive_timestamp_mut(&mut self) -> FieldMut<'_, TimestampValueSpec> {
        FieldMut::new(&mut self.as_mut()[Self::FIELD_RECEIVE_TIMESTAMP])
    }

    /// Get mutable access to transmit timestamp.
    #[inline]
    pub fn transmit_timestamp_mut(&mut self) -> FieldMut<'_, TimestampValueSpec> {
        FieldMut::new(&mut self.as_mut()[Self::FIELD_TRANSMIT_TIMESTAMP])
    }
}

impl<T: AsRef<[u8]>> AsRef<[u8]> for Icmpv4Timestamp<T> {
    fn as_ref(&self) -> &[u8] {
        self.data.as_ref()
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> AsMut<[u8]> for Icmpv4Timestamp<T> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.data.as_mut()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timestamp_request() {
        let data = vec![
            0x0d, 0x00, // type=13 (Timestamp Request), code=0
            0x00, 0x00, // checksum
            0x12, 0x34, // identifier
            0x00, 0x01, // sequence
            0x00, 0x00, 0x10, 0x00, // originate timestamp
            0x00, 0x00, 0x00, 0x00, // receive timestamp
            0x00, 0x00, 0x00, 0x00, // transmit timestamp
        ];

        let ts = Icmpv4Timestamp::new(&data[..]).unwrap();
        assert_eq!(ts.identifier().get(), 0x1234);
        assert_eq!(ts.sequence().get(), 1);
        assert_eq!(ts.originate_timestamp().get(), 0x1000);
        assert_eq!(ts.receive_timestamp().get(), 0);
        assert_eq!(ts.transmit_timestamp().get(), 0);
    }

    #[test]
    fn test_timestamp_reply() {
        let data = vec![
            0x0e, 0x00, // type=14 (Timestamp Reply), code=0
            0x00, 0x00, // checksum
            0x12, 0x34, // identifier
            0x00, 0x01, // sequence
            0x00, 0x00, 0x10, 0x00, // originate timestamp
            0x00, 0x00, 0x20, 0x00, // receive timestamp
            0x00, 0x00, 0x30, 0x00, // transmit timestamp
        ];

        let ts = Icmpv4Timestamp::new(&data[..]).unwrap();
        assert_eq!(ts.identifier().get(), 0x1234);
        assert_eq!(ts.sequence().get(), 1);
        assert_eq!(ts.originate_timestamp().get(), 0x1000);
        assert_eq!(ts.receive_timestamp().get(), 0x2000);
        assert_eq!(ts.transmit_timestamp().get(), 0x3000);
    }

    #[test]
    fn test_timestamp_mutation() {
        let mut data = vec![
            0x0d, 0x00, // type=13, code=0
            0x00, 0x00, // checksum
            0x00, 0x00, // identifier
            0x00, 0x00, // sequence
            0x00, 0x00, 0x00, 0x00, // originate timestamp
            0x00, 0x00, 0x00, 0x00, // receive timestamp
            0x00, 0x00, 0x00, 0x00, // transmit timestamp
        ];

        let mut ts = Icmpv4Timestamp::new(&mut data[..]).unwrap();
        ts.identifier_mut().set(0xabcd);
        ts.sequence_mut().set(42);
        ts.originate_timestamp_mut().set(1000);
        ts.receive_timestamp_mut().set(2000);
        ts.transmit_timestamp_mut().set(3000);

        assert_eq!(ts.identifier().get(), 0xabcd);
        assert_eq!(ts.sequence().get(), 42);
        assert_eq!(ts.originate_timestamp().get(), 1000);
        assert_eq!(ts.receive_timestamp().get(), 2000);
        assert_eq!(ts.transmit_timestamp().get(), 3000);
    }
}
