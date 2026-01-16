//! ICMPv4 Extended Echo Request and Reply messages.

use crate::{field_spec, prelude::*};

field_spec!(ExtEchoIdSpec, u16, u16);
field_spec!(ExtEchoSequenceSpec, u16, u16);
field_spec!(ExtEchoLSpec, u8, u8);
field_spec!(ExtEchoStatusSpec, u8, u8);

/// ICMPv4 Extended Echo Request (Type 42).
///
/// Extended Echo Request is a modern enhancement to traditional ICMP Echo that
/// supports probing of interfaces by name, index, or address. It allows applications
/// to probe interfaces directly without needing to know their IP addresses.
///
/// ```text
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Type      |     Code      |          Checksum             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |           Identifier          |        Sequence Number        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   Reserved  |L|          Reserved                             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                    ICMP Extension Structure                   |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// **Type**: 42
/// **Code**: 0
///
/// **Identifier**: Aid in matching requests and replies
///
/// **Sequence Number**: Aid in matching requests and replies
///
/// **L-bit**: If set, the request is local (limited to interfaces on the same node).
/// If clear, the request can transit routers.
///
/// **ICMP Extension Structure**: Variable-length data containing identification
/// information (e.g., interface name, IPv4 address, IPv6 address, interface index)
///
/// Defined in RFC 8335.
pub struct IcmpExtendedEchoRequest<T>
where
    T: AsRef<[u8]>,
{
    data: T,
}

impl<T> IcmpExtendedEchoRequest<T>
where
    T: AsRef<[u8]>,
{
    /// Minimum message length.
    pub const MIN_LENGTH: usize = 12;

    /// Field range for identifier.
    pub const FIELD_IDENTIFIER: core::ops::Range<usize> = 4..6;
    /// Field range for sequence number.
    pub const FIELD_SEQUENCE: core::ops::Range<usize> = 6..8;
    /// Field range for L-bit and reserved.
    pub const FIELD_L_BIT: core::ops::Range<usize> = 8..9;
    /// Field range for extension structure.
    pub const FIELD_EXTENSION: core::ops::RangeFrom<usize> = 12..;

    /// Create from ICMP packet data.
    ///
    /// # Safety
    ///
    /// Caller must ensure data is at least 12 bytes.
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
    pub fn identifier(&self) -> FieldRef<'_, ExtEchoIdSpec> {
        FieldRef::new(&self.as_ref()[Self::FIELD_IDENTIFIER])
    }

    /// Get the sequence number.
    #[inline]
    pub fn sequence(&self) -> FieldRef<'_, ExtEchoSequenceSpec> {
        FieldRef::new(&self.as_ref()[Self::FIELD_SEQUENCE])
    }

    /// Get the L-bit value.
    ///
    /// Returns `true` if the request is local (limited to the same node).
    #[inline]
    pub fn local_bit(&self) -> bool {
        self.as_ref()[8] & 0x01 != 0
    }

    /// Get the extension structure data.
    #[inline]
    pub fn extension(&self) -> &[u8] {
        &self.as_ref()[Self::FIELD_EXTENSION]
    }
}

impl<T> IcmpExtendedEchoRequest<T>
where
    T: AsRef<[u8]> + AsMut<[u8]>,
{
    /// Get mutable access to identifier.
    #[inline]
    pub fn identifier_mut(&mut self) -> FieldMut<'_, ExtEchoIdSpec> {
        FieldMut::new(&mut self.as_mut()[Self::FIELD_IDENTIFIER])
    }

    /// Get mutable access to sequence number.
    #[inline]
    pub fn sequence_mut(&mut self) -> FieldMut<'_, ExtEchoSequenceSpec> {
        FieldMut::new(&mut self.as_mut()[Self::FIELD_SEQUENCE])
    }

    /// Set the L-bit value.
    #[inline]
    pub fn set_local_bit(&mut self, local: bool) {
        if local {
            self.as_mut()[8] |= 0x01;
        } else {
            self.as_mut()[8] &= !0x01;
        }
    }

    /// Get mutable access to extension structure.
    #[inline]
    pub fn extension_mut(&mut self) -> &mut [u8] {
        &mut self.as_mut()[Self::FIELD_EXTENSION]
    }
}

impl<T: AsRef<[u8]>> AsRef<[u8]> for IcmpExtendedEchoRequest<T> {
    fn as_ref(&self) -> &[u8] {
        self.data.as_ref()
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> AsMut<[u8]> for IcmpExtendedEchoRequest<T> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.data.as_mut()
    }
}

/// ICMPv4 Extended Echo Reply (Type 43).
///
/// Extended Echo Reply is sent in response to an Extended Echo Request.
///
/// ```text
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Type      |     Code      |          Checksum             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |           Identifier          |        Sequence Number        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// | State | Res |A|          Reserved                             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// **Type**: 43
///
/// **Code**: Values include:
/// - 0: No Error
/// - 1: Malformed Query
/// - 2: No Such Interface
/// - 3: No Such Table Entry
/// - 4: Multiple Interfaces Satisfy Query
///
/// **State**: 3-bit field indicating interface state:
/// - 0: Reserved
/// - 1: Reserved
/// - 2: Interface Active
/// - 3: Interface Inactive
///
/// **A-bit**: If set, the responder is authoritative for the target interface.
///
/// Defined in RFC 8335.
pub struct IcmpExtendedEchoReply<T>
where
    T: AsRef<[u8]>,
{
    data: T,
}

impl<T> IcmpExtendedEchoReply<T>
where
    T: AsRef<[u8]>,
{
    /// Minimum and fixed message length.
    pub const MIN_LENGTH: usize = 12;

    /// Field range for identifier.
    pub const FIELD_IDENTIFIER: core::ops::Range<usize> = 4..6;
    /// Field range for sequence number.
    pub const FIELD_SEQUENCE: core::ops::Range<usize> = 6..8;
    /// Field range for state and flags.
    pub const FIELD_STATE: core::ops::Range<usize> = 8..9;

    /// Create from ICMP packet data.
    ///
    /// # Safety
    ///
    /// Caller must ensure data is at least 12 bytes.
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
    pub fn identifier(&self) -> FieldRef<'_, ExtEchoIdSpec> {
        FieldRef::new(&self.as_ref()[Self::FIELD_IDENTIFIER])
    }

    /// Get the sequence number.
    #[inline]
    pub fn sequence(&self) -> FieldRef<'_, ExtEchoSequenceSpec> {
        FieldRef::new(&self.as_ref()[Self::FIELD_SEQUENCE])
    }

    /// Get the state field (3 bits).
    ///
    /// Returns:
    /// - 0 or 1: Reserved
    /// - 2: Interface Active
    /// - 3: Interface Inactive
    #[inline]
    pub fn state(&self) -> u8 {
        (self.as_ref()[8] >> 5) & 0x07
    }

    /// Get the A-bit (authoritative) value.
    ///
    /// Returns `true` if the responder is authoritative for the target interface.
    #[inline]
    pub fn authoritative_bit(&self) -> bool {
        self.as_ref()[8] & 0x01 != 0
    }

    /// Check if the interface is active.
    #[inline]
    pub fn is_active(&self) -> bool {
        self.state() == 2
    }

    /// Check if the interface is inactive.
    #[inline]
    pub fn is_inactive(&self) -> bool {
        self.state() == 3
    }
}

impl<T> IcmpExtendedEchoReply<T>
where
    T: AsRef<[u8]> + AsMut<[u8]>,
{
    /// Get mutable access to identifier.
    #[inline]
    pub fn identifier_mut(&mut self) -> FieldMut<'_, ExtEchoIdSpec> {
        FieldMut::new(&mut self.as_mut()[Self::FIELD_IDENTIFIER])
    }

    /// Get mutable access to sequence number.
    #[inline]
    pub fn sequence_mut(&mut self) -> FieldMut<'_, ExtEchoSequenceSpec> {
        FieldMut::new(&mut self.as_mut()[Self::FIELD_SEQUENCE])
    }

    /// Set the state field (3 bits).
    #[inline]
    pub fn set_state(&mut self, state: u8) {
        let state = (state & 0x07) << 5;
        self.as_mut()[8] = (self.as_mut()[8] & 0x1f) | state;
    }

    /// Set the A-bit (authoritative) value.
    #[inline]
    pub fn set_authoritative_bit(&mut self, auth: bool) {
        if auth {
            self.as_mut()[8] |= 0x01;
        } else {
            self.as_mut()[8] &= !0x01;
        }
    }
}

impl<T: AsRef<[u8]>> AsRef<[u8]> for IcmpExtendedEchoReply<T> {
    fn as_ref(&self) -> &[u8] {
        self.data.as_ref()
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> AsMut<[u8]> for IcmpExtendedEchoReply<T> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.data.as_mut()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extended_echo_request() {
        let data = vec![
            0x2a, 0x00, // type=42, code=0
            0x00, 0x00, // checksum
            0x12, 0x34, // identifier
            0x00, 0x01, // sequence
            0x01, // L-bit set, reserved
            0x00, 0x00, 0x00, // reserved
        ];

        let req = IcmpExtendedEchoRequest::new(&data[..]).unwrap();
        assert_eq!(req.identifier().get(), 0x1234);
        assert_eq!(req.sequence().get(), 1);
        assert!(req.local_bit());
    }

    #[test]
    fn test_extended_echo_request_mutation() {
        let mut data = vec![
            0x2a, 0x00, // type=42, code=0
            0x00, 0x00, // checksum
            0x00, 0x00, // identifier
            0x00, 0x00, // sequence
            0x00, // L-bit clear
            0x00, 0x00, 0x00, // reserved
        ];

        let mut req = IcmpExtendedEchoRequest::new(&mut data[..]).unwrap();
        req.identifier_mut().set(0xabcd);
        req.sequence_mut().set(42);
        req.set_local_bit(true);

        assert_eq!(req.identifier().get(), 0xabcd);
        assert_eq!(req.sequence().get(), 42);
        assert!(req.local_bit());
    }

    #[test]
    fn test_extended_echo_reply_active() {
        let data = vec![
            0x2b, 0x00, // type=43, code=0
            0x00, 0x00, // checksum
            0x12, 0x34, // identifier
            0x00, 0x01, // sequence
            0x41, // state=2 (active), A-bit=1
            0x00, 0x00, 0x00, // reserved
        ];

        let reply = IcmpExtendedEchoReply::new(&data[..]).unwrap();
        assert_eq!(reply.identifier().get(), 0x1234);
        assert_eq!(reply.sequence().get(), 1);
        assert_eq!(reply.state(), 2);
        assert!(reply.is_active());
        assert!(!reply.is_inactive());
        assert!(reply.authoritative_bit());
    }

    #[test]
    fn test_extended_echo_reply_inactive() {
        let data = vec![
            0x2b, 0x00, // type=43, code=0
            0x00, 0x00, // checksum
            0x12, 0x34, // identifier
            0x00, 0x01, // sequence
            0x60, // state=3 (inactive), A-bit=0
            0x00, 0x00, 0x00, // reserved
        ];

        let reply = IcmpExtendedEchoReply::new(&data[..]).unwrap();
        assert_eq!(reply.state(), 3);
        assert!(!reply.is_active());
        assert!(reply.is_inactive());
        assert!(!reply.authoritative_bit());
    }

    #[test]
    fn test_extended_echo_reply_mutation() {
        let mut data = vec![
            0x2b, 0x00, // type=43, code=0
            0x00, 0x00, // checksum
            0x00, 0x00, // identifier
            0x00, 0x00, // sequence
            0x00, // state=0, A-bit=0
            0x00, 0x00, 0x00, // reserved
        ];

        let mut reply = IcmpExtendedEchoReply::new(&mut data[..]).unwrap();
        reply.identifier_mut().set(0x5678);
        reply.sequence_mut().set(99);
        reply.set_state(2); // active
        reply.set_authoritative_bit(true);

        assert_eq!(reply.identifier().get(), 0x5678);
        assert_eq!(reply.sequence().get(), 99);
        assert_eq!(reply.state(), 2);
        assert!(reply.is_active());
        assert!(reply.authoritative_bit());
    }
}
