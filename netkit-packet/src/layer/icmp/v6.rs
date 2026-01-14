//! ICMPv6 layer implementation.
//!
//! Note: This is a simplified implementation. Full ICMPv6 includes:
//! - Neighbor Discovery Protocol (NDP)
//! - Multicast Listener Discovery (MLD)
//! - Path MTU Discovery
//! - And more...

use crate::{field_spec, prelude::*};
use num_enum::{FromPrimitive, IntoPrimitive};
use strum::{AsRefStr, Display, EnumString};

/// ICMPv6 message types
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    IntoPrimitive,
    FromPrimitive,
    EnumString,
    Display,
    AsRefStr,
)]
#[repr(u8)]
#[non_exhaustive]
pub enum Icmpv6Type {
    /// Destination Unreachable
    DestinationUnreachable = 1,
    /// Packet Too Big
    PacketTooBig = 2,
    /// Time Exceeded
    TimeExceeded = 3,
    /// Parameter Problem
    ParameterProblem = 4,
    /// Echo Request
    EchoRequest = 128,
    /// Echo Reply
    EchoReply = 129,
    /// Router Solicitation (NDP)
    RouterSolicitation = 133,
    /// Router Advertisement (NDP)
    RouterAdvertisement = 134,
    /// Neighbor Solicitation (NDP)
    NeighborSolicitation = 135,
    /// Neighbor Advertisement (NDP)
    NeighborAdvertisement = 136,
    /// Redirect Message
    Redirect = 137,
    /// Reserved or unknown ICMPv6 type
    #[num_enum(catch_all)]
    Reserved(u8),
}

crate::impl_target!(frominto, Icmpv6Type, u8);

field_spec!(Icmpv6TypeSpec, Icmpv6Type, u8);
field_spec!(Icmpv6CodeSpec, u8, u8);
field_spec!(Icmpv6ChecksumSpec, u16, u16);

/// Error type for ICMPv6.
#[derive(Debug, thiserror::Error, Clone, PartialEq)]
pub enum Icmpv6Error {
    /// Invalid ICMPv6 length.
    #[error("Invalid ICMPv6 length: Length {0} is less than minimum 8")]
    InvalidLength(usize),
}

/// Minimum ICMPv6 header length.
pub const MIN_HEADER_LENGTH: usize = 8;

/// ICMPv6 (Internet Control Message Protocol version 6) Packet
///
/// ## Packet Format (RFC 4443)
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Type      |     Code      |          Checksum             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                      Message Body (variable)                  |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// - **Type**: 8 bits - ICMPv6 message type
///   - Error messages (0-127): Destination Unreachable (1), Packet Too Big (2), Time Exceeded (3), Parameter Problem (4)
///   - Informational messages (128-255): Echo Request (128), Echo Reply (129)
///   - NDP messages: Router Solicitation (133), Router Advertisement (134), Neighbor Solicitation (135), Neighbor Advertisement (136), Redirect (137)
/// - **Code**: 8 bits - Subtype code (meaning depends on Type)
/// - **Checksum**: 16 bits - One's complement checksum of ICMPv6 message + IPv6 pseudo-header
///   - Note: Unlike ICMPv4, the ICMPv6 checksum is mandatory and includes the IPv6 pseudo-header
/// - **Message Body**: Variable - Content depends on Type and Code
///
/// **Note**: This is currently a simplified implementation. Future enhancements will include
/// full support for Neighbor Discovery Protocol (NDP), Multicast Listener Discovery (MLD),
/// and Path MTU Discovery.
pub struct Icmpv6<T>
where
    T: AsRef<[u8]>,
{
    data: T,
}

impl<T> Icmpv6<T>
where
    T: AsRef<[u8]>,
{
    /// Field range of the type: 0..1
    pub const FIELD_TYPE: core::ops::Range<usize> = 0..1;
    /// Field range of the code: 1..2
    pub const FIELD_CODE: core::ops::Range<usize> = 1..2;
    /// Field range of the checksum: 2..4
    pub const FIELD_CHECKSUM: core::ops::Range<usize> = 2..4;
    /// Field range of the message body: 4..
    pub const FIELD_MESSAGE_BODY: core::ops::RangeFrom<usize> = 4..;

    /// Create a new ICMPv6 packet without validation.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the data is a valid ICMPv6 packet.
    #[inline]
    pub const unsafe fn new_unchecked(data: T) -> Self {
        Self { data }
    }

    /// Validate the ICMPv6 packet.
    pub fn validate(&self) -> Result<(), Icmpv6Error> {
        if self.data.as_ref().len() < MIN_HEADER_LENGTH {
            return Err(Icmpv6Error::InvalidLength(self.data.as_ref().len()));
        }
        Ok(())
    }

    /// Create a new ICMPv6 packet from raw data.
    #[inline]
    pub fn new(data: T) -> Result<Self, Icmpv6Error> {
        let res = unsafe { Self::new_unchecked(data) };
        res.validate()?;
        Ok(res)
    }

    /// Get the inner raw data.
    #[inline]
    pub const fn inner(&self) -> &T {
        &self.data
    }

    /// Get the message type.
    #[inline]
    pub fn msg_type(&self) -> FieldRef<'_, Icmpv6TypeSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_TYPE])
    }

    /// Get the code.
    #[inline]
    pub fn code(&self) -> FieldRef<'_, Icmpv6CodeSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_CODE])
    }

    /// Get the checksum.
    #[inline]
    pub fn checksum(&self) -> FieldRef<'_, Icmpv6ChecksumSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_CHECKSUM])
    }

    /// Get the message body.
    #[inline]
    pub fn message_body(&self) -> &[u8] {
        &self.data.as_ref()[Self::FIELD_MESSAGE_BODY]
    }
}

impl<T> Icmpv6<T>
where
    T: AsRef<[u8]> + AsMut<[u8]>,
{
    /// Get the mutable inner raw data.
    #[inline]
    pub fn inner_mut(&mut self) -> &mut T {
        &mut self.data
    }

    /// Get mutable message type.
    #[inline]
    pub fn msg_type_mut(&mut self) -> FieldMut<'_, Icmpv6TypeSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_TYPE])
    }

    /// Get mutable code.
    #[inline]
    pub fn code_mut(&mut self) -> FieldMut<'_, Icmpv6CodeSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_CODE])
    }

    /// Get mutable checksum.
    #[inline]
    pub fn checksum_mut(&mut self) -> FieldMut<'_, Icmpv6ChecksumSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_CHECKSUM])
    }

    /// Get mutable message body.
    #[inline]
    pub fn message_body_mut(&mut self) -> &mut [u8] {
        &mut self.data.as_mut()[Self::FIELD_MESSAGE_BODY]
    }
}

layer_impl!(Icmpv6);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_icmpv6_parse() {
        let data = [
            0x80, // Echo Request
            0x00, // Code 0
            0x00, 0x00, // Checksum
            0x12, 0x34, // Identifier
            0x00, 0x01, // Sequence
        ];

        let icmp = Icmpv6::new(&data[..]).unwrap();
        assert_eq!(icmp.msg_type().get(), Icmpv6Type::EchoRequest);
        assert_eq!(icmp.code().get(), 0);
    }
}
