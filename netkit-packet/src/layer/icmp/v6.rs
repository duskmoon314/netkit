//! ICMPv6 layer implementation.
//!
//! ## Implementation Status
//!
//! ### Error Messages (0-127)
//!
//! - [x] **Type 1**: Destination Unreachable - [`Icmpv6DestUnreach`] - [RFC 4443](https://www.rfc-editor.org/rfc/rfc4443.html)
//! - [x] **Type 2**: Packet Too Big - [`Icmpv6PacketTooBig`] - [RFC 4443](https://www.rfc-editor.org/rfc/rfc4443.html)
//! - [x] **Type 3**: Time Exceeded - [`Icmpv6TimeExceeded`] - [RFC 4443](https://www.rfc-editor.org/rfc/rfc4443.html)
//! - [x] **Type 4**: Parameter Problem - [`Icmpv6ParamProblem`] - [RFC 4443](https://www.rfc-editor.org/rfc/rfc4443.html)
//!
//! ### Informational Messages (128-255)
//!
//! - [x] **Type 128**: Echo Request - [`Icmpv6Echo`] - [RFC 4443](https://www.rfc-editor.org/rfc/rfc4443.html)
//! - [x] **Type 129**: Echo Reply - [`Icmpv6Echo`] - [RFC 4443](https://www.rfc-editor.org/rfc/rfc4443.html)
//!
//! ### Multicast Listener Discovery (MLDv1)
//!
//! - [x] **Type 130**: Multicast Listener Query - [`MulticastListenerQuery`] - [RFC 2710](https://www.rfc-editor.org/rfc/rfc2710.html)
//! - [x] **Type 131**: Multicast Listener Report (MLDv1) - [`MulticastListenerReport`] - [RFC 2710](https://www.rfc-editor.org/rfc/rfc2710.html)
//! - [x] **Type 132**: Multicast Listener Done - [`MulticastListenerDone`] - [RFC 2710](https://www.rfc-editor.org/rfc/rfc2710.html)
//!
//! ### Neighbor Discovery Protocol (NDP)
//!
//! - [x] **Type 133**: Router Solicitation - [`RouterSolicitation`] - [RFC 4861](https://www.rfc-editor.org/rfc/rfc4861.html)
//! - [x] **Type 134**: Router Advertisement - [`RouterAdvertisement`] - [RFC 4861](https://www.rfc-editor.org/rfc/rfc4861.html)
//! - [x] **Type 135**: Neighbor Solicitation - [`NeighborSolicitation`] - [RFC 4861](https://www.rfc-editor.org/rfc/rfc4861.html)
//! - [x] **Type 136**: Neighbor Advertisement - [`NeighborAdvertisement`] - [RFC 4861](https://www.rfc-editor.org/rfc/rfc4861.html)
//! - [x] **Type 137**: Redirect - [`Redirect`] - [RFC 4861](https://www.rfc-editor.org/rfc/rfc4861.html)
//!
//! ### Not Implemented
//!
//! - [ ] **Type 138**: Router Renumbering - [RFC 2894](https://www.rfc-editor.org/rfc/rfc2894.html)
//! - [ ] **Type 139**: Node Information Query - [RFC 4620](https://www.rfc-editor.org/rfc/rfc4620.html) (experimental)
//! - [ ] **Type 140**: Node Information Response - [RFC 4620](https://www.rfc-editor.org/rfc/rfc4620.html) (experimental)
//! - [ ] **Type 143**: Multicast Listener Report v2 (MLDv2) - [RFC 9777](https://www.rfc-editor.org/rfc/rfc9777.html)
//! - [ ] **Type 144**: Home Agent Address Discovery Request - [RFC 6275](https://www.rfc-editor.org/rfc/rfc6275.html) (Mobile IPv6)
//! - [ ] **Type 145**: Home Agent Address Discovery Reply - [RFC 6275](https://www.rfc-editor.org/rfc/rfc6275.html) (Mobile IPv6)
//! - [ ] **Type 146**: Mobile Prefix Solicitation - [RFC 6275](https://www.rfc-editor.org/rfc/rfc6275.html) (Mobile IPv6)
//! - [ ] **Type 147**: Mobile Prefix Advertisement - [RFC 6275](https://www.rfc-editor.org/rfc/rfc6275.html) (Mobile IPv6)
//! - [ ] **Type 148**: Certification Path Solicitation - [RFC 3971](https://www.rfc-editor.org/rfc/rfc3971.html) (SEND)
//! - [ ] **Type 149**: Certification Path Advertisement - [RFC 3971](https://www.rfc-editor.org/rfc/rfc3971.html) (SEND)
//! - [ ] **Type 151**: Multicast Router Advertisement - [RFC 4286](https://www.rfc-editor.org/rfc/rfc4286.html) (MRD)
//! - [ ] **Type 152**: Multicast Router Solicitation - [RFC 4286](https://www.rfc-editor.org/rfc/rfc4286.html) (MRD)
//! - [ ] **Type 153**: Multicast Router Termination - [RFC 4286](https://www.rfc-editor.org/rfc/rfc4286.html) (MRD)
//! - [ ] **Type 155**: RPL Control Message - [RFC 6550](https://www.rfc-editor.org/rfc/rfc6550.html) (IoT/6LoWPAN)
//! - [ ] **Type 160**: Extended Echo Request - [RFC 8335](https://www.rfc-editor.org/rfc/rfc8335.html)
//! - [ ] **Type 161**: Extended Echo Reply - [RFC 8335](https://www.rfc-editor.org/rfc/rfc8335.html)
//!
//! ## References
//!
//! - [IANA ICMPv6 Parameters](https://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xhtml)
//! - [RFC 4443 - Internet Control Message Protocol (ICMPv6)](https://www.rfc-editor.org/rfc/rfc4443.html)
//! - [RFC 4861 - Neighbor Discovery for IP version 6 (IPv6)](https://www.rfc-editor.org/rfc/rfc4861.html)
//! - [RFC 2710 - Multicast Listener Discovery (MLD) for IPv6](https://www.rfc-editor.org/rfc/rfc2710.html)

// Message type definitions
pub mod msg_type;
pub use msg_type::Icmpv6Type;

// Error messages
pub mod dest_unreach;
pub mod packet_too_big;
pub mod param_problem;
pub mod time_exceeded;

pub use dest_unreach::Icmpv6DestUnreach;
pub use packet_too_big::Icmpv6PacketTooBig;
pub use param_problem::Icmpv6ParamProblem;
pub use time_exceeded::Icmpv6TimeExceeded;

// Informational messages
pub mod echo;
pub use echo::Icmpv6Echo;

// Multicast Listener Discovery (MLD)
pub mod mld;
pub use mld::{MulticastListenerDone, MulticastListenerQuery, MulticastListenerReport};

// Neighbor Discovery Protocol (NDP)
pub mod ndp;
pub use ndp::{
    NeighborAdvertisement, NeighborSolicitation, Redirect, RouterAdvertisement, RouterSolicitation,
};

use crate::{field_spec, prelude::*};

field_spec!(Icmpv6TypeSpec, Icmpv6Type, u8);
field_spec!(Icmpv6CodeSpec, u8, u8);
field_spec!(Icmpv6ChecksumSpec, u16, u16);

/// Error type for ICMPv6.
#[derive(Debug, thiserror::Error, Clone, PartialEq)]
pub enum Icmpv6Error {
    /// Invalid ICMPv6 length.
    #[error("Invalid ICMPv6 length: Length {0} is less than minimum 8")]
    InvalidLength(usize),

    /// Invalid ICMPv6 checksum.
    #[error("Invalid ICMPv6 checksum: Expected {expected:#06x}, got {actual:#06x}")]
    InvalidChecksum {
        /// Expected checksum value.
        expected: u16,
        /// Actual checksum value found in the packet.
        actual: u16,
    },
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

    /// Parse as Echo Request or Echo Reply message.
    ///
    /// Returns `Some` if this is an Echo Request (type 128) or Echo Reply (type 129).
    #[inline]
    pub fn echo(&self) -> Option<Icmpv6Echo<&[u8]>> {
        match self.msg_type().get() {
            Icmpv6Type::EchoRequest | Icmpv6Type::EchoReply => Icmpv6Echo::new(self.data.as_ref()),
            _ => None,
        }
    }

    /// Parse as Destination Unreachable message.
    ///
    /// Returns `Some` if this is a Destination Unreachable message (type 1).
    #[inline]
    pub fn dest_unreach(&self) -> Option<Icmpv6DestUnreach<&[u8]>> {
        match self.msg_type().get() {
            Icmpv6Type::DestinationUnreachable => Icmpv6DestUnreach::new(self.data.as_ref()),
            _ => None,
        }
    }

    /// Parse as Packet Too Big message.
    ///
    /// Returns `Some` if this is a Packet Too Big message (type 2).
    #[inline]
    pub fn packet_too_big(&self) -> Option<Icmpv6PacketTooBig<&[u8]>> {
        match self.msg_type().get() {
            Icmpv6Type::PacketTooBig => Icmpv6PacketTooBig::new(self.data.as_ref()),
            _ => None,
        }
    }

    /// Parse as Time Exceeded message.
    ///
    /// Returns `Some` if this is a Time Exceeded message (type 3).
    #[inline]
    pub fn time_exceeded(&self) -> Option<Icmpv6TimeExceeded<&[u8]>> {
        match self.msg_type().get() {
            Icmpv6Type::TimeExceeded => Icmpv6TimeExceeded::new(self.data.as_ref()),
            _ => None,
        }
    }

    /// Parse as Parameter Problem message.
    ///
    /// Returns `Some` if this is a Parameter Problem message (type 4).
    #[inline]
    pub fn param_problem(&self) -> Option<Icmpv6ParamProblem<&[u8]>> {
        match self.msg_type().get() {
            Icmpv6Type::ParameterProblem => Icmpv6ParamProblem::new(self.data.as_ref()),
            _ => None,
        }
    }

    /// Parse as Router Solicitation message (NDP).
    ///
    /// Returns `Some` if this is a Router Solicitation message (type 133).
    #[inline]
    pub fn router_solicitation(&self) -> Option<RouterSolicitation<&[u8]>> {
        match self.msg_type().get() {
            Icmpv6Type::RouterSolicitation => RouterSolicitation::new(self.data.as_ref()),
            _ => None,
        }
    }

    /// Parse as Router Advertisement message (NDP).
    ///
    /// Returns `Some` if this is a Router Advertisement message (type 134).
    #[inline]
    pub fn router_advertisement(&self) -> Option<RouterAdvertisement<&[u8]>> {
        match self.msg_type().get() {
            Icmpv6Type::RouterAdvertisement => RouterAdvertisement::new(self.data.as_ref()),
            _ => None,
        }
    }

    /// Parse as Neighbor Solicitation message (NDP).
    ///
    /// Returns `Some` if this is a Neighbor Solicitation message (type 135).
    #[inline]
    pub fn neighbor_solicitation(&self) -> Option<NeighborSolicitation<&[u8]>> {
        match self.msg_type().get() {
            Icmpv6Type::NeighborSolicitation => NeighborSolicitation::new(self.data.as_ref()),
            _ => None,
        }
    }

    /// Parse as Neighbor Advertisement message (NDP).
    ///
    /// Returns `Some` if this is a Neighbor Advertisement message (type 136).
    #[inline]
    pub fn neighbor_advertisement(&self) -> Option<NeighborAdvertisement<&[u8]>> {
        match self.msg_type().get() {
            Icmpv6Type::NeighborAdvertisement => NeighborAdvertisement::new(self.data.as_ref()),
            _ => None,
        }
    }

    /// Parse as Redirect message (NDP).
    ///
    /// Returns `Some` if this is a Redirect message (type 137).
    #[inline]
    pub fn redirect(&self) -> Option<Redirect<&[u8]>> {
        match self.msg_type().get() {
            Icmpv6Type::Redirect => Redirect::new(self.data.as_ref()),
            _ => None,
        }
    }

    /// Parse as Multicast Listener Query message (MLD).
    ///
    /// Returns `Some` if this is a Multicast Listener Query message (type 130).
    #[inline]
    pub fn mld_query(&self) -> Option<MulticastListenerQuery<&[u8]>> {
        match self.msg_type().get() {
            Icmpv6Type::MulticastListenerQuery => MulticastListenerQuery::new(self.data.as_ref()),
            _ => None,
        }
    }

    /// Parse as Multicast Listener Report message (MLD).
    ///
    /// Returns `Some` if this is a Multicast Listener Report message (type 131).
    #[inline]
    pub fn mld_report(&self) -> Option<MulticastListenerReport<&[u8]>> {
        match self.msg_type().get() {
            Icmpv6Type::MulticastListenerReport => MulticastListenerReport::new(self.data.as_ref()),
            _ => None,
        }
    }

    /// Parse as Multicast Listener Done message (MLD).
    ///
    /// Returns `Some` if this is a Multicast Listener Done message (type 132).
    #[inline]
    pub fn mld_done(&self) -> Option<MulticastListenerDone<&[u8]>> {
        match self.msg_type().get() {
            Icmpv6Type::MulticastListenerDone => MulticastListenerDone::new(self.data.as_ref()),
            _ => None,
        }
    }

    /// Calculate the ICMPv6 checksum.
    ///
    /// The checksum is calculated over the IPv6 pseudo-header and ICMPv6 message.
    /// Unlike ICMPv4, ICMPv6 checksum is mandatory and always includes the IPv6 pseudo-header.
    ///
    /// ## Parameters
    /// - `src`: Source IPv6 address
    /// - `dst`: Destination IPv6 address
    ///
    /// ## Example
    /// ```ignore
    /// use netkit_packet::layer::icmp::v6::Icmpv6;
    /// use core::net::Ipv6Addr;
    ///
    /// let icmpv6_data = [/* ICMPv6 packet data */];
    /// let icmpv6 = Icmpv6::new(&icmpv6_data[..]).unwrap();
    /// let src = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
    /// let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
    /// let checksum = icmpv6.calculate_checksum(src, dst);
    /// ```
    pub fn calculate_checksum(&self, src: core::net::Ipv6Addr, dst: core::net::Ipv6Addr) -> u16 {
        use crate::utils::checksum::{calculate_with_pseudo, ipv6_pseudo_header};

        let icmpv6_length = self.data.as_ref().len() as u32;
        let pseudo = ipv6_pseudo_header(src, dst, 58, icmpv6_length); // 58 = ICMPv6

        // Create a copy of the ICMPv6 data with checksum field set to 0
        let mut icmpv6_data = self.data.as_ref().to_vec();
        icmpv6_data[Self::FIELD_CHECKSUM].copy_from_slice(&[0, 0]);

        calculate_with_pseudo(&pseudo, &icmpv6_data)
    }

    /// Validate the ICMPv6 checksum.
    ///
    /// Returns `Ok(())` if the checksum is valid.
    /// Returns `Err(Icmpv6Error::InvalidChecksum)` if the checksum is invalid.
    ///
    /// ## Parameters
    /// - `src`: Source IPv6 address
    /// - `dst`: Destination IPv6 address
    pub fn validate_checksum(
        &self,
        src: core::net::Ipv6Addr,
        dst: core::net::Ipv6Addr,
    ) -> Result<(), Icmpv6Error> {
        let expected = self.calculate_checksum(src, dst);
        let actual = self.checksum().get();

        if expected != actual {
            return Err(Icmpv6Error::InvalidChecksum { expected, actual });
        }

        Ok(())
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
