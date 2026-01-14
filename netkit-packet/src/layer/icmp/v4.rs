//! ICMPv4 layer implementation.

pub mod msg_type;
pub use msg_type::*;

pub mod echo;
pub use echo::IcmpEcho;

pub mod dest_unreach;
pub use dest_unreach::IcmpDestUnreach;

pub mod time_exceeded;
pub use time_exceeded::IcmpTimeExceeded;

pub mod redirect;
pub use redirect::IcmpRedirect;

pub mod param_problem;
pub use param_problem::IcmpParamProblem;

use crate::{field_spec, prelude::*};

field_spec!(Icmpv4TypeSpec, Icmpv4Type, u8);
field_spec!(Icmpv4CodeSpec, u8, u8);
field_spec!(Icmpv4ChecksumSpec, u16, u16);

/// Error type for ICMPv4.
#[derive(Debug, thiserror::Error, Clone, PartialEq)]
pub enum Icmpv4Error {
    /// Invalid ICMPv4 length.
    #[error("Invalid ICMPv4 length: Length {0} is less than minimum 8")]
    InvalidLength(usize),

    /// Invalid checksum.
    #[error("Invalid checksum: Expected {expected:#06x}, got {actual:#06x}")]
    InvalidChecksum {
        /// Expected checksum value.
        expected: u16,
        /// Actual checksum value found in the packet.
        actual: u16,
    },
}

/// Minimum ICMPv4 header length.
pub const MIN_HEADER_LENGTH: usize = 8;

/// ICMPv4 (Internet Control Message Protocol version 4) Packet
///
/// ## Packet Format (RFC 792)
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
/// - **Type**: 8 bits - ICMP message type
///   - 0 = Echo Reply, 3 = Destination Unreachable, 8 = Echo Request,
///   - 11 = Time Exceeded, 12 = Parameter Problem, 5 = Redirect, etc.
/// - **Code**: 8 bits - Subtype code (meaning depends on Type)
/// - **Checksum**: 16 bits - One's complement checksum of ICMP message
/// - **Message Body**: Variable - Content depends on Type and Code
///
/// This is the base ICMP packet. Use the accessor methods to get
/// message-specific views like [`IcmpEcho`], [`IcmpDestUnreach`], etc.
pub struct Icmpv4<T>
where
    T: AsRef<[u8]>,
{
    data: T,
}

impl<T> Icmpv4<T>
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

    /// Create a new ICMPv4 packet without validation.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the data is a valid ICMPv4 packet.
    #[inline]
    pub const unsafe fn new_unchecked(data: T) -> Self {
        Self { data }
    }

    /// Validate the ICMPv4 packet.
    pub fn validate(&self) -> Result<(), Icmpv4Error> {
        if self.data.as_ref().len() < MIN_HEADER_LENGTH {
            return Err(Icmpv4Error::InvalidLength(self.data.as_ref().len()));
        }
        Ok(())
    }

    /// Create a new ICMPv4 packet from raw data.
    #[inline]
    pub fn new(data: T) -> Result<Self, Icmpv4Error> {
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
    pub fn msg_type(&self) -> FieldRef<'_, Icmpv4TypeSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_TYPE])
    }

    /// Get the code.
    #[inline]
    pub fn code(&self) -> FieldRef<'_, Icmpv4CodeSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_CODE])
    }

    /// Get the checksum.
    #[inline]
    pub fn checksum(&self) -> FieldRef<'_, Icmpv4ChecksumSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_CHECKSUM])
    }

    /// Get the message body (everything after the checksum).
    #[inline]
    pub fn message_body(&self) -> &[u8] {
        &self.data.as_ref()[Self::FIELD_MESSAGE_BODY]
    }

    /// Parse as Echo Request/Reply message.
    ///
    /// Returns `Some` if this is an Echo Request or Echo Reply.
    #[inline]
    pub fn echo(&self) -> Option<IcmpEcho<&[u8]>> {
        match self.msg_type().get() {
            Icmpv4Type::EchoRequest | Icmpv4Type::EchoReply => IcmpEcho::new(self.data.as_ref()),
            _ => None,
        }
    }

    /// Parse as Destination Unreachable message.
    ///
    /// Returns `Some` if this is a Destination Unreachable message.
    #[inline]
    pub fn dest_unreachable(&self) -> Option<IcmpDestUnreach<&[u8]>> {
        match self.msg_type().get() {
            Icmpv4Type::DestinationUnreachable => IcmpDestUnreach::new(self.data.as_ref()),
            _ => None,
        }
    }

    /// Parse as Time Exceeded message.
    ///
    /// Returns `Some` if this is a Time Exceeded message.
    #[inline]
    pub fn time_exceeded(&self) -> Option<IcmpTimeExceeded<&[u8]>> {
        match self.msg_type().get() {
            Icmpv4Type::TimeExceeded => IcmpTimeExceeded::new(self.data.as_ref()),
            _ => None,
        }
    }

    /// Parse as Redirect message.
    ///
    /// Returns `Some` if this is a Redirect message.
    #[inline]
    pub fn redirect(&self) -> Option<IcmpRedirect<&[u8]>> {
        match self.msg_type().get() {
            Icmpv4Type::Redirect => IcmpRedirect::new(self.data.as_ref()),
            _ => None,
        }
    }

    /// Parse as Parameter Problem message.
    ///
    /// Returns `Some` if this is a Parameter Problem message.
    #[inline]
    pub fn param_problem(&self) -> Option<IcmpParamProblem<&[u8]>> {
        match self.msg_type().get() {
            Icmpv4Type::ParameterProblem => IcmpParamProblem::new(self.data.as_ref()),
            _ => None,
        }
    }

    /// Calculate the checksum.
    ///
    /// This calculates what the checksum field should be based on the current
    /// packet contents (with the checksum field treated as zero).
    pub fn calculate_checksum(&self) -> u16 {
        let data = self.data.as_ref();
        let mut sum: u32 = 0;

        // Sum all 16-bit words, treating checksum field as 0
        for (i, chunk) in data.chunks(2).enumerate() {
            if i == 1 {
                // Skip the checksum field (bytes 2-3)
                continue;
            }

            let word = if chunk.len() == 2 {
                u16::from_be_bytes([chunk[0], chunk[1]])
            } else {
                // Odd length - pad with zero
                u16::from_be_bytes([chunk[0], 0])
            };

            sum += word as u32;
        }

        // Fold 32-bit sum to 16 bits
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        // One's complement
        !sum as u16
    }

    /// Validate the checksum.
    pub fn validate_checksum(&self) -> Result<(), Icmpv4Error> {
        let expected = self.calculate_checksum();
        let actual = self.checksum().get();

        if expected != actual {
            return Err(Icmpv4Error::InvalidChecksum { expected, actual });
        }

        Ok(())
    }
}

impl<T> Icmpv4<T>
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
    pub fn msg_type_mut(&mut self) -> FieldMut<'_, Icmpv4TypeSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_TYPE])
    }

    /// Get mutable code.
    #[inline]
    pub fn code_mut(&mut self) -> FieldMut<'_, Icmpv4CodeSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_CODE])
    }

    /// Get mutable checksum.
    #[inline]
    pub fn checksum_mut(&mut self) -> FieldMut<'_, Icmpv4ChecksumSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_CHECKSUM])
    }

    /// Get mutable message body.
    #[inline]
    pub fn message_body_mut(&mut self) -> &mut [u8] {
        &mut self.data.as_mut()[Self::FIELD_MESSAGE_BODY]
    }

    /// Parse as mutable Echo message.
    #[inline]
    pub fn echo_mut(&mut self) -> Option<IcmpEcho<&mut [u8]>> {
        match self.msg_type().get() {
            Icmpv4Type::EchoRequest | Icmpv4Type::EchoReply => IcmpEcho::new(self.data.as_mut()),
            _ => None,
        }
    }

    /// Parse as mutable Destination Unreachable message.
    #[inline]
    pub fn dest_unreachable_mut(&mut self) -> Option<IcmpDestUnreach<&mut [u8]>> {
        match self.msg_type().get() {
            Icmpv4Type::DestinationUnreachable => IcmpDestUnreach::new(self.data.as_mut()),
            _ => None,
        }
    }

    /// Parse as mutable Time Exceeded message.
    #[inline]
    pub fn time_exceeded_mut(&mut self) -> Option<IcmpTimeExceeded<&mut [u8]>> {
        match self.msg_type().get() {
            Icmpv4Type::TimeExceeded => IcmpTimeExceeded::new(self.data.as_mut()),
            _ => None,
        }
    }

    /// Parse as mutable Redirect message.
    #[inline]
    pub fn redirect_mut(&mut self) -> Option<IcmpRedirect<&mut [u8]>> {
        match self.msg_type().get() {
            Icmpv4Type::Redirect => IcmpRedirect::new(self.data.as_mut()),
            _ => None,
        }
    }

    /// Parse as mutable Parameter Problem message.
    #[inline]
    pub fn param_problem_mut(&mut self) -> Option<IcmpParamProblem<&mut [u8]>> {
        match self.msg_type().get() {
            Icmpv4Type::ParameterProblem => IcmpParamProblem::new(self.data.as_mut()),
            _ => None,
        }
    }
}

layer_impl!(Icmpv4);

/// Builder for ICMPv4 Echo Request/Reply.
#[derive(Clone, Debug)]
pub struct Icmpv4EchoBuilder {
    msg_type: Icmpv4Type,
    code: u8,
    identifier: u16,
    sequence: u16,
    data: Vec<u8>,
}

impl Icmpv4EchoBuilder {
    /// Create a new Echo Request builder.
    pub fn request() -> Self {
        Self {
            msg_type: Icmpv4Type::EchoRequest,
            code: 0,
            identifier: 0,
            sequence: 0,
            data: Vec::new(),
        }
    }

    /// Create a new Echo Reply builder.
    pub fn reply() -> Self {
        Self {
            msg_type: Icmpv4Type::EchoReply,
            code: 0,
            identifier: 0,
            sequence: 0,
            data: Vec::new(),
        }
    }

    /// Set the identifier.
    pub fn identifier(mut self, id: u16) -> Self {
        self.identifier = id;
        self
    }

    /// Set the sequence number.
    pub fn sequence(mut self, seq: u16) -> Self {
        self.sequence = seq;
        self
    }

    /// Set the data payload.
    pub fn data(mut self, data: impl AsRef<[u8]>) -> Self {
        self.data.extend_from_slice(data.as_ref());
        self
    }

    /// Build the ICMP packet.
    pub fn build(self) -> Icmpv4<Vec<u8>> {
        let total_len = MIN_HEADER_LENGTH + self.data.len();
        let mut icmp = unsafe { Icmpv4::new_unchecked(vec![0; total_len]) };

        icmp.msg_type_mut().set(self.msg_type);
        icmp.code_mut().set(self.code);

        // Set echo-specific fields
        if let Some(mut echo) = icmp.echo_mut() {
            echo.identifier_mut().set(self.identifier);
            echo.sequence_mut().set(self.sequence);
            echo.data_mut().copy_from_slice(&self.data);
        }

        // Calculate and set checksum
        let checksum = icmp.calculate_checksum();
        icmp.checksum_mut().set(checksum);

        icmp
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_echo_request() {
        let icmp = Icmpv4EchoBuilder::request()
            .identifier(1234)
            .sequence(5)
            .data(vec![0xAA, 0xBB, 0xCC])
            .build();

        assert_eq!(icmp.msg_type().get(), Icmpv4Type::EchoRequest);
        assert!(icmp.validate_checksum().is_ok());

        let echo = icmp.echo().unwrap();
        assert_eq!(echo.identifier().get(), 1234);
        assert_eq!(echo.sequence().get(), 5);
        assert_eq!(echo.data(), &[0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn test_dest_unreachable_access() {
        let mut data = vec![0u8; 36];
        data[0] = 3; // Destination Unreachable
        data[1] = 4; // Fragmentation Needed
        data[6] = 0x05; // MTU high byte
        data[7] = 0xDC; // MTU low byte (1500)

        let icmp = Icmpv4::new(&data[..]).unwrap();
        assert_eq!(icmp.msg_type().get(), Icmpv4Type::DestinationUnreachable);

        let dest_unreach = icmp.dest_unreachable().unwrap();
        assert_eq!(dest_unreach.next_hop_mtu().get(), 1500);
    }
}
