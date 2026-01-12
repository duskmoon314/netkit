//! Parameter Problem message parsing.

use crate::{field_spec, prelude::*};

field_spec!(ParamProblemPointerSpec, u8, u8);

/// ICMP Parameter Problem message.
///
/// This message is sent when a router or host encounters a problem with
/// the IP header of a received datagram. The pointer field indicates the
/// byte offset within the original datagram where the error was detected.
pub struct IcmpParamProblem<T>
where
    T: AsRef<[u8]>,
{
    data: T,
}

impl<T> IcmpParamProblem<T>
where
    T: AsRef<[u8]>,
{
    /// Field range of pointer: 4..5
    pub const FIELD_POINTER: core::ops::Range<usize> = 4..5;
    /// Field range of unused: 5..8
    pub const FIELD_UNUSED: core::ops::Range<usize> = 5..8;
    /// Field range of original datagram: 8..
    pub const FIELD_ORIGINAL_DATAGRAM: core::ops::RangeFrom<usize> = 8..;

    /// Minimum length for Parameter Problem message.
    pub const MIN_LENGTH: usize = 8;

    /// Create a new Parameter Problem message.
    ///
    /// Returns `None` if the data is too short.
    pub fn new(data: T) -> Option<Self> {
        if data.as_ref().len() < Self::MIN_LENGTH {
            return None;
        }
        Some(Self { data })
    }

    /// Get the pointer to the byte offset where the error was detected.
    ///
    /// This points to the octet in the original datagram where the error
    /// was detected. For example, if the error is in the IP header's
    /// protocol field (byte 9), the pointer will be 9.
    #[inline]
    pub fn pointer(&self) -> FieldRef<'_, ParamProblemPointerSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_POINTER])
    }

    /// Get the original datagram (IP header + first 8 bytes of data).
    ///
    /// This contains the IP header and the first 8 bytes of the original
    /// datagram's data.
    #[inline]
    pub fn original_datagram(&self) -> &[u8] {
        &self.data.as_ref()[Self::FIELD_ORIGINAL_DATAGRAM]
    }

    /// Try to parse the original IPv4 header.
    #[inline]
    pub fn original_ipv4(&self) -> Option<Ipv4<&[u8]>> {
        Ipv4::new(self.original_datagram()).ok()
    }
}

impl<T> IcmpParamProblem<T>
where
    T: AsRef<[u8]> + AsMut<[u8]>,
{
    /// Get mutable pointer field.
    #[inline]
    pub fn pointer_mut(&mut self) -> FieldMut<'_, ParamProblemPointerSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_POINTER])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_param_problem_parse() {
        // Create a minimal Parameter Problem packet
        let mut data = vec![0u8; 36]; // 8 ICMP header + 28 bytes original datagram
        data[0] = 12; // Parameter Problem
        data[1] = 0; // Pointer indicates the error
        data[4] = 9; // Pointer to byte 9 (protocol field in IP header)

        // Add some dummy IPv4 header data
        data[8] = 0x45; // Version 4, IHL 5
        data[9] = 0x00; // TOS
        data[10] = 0x00;
        data[11] = 0x1C; // Total length 28
        data[17] = 99; // Invalid protocol number that caused the error

        let icmp = Icmpv4::new(&data[..]).unwrap();
        assert_eq!(icmp.msg_type().get(), Icmpv4Type::ParameterProblem);
        assert_eq!(icmp.code().get(), 0);

        // Access Parameter Problem specific fields
        let param_problem = icmp.param_problem().unwrap();
        assert_eq!(param_problem.pointer().get(), 9);

        // Verify we can parse the original IPv4 header
        let original_ipv4 = param_problem.original_ipv4().unwrap();
        assert_eq!(original_ipv4.version(), 4);
        assert_eq!(original_ipv4.ihl().get(), 5);
    }

    #[test]
    fn test_param_problem_mutable() {
        let mut data = vec![0u8; 36];
        data[0] = 12; // Parameter Problem
        data[4] = 5; // Initial pointer

        let mut icmp = Icmpv4::new(data).unwrap();

        if let Some(mut param_problem) = icmp.param_problem_mut() {
            param_problem.pointer_mut().set(9);
        }

        // Verify modification
        let param_problem = icmp.param_problem().unwrap();
        assert_eq!(param_problem.pointer().get(), 9);
    }
}
