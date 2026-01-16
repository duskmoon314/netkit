//! ICMPv6 Parameter Problem message.

use crate::{field_spec, prelude::*};

field_spec!(PointerSpec, u32, u32);

/// ICMPv6 Parameter Problem message (Type 4).
///
/// ```text
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Type      |     Code      |          Checksum             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                            Pointer                            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                    As much of invoking packet                 |
/// +                as possible without the ICMPv6 packet          +
/// |                exceeding the minimum IPv6 MTU (1280 bytes)    |
/// ```
///
/// **Code values**:
/// - 0: Erroneous header field encountered
/// - 1: Unrecognized Next Header type encountered
/// - 2: Unrecognized IPv6 option encountered
///
/// **Pointer**: Identifies the octet offset within the invoking packet where the error was detected.
pub struct Icmpv6ParamProblem<T>
where
    T: AsRef<[u8]>,
{
    data: T,
}

impl<T> Icmpv6ParamProblem<T>
where
    T: AsRef<[u8]>,
{
    /// Minimum message length.
    pub const MIN_LENGTH: usize = 8;

    /// Field range for pointer.
    pub const FIELD_POINTER: core::ops::Range<usize> = 4..8;
    /// Field range for invoking packet.
    pub const FIELD_INVOKING_PACKET: core::ops::RangeFrom<usize> = 8..;

    /// Create from ICMPv6 packet data.
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

    /// Get the pointer field (byte offset of the error).
    #[inline]
    pub fn pointer(&self) -> FieldRef<'_, PointerSpec> {
        FieldRef::new(&self.as_ref()[Self::FIELD_POINTER])
    }

    /// Get the invoking packet (as much of the original packet as possible).
    #[inline]
    pub fn invoking_packet(&self) -> &[u8] {
        &self.as_ref()[Self::FIELD_INVOKING_PACKET]
    }

    /// Try to parse the original IPv6 header from the invoking packet.
    #[inline]
    pub fn original_ipv6(&self) -> Option<Ipv6<&[u8]>> {
        Ipv6::new(self.invoking_packet()).ok()
    }
}

impl<T> Icmpv6ParamProblem<T>
where
    T: AsRef<[u8]> + AsMut<[u8]>,
{
    /// Get mutable access to the pointer field.
    #[inline]
    pub fn pointer_mut(&mut self) -> FieldMut<'_, PointerSpec> {
        FieldMut::new(&mut self.as_mut()[Self::FIELD_POINTER])
    }

    /// Get mutable access to invoking packet area.
    #[inline]
    pub fn invoking_packet_mut(&mut self) -> &mut [u8] {
        &mut self.as_mut()[Self::FIELD_INVOKING_PACKET]
    }
}

impl<T: AsRef<[u8]>> AsRef<[u8]> for Icmpv6ParamProblem<T> {
    fn as_ref(&self) -> &[u8] {
        self.data.as_ref()
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> AsMut<[u8]> for Icmpv6ParamProblem<T> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.data.as_mut()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_param_problem_parse() {
        let data = vec![
            0x04, 0x00, // type=4, code=0 (erroneous header field)
            0x00, 0x00, // checksum
            0x00, 0x00, 0x00, 0x06, // pointer = 6
            // Original IPv6 header would follow...
            0x60, 0x00, 0x00, 0x00, // IPv6 header start
        ];

        let msg = Icmpv6ParamProblem::new(&data[..]).unwrap();
        assert_eq!(msg.pointer().get(), 6);
        assert!(msg.invoking_packet().len() >= 4);
    }

    #[test]
    fn test_param_problem_mutation() {
        let mut data = vec![
            0x04, 0x01, // type=4, code=1 (unrecognized next header)
            0x00, 0x00, // checksum
            0x00, 0x00, 0x00, 0x00, // pointer
            0x60, 0x00, 0x00, 0x00, // IPv6 header start
        ];

        let mut msg = Icmpv6ParamProblem::new(&mut data[..]).unwrap();
        msg.pointer_mut().set(40); // Pointer to next header field

        assert_eq!(msg.pointer().get(), 40);
    }
}
