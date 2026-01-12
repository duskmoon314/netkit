//! ICMP Destination Unreachable message.

use crate::{field_spec, prelude::*};

field_spec!(NextHopMtuSpec, u16, u16);

/// ICMP Destination Unreachable message.
///
/// ```text
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Type      |     Code      |          Checksum             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |             unused            |    Next-Hop MTU (for code 4)  |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |      Internet Header + 64 bits of Original Data Datagram      |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
pub struct IcmpDestUnreach<T>
where
    T: AsRef<[u8]>,
{
    data: T,
}

impl<T> IcmpDestUnreach<T>
where
    T: AsRef<[u8]>,
{
    /// Minimum message length.
    pub const MIN_LENGTH: usize = 8;

    /// Field range for unused/next-hop MTU.
    pub const FIELD_UNUSED: core::ops::Range<usize> = 4..6;
    /// Field range for next-hop MTU (only valid for code 4).
    pub const FIELD_NEXT_HOP_MTU: core::ops::Range<usize> = 6..8;
    /// Field range for original datagram.
    pub const FIELD_ORIGINAL_DATAGRAM: core::ops::RangeFrom<usize> = 8..;

    /// Create from ICMP packet data.
    ///
    /// # Safety
    ///
    /// Caller must ensure data is at least 8 bytes.
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

    /// Get the next-hop MTU (only valid for code 4 - Fragmentation Needed).
    #[inline]
    pub fn next_hop_mtu(&self) -> FieldRef<'_, NextHopMtuSpec> {
        FieldRef::new(&self.as_ref()[Self::FIELD_NEXT_HOP_MTU])
    }

    /// Get the original datagram (IP header + 64 bits of data).
    #[inline]
    pub fn original_datagram(&self) -> &[u8] {
        &self.as_ref()[Self::FIELD_ORIGINAL_DATAGRAM]
    }

    /// Try to parse the original IPv4 header.
    #[inline]
    pub fn original_ipv4(&self) -> Option<Ipv4<&[u8]>> {
        Ipv4::new(self.original_datagram()).ok()
    }
}

impl<T> IcmpDestUnreach<T>
where
    T: AsRef<[u8]> + AsMut<[u8]>,
{
    /// Set the next-hop MTU (for code 4).
    #[inline]
    pub fn next_hop_mtu_mut(&mut self) -> FieldMut<'_, NextHopMtuSpec> {
        FieldMut::new(&mut self.as_mut()[Self::FIELD_NEXT_HOP_MTU])
    }

    /// Get mutable access to original datagram area.
    #[inline]
    pub fn original_datagram_mut(&mut self) -> &mut [u8] {
        &mut self.as_mut()[Self::FIELD_ORIGINAL_DATAGRAM]
    }
}

impl<T: AsRef<[u8]>> AsRef<[u8]> for IcmpDestUnreach<T> {
    fn as_ref(&self) -> &[u8] {
        self.data.as_ref()
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> AsMut<[u8]> for IcmpDestUnreach<T> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.data.as_mut()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dest_unreach_fragmentation_needed() {
        let data = vec![
            0x03, 0x04, // type=3, code=4 (fragmentation needed)
            0x00, 0x00, // checksum
            0x00, 0x00, // unused
            0x05, 0xDC, // next-hop MTU = 1500
            // Original IP header would follow...
            0x45, 0x00, 0x00, 0x3c, // IPv4 header start
        ];

        let msg = IcmpDestUnreach::new(&data[..]).unwrap();
        assert_eq!(msg.next_hop_mtu().get(), 1500);
        assert!(msg.original_datagram().len() >= 4);
    }
}
