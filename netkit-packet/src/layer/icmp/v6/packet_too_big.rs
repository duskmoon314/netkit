//! ICMPv6 Packet Too Big message.

use crate::{field_spec, prelude::*};

field_spec!(MtuSpec, u32, u32);

/// ICMPv6 Packet Too Big message (Type 2).
///
/// This message is sent when a packet cannot be forwarded because it exceeds
/// the MTU of the outgoing link. This is unique to ICMPv6; IPv4 uses
/// Destination Unreachable (code 4) for this purpose.
///
/// ```text
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Type      |     Code      |          Checksum             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                             MTU                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                    As much of invoking packet                 |
/// +                as possible without the ICMPv6 packet          +
/// |                exceeding the minimum IPv6 MTU (1280 bytes)    |
/// ```
///
/// **Code**: Always 0
///
/// **MTU**: The Maximum Transmission Unit of the next-hop link
pub struct Icmpv6PacketTooBig<T>
where
    T: AsRef<[u8]>,
{
    data: T,
}

impl<T> Icmpv6PacketTooBig<T>
where
    T: AsRef<[u8]>,
{
    /// Minimum message length.
    pub const MIN_LENGTH: usize = 8;

    /// Field range for MTU.
    pub const FIELD_MTU: core::ops::Range<usize> = 4..8;
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

    /// Get the MTU of the next-hop link.
    #[inline]
    pub fn mtu(&self) -> FieldRef<'_, MtuSpec> {
        FieldRef::new(&self.as_ref()[Self::FIELD_MTU])
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

impl<T> Icmpv6PacketTooBig<T>
where
    T: AsRef<[u8]> + AsMut<[u8]>,
{
    /// Get mutable access to the MTU field.
    #[inline]
    pub fn mtu_mut(&mut self) -> FieldMut<'_, MtuSpec> {
        FieldMut::new(&mut self.as_mut()[Self::FIELD_MTU])
    }

    /// Get mutable access to invoking packet area.
    #[inline]
    pub fn invoking_packet_mut(&mut self) -> &mut [u8] {
        &mut self.as_mut()[Self::FIELD_INVOKING_PACKET]
    }
}

impl<T: AsRef<[u8]>> AsRef<[u8]> for Icmpv6PacketTooBig<T> {
    fn as_ref(&self) -> &[u8] {
        self.data.as_ref()
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> AsMut<[u8]> for Icmpv6PacketTooBig<T> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.data.as_mut()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_too_big_parse() {
        let data = vec![
            0x02, 0x00, // type=2, code=0
            0x00, 0x00, // checksum
            0x00, 0x00, 0x05, 0xDC, // MTU = 1500
            // Original IPv6 header would follow...
            0x60, 0x00, 0x00, 0x00, // IPv6 header start
        ];

        let msg = Icmpv6PacketTooBig::new(&data[..]).unwrap();
        assert_eq!(msg.mtu().get(), 1500);
        assert!(msg.invoking_packet().len() >= 4);
    }

    #[test]
    fn test_packet_too_big_mutation() {
        let mut data = vec![
            0x02, 0x00, // type=2, code=0
            0x00, 0x00, // checksum
            0x00, 0x00, 0x00, 0x00, // MTU
            0x60, 0x00, 0x00, 0x00, // IPv6 header start
        ];

        let mut msg = Icmpv6PacketTooBig::new(&mut data[..]).unwrap();
        msg.mtu_mut().set(1280); // Minimum IPv6 MTU

        assert_eq!(msg.mtu().get(), 1280);
    }
}
