//! ICMPv6 Time Exceeded message.

use crate::{field_spec, prelude::*};

field_spec!(UnusedSpec, u32, u32);

/// ICMPv6 Time Exceeded message (Type 3).
///
/// ```text
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Type      |     Code      |          Checksum             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                             Unused                            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                    As much of invoking packet                 |
/// +                as possible without the ICMPv6 packet          +
/// |                exceeding the minimum IPv6 MTU (1280 bytes)    |
/// ```
///
/// **Code values**:
/// - 0: Hop limit exceeded in transit
/// - 1: Fragment reassembly time exceeded
pub struct Icmpv6TimeExceeded<T>
where
    T: AsRef<[u8]>,
{
    data: T,
}

impl<T> Icmpv6TimeExceeded<T>
where
    T: AsRef<[u8]>,
{
    /// Minimum message length.
    pub const MIN_LENGTH: usize = 8;

    /// Field range for unused field.
    pub const FIELD_UNUSED: core::ops::Range<usize> = 4..8;
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

impl<T> Icmpv6TimeExceeded<T>
where
    T: AsRef<[u8]> + AsMut<[u8]>,
{
    /// Get mutable access to the unused field.
    #[inline]
    pub fn unused_mut(&mut self) -> FieldMut<'_, UnusedSpec> {
        FieldMut::new(&mut self.as_mut()[Self::FIELD_UNUSED])
    }

    /// Get mutable access to invoking packet area.
    #[inline]
    pub fn invoking_packet_mut(&mut self) -> &mut [u8] {
        &mut self.as_mut()[Self::FIELD_INVOKING_PACKET]
    }
}

impl<T: AsRef<[u8]>> AsRef<[u8]> for Icmpv6TimeExceeded<T> {
    fn as_ref(&self) -> &[u8] {
        self.data.as_ref()
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> AsMut<[u8]> for Icmpv6TimeExceeded<T> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.data.as_mut()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_time_exceeded_parse() {
        let data = vec![
            0x03, 0x00, // type=3, code=0 (hop limit exceeded)
            0x00, 0x00, // checksum
            0x00, 0x00, 0x00, 0x00, // unused
            // Original IPv6 header would follow...
            0x60, 0x00, 0x00, 0x00, // IPv6 header start
        ];

        let msg = Icmpv6TimeExceeded::new(&data[..]).unwrap();
        assert!(msg.invoking_packet().len() >= 4);
    }
}
