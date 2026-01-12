//! Time Exceeded message parsing.

use crate::prelude::*;

/// ICMP Time Exceeded message.
///
/// This message is sent when a datagram is discarded because:
/// - TTL expired in transit (code 0)
/// - Fragment reassembly time exceeded (code 1)
///
/// Used by traceroute to discover the path to a destination.
pub struct IcmpTimeExceeded<T>
where
    T: AsRef<[u8]>,
{
    data: T,
}

impl<T> IcmpTimeExceeded<T>
where
    T: AsRef<[u8]>,
{
    /// Field range of unused field: 4..8
    pub const FIELD_UNUSED: core::ops::Range<usize> = 4..8;
    /// Field range of original datagram: 8..
    pub const FIELD_ORIGINAL_DATAGRAM: core::ops::RangeFrom<usize> = 8..;

    /// Minimum length for Time Exceeded message.
    pub const MIN_LENGTH: usize = 8;

    /// Create a new Time Exceeded message.
    ///
    /// Returns `None` if the data is too short.
    pub fn new(data: T) -> Option<Self> {
        if data.as_ref().len() < Self::MIN_LENGTH {
            return None;
        }
        Some(Self { data })
    }

    /// Get the original datagram (IP header + first 8 bytes of data).
    ///
    /// This contains the IP header and the first 8 bytes of the original
    /// datagram's data, which allows the sender to identify which packet
    /// triggered the error.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_time_exceeded_parse() {
        // Create a minimal Time Exceeded packet
        let mut data = vec![0u8; 36]; // 8 ICMP header + 28 bytes original datagram
        data[0] = 11; // Time Exceeded
        data[1] = 0; // TTL exceeded in transit

        // Add some dummy IPv4 header data
        data[8] = 0x45; // Version 4, IHL 5
        data[9] = 0x00; // TOS
        data[10] = 0x00;
        data[11] = 0x1C; // Total length 28

        let icmp = Icmpv4::new(&data[..]).unwrap();
        assert_eq!(icmp.msg_type().get(), Icmpv4Type::TimeExceeded);
        assert_eq!(icmp.code().get(), 0);

        // Access Time Exceeded specific fields
        let time_exceeded = icmp.time_exceeded().unwrap();
        assert_eq!(time_exceeded.original_datagram().len(), 28);

        // Verify we can parse the original IPv4 header
        let original_ipv4 = time_exceeded.original_ipv4().unwrap();
        assert_eq!(original_ipv4.version(), 4);
        assert_eq!(original_ipv4.ihl().get(), 5);
    }
}
