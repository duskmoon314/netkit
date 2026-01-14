//! Checksum calculation utilities for network protocols.

use core::net::{Ipv4Addr, Ipv6Addr};

/// Calculate the Internet checksum (RFC 1071).
///
/// This is the standard one's complement checksum used by TCP, UDP, ICMP, and IPv4.
/// The checksum is calculated over 16-bit words, with any odd byte padded with zero.
///
/// ## Algorithm
/// 1. Sum all 16-bit words
/// 2. Add any carry bits from the high-order 16 bits back into the low-order 16 bits
/// 3. Take the one's complement (bitwise NOT) of the result
///
/// ## Example
///
/// ```
/// use netkit_packet::utils::checksum::internet_checksum;
///
/// let data = [0x45, 0x00, 0x00, 0x3c];
/// let checksum = internet_checksum(&data);
/// ```
pub fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    // Sum all 16-bit words
    for chunk in data.chunks(2) {
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

/// Create an IPv4 pseudo-header for TCP/UDP checksum calculation.
///
/// The IPv4 pseudo-header is used in TCP and UDP checksum calculations
/// to provide additional protection against misrouted packets.
///
/// ## Format (12 bytes)
/// ```text
/// +--------+--------+--------+--------+
/// |      Source Address (4 bytes)    |
/// +--------+--------+--------+--------+
/// |   Destination Address (4 bytes)  |
/// +--------+--------+--------+--------+
/// | Zero   | Proto  | UDP/TCP Length  |
/// +--------+--------+--------+--------+
/// ```
///
/// ## Parameters
/// - `src`: Source IPv4 address
/// - `dst`: Destination IPv4 address
/// - `protocol`: IP protocol number (6 for TCP, 17 for UDP)
/// - `length`: Length of the TCP/UDP segment (header + data)
pub fn ipv4_pseudo_header(src: Ipv4Addr, dst: Ipv4Addr, protocol: u8, length: u16) -> [u8; 12] {
    let mut header = [0u8; 12];
    header[0..4].copy_from_slice(&src.octets());
    header[4..8].copy_from_slice(&dst.octets());
    header[8] = 0; // Zero
    header[9] = protocol;
    header[10..12].copy_from_slice(&length.to_be_bytes());
    header
}

/// Create an IPv6 pseudo-header for TCP/UDP/ICMPv6 checksum calculation.
///
/// The IPv6 pseudo-header is used in TCP, UDP, and ICMPv6 checksum calculations.
/// Unlike IPv4, ICMPv6 also requires the pseudo-header for its checksum.
///
/// ## Format (40 bytes)
/// ```text
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// +                                                               +
/// |                                                               |
/// +                         Source Address                        +
/// |                                                               |
/// +                                                               +
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// +                                                               +
/// |                                                               |
/// +                      Destination Address                      +
/// |                                                               |
/// +                                                               +
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                   Upper-Layer Packet Length                   |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                      zero                     |  Next Header  |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// ## Parameters
/// - `src`: Source IPv6 address
/// - `dst`: Destination IPv6 address
/// - `next_header`: Next header value (6 for TCP, 17 for UDP, 58 for ICMPv6)
/// - `length`: Length of the upper-layer packet (header + data)
pub fn ipv6_pseudo_header(src: Ipv6Addr, dst: Ipv6Addr, next_header: u8, length: u32) -> [u8; 40] {
    let mut header = [0u8; 40];
    header[0..16].copy_from_slice(&src.octets());
    header[16..32].copy_from_slice(&dst.octets());
    header[32..36].copy_from_slice(&length.to_be_bytes());
    header[36..39].fill(0); // Zero padding
    header[39] = next_header;
    header
}

/// Calculate checksum with pseudo-header.
///
/// This is a convenience function that combines the pseudo-header and data,
/// then calculates the Internet checksum over the combined buffer.
///
/// ## Parameters
/// - `pseudo`: The pseudo-header bytes
/// - `data`: The protocol data (TCP/UDP/ICMPv6 header + payload)
///
/// ## Example
/// ```ignore
/// use netkit_packet::utils::checksum::{ipv4_pseudo_header, calculate_with_pseudo};
/// use core::net::Ipv4Addr;
///
/// let src = Ipv4Addr::new(192, 168, 1, 1);
/// let dst = Ipv4Addr::new(192, 168, 1, 2);
/// let pseudo = ipv4_pseudo_header(src, dst, 17, 16); // UDP
/// let udp_data = [0u8; 16]; // UDP header + data
/// let checksum = calculate_with_pseudo(&pseudo, &udp_data);
/// ```
pub fn calculate_with_pseudo(pseudo: &[u8], data: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    // Sum pseudo-header
    for chunk in pseudo.chunks(2) {
        let word = u16::from_be_bytes([chunk[0], chunk[1]]);
        sum += word as u32;
    }

    // Sum data
    for chunk in data.chunks(2) {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_internet_checksum() {
        // Test with a simple known value
        // IPv4 header: 45 00 00 3c 1c 46 40 00 40 06 00 00 ac 10 0a 63 ac 10 0a 0c
        // The checksum field (bytes 10-11) should be calculated with those bytes set to 0
        let data = [
            0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 0xac, 0x10,
            0x0a, 0x63, 0xac, 0x10, 0x0a, 0x0c,
        ];
        let checksum = internet_checksum(&data);
        // The result should be a valid checksum (exact value depends on input)
        assert_ne!(checksum, 0); // Should not be zero for this input
    }

    #[test]
    fn test_internet_checksum_verify() {
        // Test that checksum verification works
        // If we include the checksum in the data, the result should be 0
        let data = [0x45, 0x00, 0x00, 0x3c];
        let checksum = internet_checksum(&data);

        let mut data_with_checksum = vec![0x45, 0x00, 0x00, 0x3c];
        data_with_checksum.extend_from_slice(&checksum.to_be_bytes());

        // Checksum of data with its own checksum included should give 0xFFFF or 0x0000
        let verify = internet_checksum(&data_with_checksum);
        assert!(verify == 0xFFFF || verify == 0x0000);
    }

    #[test]
    fn test_ipv4_pseudo_header() {
        let src = Ipv4Addr::new(192, 168, 1, 1);
        let dst = Ipv4Addr::new(192, 168, 1, 2);
        let protocol = 17; // UDP
        let length = 16;

        let header = ipv4_pseudo_header(src, dst, protocol, length);

        assert_eq!(header.len(), 12);
        assert_eq!(&header[0..4], &[192, 168, 1, 1]); // Source
        assert_eq!(&header[4..8], &[192, 168, 1, 2]); // Destination
        assert_eq!(header[8], 0); // Zero
        assert_eq!(header[9], 17); // Protocol
        assert_eq!(&header[10..12], &[0, 16]); // Length
    }

    #[test]
    fn test_ipv6_pseudo_header() {
        let src = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
        let next_header = 58; // ICMPv6
        let length = 64;

        let header = ipv6_pseudo_header(src, dst, next_header, length);

        assert_eq!(header.len(), 40);
        assert_eq!(&header[0..16], &src.octets()); // Source
        assert_eq!(&header[16..32], &dst.octets()); // Destination
        assert_eq!(&header[32..36], &[0, 0, 0, 64]); // Length
        assert_eq!(&header[36..39], &[0, 0, 0]); // Zero
        assert_eq!(header[39], 58); // Next header
    }

    #[test]
    fn test_calculate_with_pseudo() {
        let src = Ipv4Addr::new(192, 168, 1, 1);
        let dst = Ipv4Addr::new(192, 168, 1, 2);
        let pseudo = ipv4_pseudo_header(src, dst, 17, 8);

        // Minimal UDP header (8 bytes) with ports 0, length 8, checksum 0
        let udp_data = [0, 0, 0, 0, 0, 8, 0, 0];

        let checksum = calculate_with_pseudo(&pseudo, &udp_data);
        assert_ne!(checksum, 0); // Should produce a non-zero checksum
    }
}
