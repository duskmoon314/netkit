//! Universal packet representation for all capture formats.

/// A format-agnostic packet representation.
///
/// This struct provides a common representation for packets from any capture
/// format (pcap, pcapng, etc.), normalizing timestamps and metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    /// Timestamp in nanoseconds since Unix epoch.
    ///
    /// This is normalized from whatever timestamp format the source uses
    /// (microseconds, nanoseconds, or custom resolution).
    pub timestamp_ns: i64,

    /// Original length of the packet on the wire.
    ///
    /// This may be larger than `data.len()` if the packet was truncated
    /// during capture (due to snaplen).
    pub orig_len: u32,

    /// Captured packet data.
    ///
    /// May be shorter than `orig_len` if truncated during capture.
    pub data: Vec<u8>,

    /// Interface index for multi-interface captures (pcapng).
    ///
    /// For pcap files, this is always 0.
    pub interface_id: u32,

    /// Optional packet metadata.
    pub metadata: Option<PacketMetadata>,
}

impl Packet {
    /// Create a new packet with the given timestamp, length, and data.
    pub fn new(timestamp_ns: i64, orig_len: u32, data: Vec<u8>) -> Self {
        Self {
            timestamp_ns,
            orig_len,
            data,
            interface_id: 0,
            metadata: None,
        }
    }

    /// Create a packet with interface ID (for pcapng).
    pub fn with_interface(mut self, interface_id: u32) -> Self {
        self.interface_id = interface_id;
        self
    }

    /// Create a packet with metadata.
    pub fn with_metadata(mut self, metadata: PacketMetadata) -> Self {
        self.metadata = Some(metadata);
        self
    }

    /// Get the captured length (actual bytes in data).
    #[inline]
    pub fn captured_len(&self) -> u32 {
        self.data.len() as u32
    }

    /// Check if the packet was truncated during capture.
    #[inline]
    pub fn is_truncated(&self) -> bool {
        self.captured_len() < self.orig_len
    }

    /// Get timestamp in seconds (with fractional nanoseconds).
    #[inline]
    pub fn timestamp_secs(&self) -> f64 {
        self.timestamp_ns as f64 / 1_000_000_000.0
    }

    /// Get timestamp seconds component.
    #[inline]
    pub fn ts_sec(&self) -> u32 {
        (self.timestamp_ns / 1_000_000_000) as u32
    }

    /// Get timestamp nanoseconds component (within the second).
    #[inline]
    pub fn ts_nsec(&self) -> u32 {
        (self.timestamp_ns % 1_000_000_000) as u32
    }

    /// Get timestamp microseconds component (within the second).
    #[inline]
    pub fn ts_usec(&self) -> u32 {
        self.ts_nsec() / 1000
    }
}

impl PartialOrd for Packet {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Packet {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.timestamp_ns.cmp(&other.timestamp_ns)
    }
}

/// Optional metadata that can be attached to a packet.
///
/// This is primarily used by pcapng which supports rich metadata,
/// but can be used with any format.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PacketMetadata {
    /// Packet flags (direction, reception type, etc.).
    pub flags: Option<PacketFlags>,

    /// User comment attached to the packet.
    pub comment: Option<String>,

    /// Packet hash (for deduplication or verification).
    pub hash: Option<Vec<u8>>,

    /// Drop count before this packet.
    pub drop_count: Option<u64>,

    /// Packet ID (unique identifier).
    pub packet_id: Option<u64>,

    /// Queue ID (for multi-queue NICs).
    pub queue_id: Option<u32>,

    /// Verdict (for firewall/filter captures).
    pub verdict: Option<Vec<u8>>,
}

/// Packet flags indicating direction, reception type, etc.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PacketFlags {
    /// Direction: true = inbound, false = outbound, None = unknown.
    pub inbound: Option<bool>,

    /// Reception type.
    pub reception_type: ReceptionType,

    /// FCS (Frame Check Sequence) length in bytes.
    pub fcs_len: u8,

    /// Link-layer-dependent errors were detected.
    pub link_layer_errors: bool,

    /// Preamble/Start Frame Delimiter errors were detected.
    pub preamble_errors: bool,

    /// Unaligned frame errors were detected.
    pub unaligned_errors: bool,

    /// Wrong Inter Frame Gap errors were detected.
    pub wrong_ifg_errors: bool,

    /// Packet is CRC-validated.
    pub crc_validated: bool,

    /// Packet CRC is invalid.
    pub crc_invalid: bool,
}

/// How the packet was received.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ReceptionType {
    /// Not specified.
    #[default]
    Unspecified,
    /// Unicast to this host.
    Unicast,
    /// Multicast.
    Multicast,
    /// Broadcast.
    Broadcast,
    /// Promiscuous mode capture.
    Promiscuous,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_timestamps() {
        // 1 second + 500ms = 1.5 seconds
        let pkt = Packet::new(1_500_000_000, 100, vec![0; 100]);

        assert_eq!(pkt.ts_sec(), 1);
        assert_eq!(pkt.ts_nsec(), 500_000_000);
        assert_eq!(pkt.ts_usec(), 500_000);
        assert!((pkt.timestamp_secs() - 1.5).abs() < 1e-9);
    }

    #[test]
    fn test_packet_truncation() {
        let pkt = Packet::new(0, 1500, vec![0; 100]);

        assert!(pkt.is_truncated());
        assert_eq!(pkt.captured_len(), 100);
        assert_eq!(pkt.orig_len, 1500);
    }

    #[test]
    fn test_packet_ordering() {
        let pkt1 = Packet::new(1000, 100, vec![]);
        let pkt2 = Packet::new(2000, 100, vec![]);
        let pkt3 = Packet::new(1000, 200, vec![]);

        assert!(pkt1 < pkt2);
        assert_eq!(pkt1.cmp(&pkt3), std::cmp::Ordering::Equal);
    }
}
