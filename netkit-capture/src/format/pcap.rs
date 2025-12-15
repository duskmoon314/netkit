//! Classic pcap file format reader and writer.
//!
//! This module implements reading and writing of pcap files as defined by
//! libpcap. Both microsecond and nanosecond timestamp precision are supported.
//!
//! # Format Overview
//!
//! A pcap file consists of:
//! 1. Global header (24 bytes) - magic number, version, snaplen, link type
//! 2. Packet records - each with a 16-byte header followed by packet data
//!
//! # Example
//!
//! ```ignore
//! use std::fs::File;
//! use netkit_capture::format::pcap::PcapReader;
//!
//! let file = File::open("capture.pcap")?;
//! let reader = PcapReader::new(file)?;
//!
//! for result in reader {
//!     let packet = result?;
//!     println!("Packet: {} bytes", packet.data.len());
//! }
//! ```

use std::cmp::min;
use std::io::{BufReader, BufWriter, Read, Write};

use crate::error::{CaptureError, CaptureResult};
use crate::linktype::LinkType;
use crate::packet::Packet;
use crate::{CaptureReader, CaptureWriter};

/// Magic numbers for pcap files.
pub mod magic {
    /// Big-endian, microsecond timestamps
    pub const BE_USEC: u32 = 0xA1B2C3D4;
    /// Big-endian, nanosecond timestamps  
    pub const BE_NSEC: u32 = 0xA1B23C4D;
    /// Little-endian, microsecond timestamps
    pub const LE_USEC: u32 = 0xD4C3B2A1;
    /// Little-endian, nanosecond timestamps
    pub const LE_NSEC: u32 = 0x4D3CB2A1;
}

/// Pcap file global header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PcapHeader {
    /// Magic number, used to detect the file format and byte ordering
    pub magic_number: u32,
    /// Major version number (usually 2)
    pub version_major: u16,
    /// Minor version number (usually 4)
    pub version_minor: u16,
    /// GMT to local correction (usually 0)
    pub thiszone: i32,
    /// Accuracy of timestamps (usually 0)
    pub sigfigs: u32,
    /// Snapshot length (max bytes per packet)
    pub snaplen: u32,
    /// Data link type
    pub network: u32,
}

impl PcapHeader {
    /// Size of the pcap global header in bytes.
    pub const SIZE: usize = 24;

    /// Get the link type.
    pub fn linktype(&self) -> LinkType {
        LinkType::from(self.network)
    }

    /// Check if this header uses big-endian byte order.
    pub fn is_big_endian(&self) -> bool {
        matches!(self.magic_number, magic::BE_USEC | magic::BE_NSEC)
    }

    /// Check if this header uses nanosecond timestamps.
    pub fn is_nanosecond(&self) -> bool {
        matches!(self.magic_number, magic::BE_NSEC | magic::LE_NSEC)
    }
}

impl Default for PcapHeader {
    fn default() -> Self {
        Self {
            magic_number: magic::LE_USEC,
            version_major: 2,
            version_minor: 4,
            thiszone: 0,
            sigfigs: 0,
            snaplen: 65535,
            network: LinkType::Ethernet.as_u32(),
        }
    }
}

/// Pcap packet header (per-packet).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PcapPacketHeader {
    /// Timestamp seconds
    pub ts_sec: u32,
    /// Timestamp microseconds (or nanoseconds)
    pub ts_usec: u32,
    /// Number of bytes of packet saved in file
    pub incl_len: u32,
    /// Actual length of packet on the wire
    pub orig_len: u32,
}

impl PcapPacketHeader {
    /// Size of the pcap packet header in bytes.
    pub const SIZE: usize = 16;

    /// Convert to universal Packet with nanosecond flag and linktype.
    pub fn to_packet(&self, data: Vec<u8>, nanoseconds: bool, linktype: LinkType) -> Packet {
        let ts_nsec = if nanoseconds {
            self.ts_usec
        } else {
            self.ts_usec * 1000
        };
        let timestamp_ns = (self.ts_sec as i64) * 1_000_000_000 + (ts_nsec as i64);

        Packet::new(timestamp_ns, self.orig_len, data, linktype)
    }

    /// Create from universal Packet with nanosecond flag.
    pub fn from_packet(packet: &Packet, nanoseconds: bool) -> Self {
        let ts_sec = packet.ts_sec();
        let ts_usec = if nanoseconds {
            packet.ts_nsec()
        } else {
            packet.ts_usec()
        };

        Self {
            ts_sec,
            ts_usec,
            incl_len: packet.captured_len(),
            orig_len: packet.orig_len,
        }
    }
}

impl PartialOrd for PcapPacketHeader {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PcapPacketHeader {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.ts_sec
            .cmp(&other.ts_sec)
            .then(self.ts_usec.cmp(&other.ts_usec))
    }
}

/// Reader for pcap files.
///
/// Implements the [`CaptureReader`] trait for reading packets.
#[derive(Debug)]
pub struct PcapReader<R: Read> {
    /// The pcap global header.
    pub header: PcapHeader,
    /// Whether the file is big-endian.
    pub big_endian: bool,
    /// Whether timestamps are in nanoseconds.
    pub nanoseconds: bool,
    reader: BufReader<R>,
}

impl<R: Read> PcapReader<R> {
    /// Create a new pcap reader.
    ///
    /// Returns an error if the magic number is invalid or the header cannot be read.
    pub fn open(reader: R) -> CaptureResult<Self> {
        let mut reader = BufReader::new(reader);

        // Read magic number
        let mut magic_buf = [0u8; 4];
        reader.read_exact(&mut magic_buf)?;
        let magic_number = u32::from_be_bytes(magic_buf);

        let (big_endian, nanoseconds) = match magic_number {
            magic::BE_USEC => (true, false),
            magic::BE_NSEC => (true, true),
            magic::LE_USEC => (false, false),
            magic::LE_NSEC => (false, true),
            _ => return Err(CaptureError::InvalidMagic(magic_number)),
        };

        // Read rest of header
        let mut buffer = [0u8; 20];
        reader.read_exact(&mut buffer)?;

        let header = if big_endian {
            PcapHeader {
                magic_number,
                version_major: u16::from_be_bytes([buffer[0], buffer[1]]),
                version_minor: u16::from_be_bytes([buffer[2], buffer[3]]),
                thiszone: i32::from_be_bytes([buffer[4], buffer[5], buffer[6], buffer[7]]),
                sigfigs: u32::from_be_bytes([buffer[8], buffer[9], buffer[10], buffer[11]]),
                snaplen: u32::from_be_bytes([buffer[12], buffer[13], buffer[14], buffer[15]]),
                network: u32::from_be_bytes([buffer[16], buffer[17], buffer[18], buffer[19]]),
            }
        } else {
            PcapHeader {
                magic_number: u32::from_le_bytes(magic_buf),
                version_major: u16::from_le_bytes([buffer[0], buffer[1]]),
                version_minor: u16::from_le_bytes([buffer[2], buffer[3]]),
                thiszone: i32::from_le_bytes([buffer[4], buffer[5], buffer[6], buffer[7]]),
                sigfigs: u32::from_le_bytes([buffer[8], buffer[9], buffer[10], buffer[11]]),
                snaplen: u32::from_le_bytes([buffer[12], buffer[13], buffer[14], buffer[15]]),
                network: u32::from_le_bytes([buffer[16], buffer[17], buffer[18], buffer[19]]),
            }
        };

        Ok(Self {
            header,
            big_endian,
            nanoseconds,
            reader,
        })
    }

    /// Read the next packet header and data.
    ///
    /// Returns `Ok(None)` at end of file.
    fn read_packet_raw(&mut self) -> CaptureResult<Option<(PcapPacketHeader, Vec<u8>)>> {
        let mut buffer = [0u8; 16];
        match self.reader.read_exact(&mut buffer) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e.into()),
        }

        let header = if self.big_endian {
            PcapPacketHeader {
                ts_sec: u32::from_be_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]),
                ts_usec: u32::from_be_bytes([buffer[4], buffer[5], buffer[6], buffer[7]]),
                incl_len: u32::from_be_bytes([buffer[8], buffer[9], buffer[10], buffer[11]]),
                orig_len: u32::from_be_bytes([buffer[12], buffer[13], buffer[14], buffer[15]]),
            }
        } else {
            PcapPacketHeader {
                ts_sec: u32::from_le_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]),
                ts_usec: u32::from_le_bytes([buffer[4], buffer[5], buffer[6], buffer[7]]),
                incl_len: u32::from_le_bytes([buffer[8], buffer[9], buffer[10], buffer[11]]),
                orig_len: u32::from_le_bytes([buffer[12], buffer[13], buffer[14], buffer[15]]),
            }
        };

        // Read packet data
        let data_len = min(header.incl_len, self.header.snaplen) as usize;
        let mut data = vec![0u8; data_len];

        match self.reader.read_exact(&mut data) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Err(CaptureError::TruncatedPacket {
                    expected: data_len,
                    actual: 0, // We don't know how many bytes were actually read
                });
            }
            Err(e) => return Err(e.into()),
        }

        Ok(Some((header, data)))
    }

    /// Get the snapshot length.
    pub fn snaplen(&self) -> u32 {
        self.header.snaplen
    }

    /// Get the link type.
    pub fn linktype(&self) -> LinkType {
        self.header.linktype()
    }
}

// Implement Iterator for CaptureReader trait
impl<R: Read> Iterator for PcapReader<R> {
    type Item = CaptureResult<Packet>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.read_packet_raw() {
            Ok(Some((hdr, data))) => {
                let linktype = self.linktype();
                Some(Ok(hdr.to_packet(data, self.nanoseconds, linktype)))
            }
            Ok(None) => None,
            Err(e) => Some(Err(e)),
        }
    }
}

impl<R: Read> CaptureReader for PcapReader<R> {
    fn linktype(&self) -> LinkType {
        self.linktype()
    }

    fn snaplen(&self) -> u32 {
        self.snaplen()
    }

    fn is_nanosecond_precision(&self) -> bool {
        self.nanoseconds
    }
}

/// Writer for pcap files.
#[derive(Debug)]
pub struct PcapWriter<W: Write> {
    /// The pcap global header.
    pub header: PcapHeader,
    /// Whether to write big-endian.
    pub big_endian: bool,
    /// Whether timestamps are in nanoseconds.
    pub nanoseconds: bool,
    writer: BufWriter<W>,
}

impl<W: Write> PcapWriter<W> {
    /// Create a new pcap writer with full control over format options.
    pub fn new(
        writer: W,
        big_endian: bool,
        nanoseconds: bool,
        snaplen: u32,
        linktype: LinkType,
    ) -> CaptureResult<Self> {
        let mut writer = BufWriter::new(writer);

        let magic_number = match (big_endian, nanoseconds) {
            (true, false) => magic::BE_USEC,
            (true, true) => magic::BE_NSEC,
            (false, false) => magic::LE_USEC,
            (false, true) => magic::LE_NSEC,
        };

        let header = PcapHeader {
            magic_number,
            version_major: 2,
            version_minor: 4,
            thiszone: 0,
            sigfigs: 0,
            snaplen,
            network: linktype.as_u32(),
        };

        // Write the header
        // Note: Magic number is always written as big-endian bytes (it's how the format works)
        let mut buffer = Vec::with_capacity(PcapHeader::SIZE);
        buffer.extend_from_slice(&magic_number.to_be_bytes());
        if big_endian {
            buffer.extend_from_slice(&header.version_major.to_be_bytes());
            buffer.extend_from_slice(&header.version_minor.to_be_bytes());
            buffer.extend_from_slice(&header.thiszone.to_be_bytes());
            buffer.extend_from_slice(&header.sigfigs.to_be_bytes());
            buffer.extend_from_slice(&header.snaplen.to_be_bytes());
            buffer.extend_from_slice(&header.network.to_be_bytes());
        } else {
            buffer.extend_from_slice(&header.version_major.to_le_bytes());
            buffer.extend_from_slice(&header.version_minor.to_le_bytes());
            buffer.extend_from_slice(&header.thiszone.to_le_bytes());
            buffer.extend_from_slice(&header.sigfigs.to_le_bytes());
            buffer.extend_from_slice(&header.snaplen.to_le_bytes());
            buffer.extend_from_slice(&header.network.to_le_bytes());
        }

        writer.write_all(&buffer)?;

        Ok(Self {
            header,
            big_endian,
            nanoseconds,
            writer,
        })
    }

    /// Create a little-endian pcap writer with microsecond timestamps.
    ///
    /// This is the most common format, compatible with libpcap and tcpdump.
    pub fn new_le(writer: W, snaplen: u32, linktype: LinkType) -> CaptureResult<Self> {
        Self::new(writer, false, false, snaplen, linktype)
    }

    /// Create a little-endian pcap writer with nanosecond timestamps.
    pub fn new_le_ns(writer: W, snaplen: u32, linktype: LinkType) -> CaptureResult<Self> {
        Self::new(writer, false, true, snaplen, linktype)
    }

    /// Create a big-endian pcap writer with microsecond timestamps.
    pub fn new_be(writer: W, snaplen: u32, linktype: LinkType) -> CaptureResult<Self> {
        Self::new(writer, true, false, snaplen, linktype)
    }

    /// Create a big-endian pcap writer with nanosecond timestamps.
    pub fn new_be_ns(writer: W, snaplen: u32, linktype: LinkType) -> CaptureResult<Self> {
        Self::new(writer, true, true, snaplen, linktype)
    }

    /// Write a packet using raw header and data.
    pub fn write_packet_raw<T: AsRef<[u8]>>(
        &mut self,
        header: PcapPacketHeader,
        data: T,
    ) -> CaptureResult<()> {
        let data = data.as_ref();
        let incl_len = min(min(header.incl_len, self.header.snaplen), data.len() as u32);

        let mut buffer = Vec::with_capacity(PcapPacketHeader::SIZE + incl_len as usize);

        if self.big_endian {
            buffer.extend_from_slice(&header.ts_sec.to_be_bytes());
            buffer.extend_from_slice(&header.ts_usec.to_be_bytes());
            buffer.extend_from_slice(&incl_len.to_be_bytes());
            buffer.extend_from_slice(&header.orig_len.to_be_bytes());
        } else {
            buffer.extend_from_slice(&header.ts_sec.to_le_bytes());
            buffer.extend_from_slice(&header.ts_usec.to_le_bytes());
            buffer.extend_from_slice(&incl_len.to_le_bytes());
            buffer.extend_from_slice(&header.orig_len.to_le_bytes());
        }

        buffer.extend_from_slice(&data[..incl_len as usize]);
        self.writer.write_all(&buffer)?;

        Ok(())
    }

    /// Flush buffered data to the underlying writer.
    pub fn flush(&mut self) -> CaptureResult<()> {
        self.writer.flush()?;
        Ok(())
    }

    /// Get the link type.
    pub fn linktype(&self) -> LinkType {
        self.header.linktype()
    }

    /// Get the snapshot length.
    pub fn snaplen(&self) -> u32 {
        self.header.snaplen
    }
}

impl<W: Write> CaptureWriter for PcapWriter<W> {
    fn write_packet(&mut self, packet: &Packet) -> CaptureResult<()> {
        let header = PcapPacketHeader::from_packet(packet, self.nanoseconds);
        self.write_packet_raw(header, &packet.data)
    }

    fn flush(&mut self) -> CaptureResult<()> {
        self.writer.flush()?;
        Ok(())
    }

    fn linktype(&self) -> LinkType {
        self.header.linktype()
    }

    fn snaplen(&self) -> u32 {
        self.header.snaplen
    }
}

// Re-export legacy name for backward compatibility
pub use PcapPacketHeader as PacketHeader;

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_write_and_read_pcap() {
        let mut buffer = Vec::new();

        // Write
        {
            let mut writer =
                PcapWriter::new(&mut buffer, false, false, 65535, LinkType::Ethernet).unwrap();

            let header = PcapPacketHeader {
                ts_sec: 1234567890,
                ts_usec: 123456,
                incl_len: 4,
                orig_len: 4,
            };
            writer.write_packet_raw(header, &[1, 2, 3, 4]).unwrap();
            writer.flush().unwrap();
        }

        // Read
        let cursor = Cursor::new(buffer);
        let mut reader = PcapReader::open(cursor).unwrap();

        assert_eq!(reader.linktype(), LinkType::Ethernet);
        assert_eq!(reader.snaplen(), 65535);
        assert!(!reader.nanoseconds);

        let packet = reader.next().unwrap().unwrap();
        assert_eq!(packet.ts_sec(), 1234567890);
        assert_eq!(packet.ts_usec(), 123456);
        assert_eq!(packet.data, vec![1, 2, 3, 4]);

        assert!(reader.next().is_none());
    }

    #[test]
    fn test_packet_conversion() {
        let pcap_hdr = PcapPacketHeader {
            ts_sec: 100,
            ts_usec: 500_000, // 500ms in microseconds
            incl_len: 10,
            orig_len: 100,
        };

        // Convert to Packet (microseconds mode)
        let packet = pcap_hdr.to_packet(vec![0; 10], false, LinkType::Ethernet);
        assert_eq!(packet.ts_sec(), 100);
        assert_eq!(packet.ts_usec(), 500_000);
        assert_eq!(packet.orig_len, 100);
        assert_eq!(packet.linktype, LinkType::Ethernet);
        assert!(packet.is_truncated());

        // Convert back
        let hdr2 = PcapPacketHeader::from_packet(&packet, false);
        assert_eq!(hdr2.ts_sec, 100);
        assert_eq!(hdr2.ts_usec, 500_000);
    }

    #[test]
    fn test_nanosecond_timestamps() {
        let mut buffer = Vec::new();

        // Write with nanoseconds
        {
            let mut writer =
                PcapWriter::new(&mut buffer, false, true, 65535, LinkType::Ethernet).unwrap();

            let header = PcapPacketHeader {
                ts_sec: 1,
                ts_usec: 999_999_999, // nanoseconds
                incl_len: 1,
                orig_len: 1,
            };
            writer.write_packet_raw(header, &[0]).unwrap();
            writer.flush().unwrap();
        }

        // Read
        let cursor = Cursor::new(buffer);
        let reader = PcapReader::open(cursor).unwrap();
        assert!(reader.nanoseconds);
    }

    #[test]
    fn test_capture_reader_trait() {
        let mut buffer = Vec::new();

        // Write using CaptureWriter trait
        {
            let mut writer =
                PcapWriter::new(&mut buffer, false, false, 65535, LinkType::Ethernet).unwrap();

            let packet = Packet::new(1_500_000_000, 4, vec![1, 2, 3, 4], LinkType::Ethernet); // 1.5 seconds
            CaptureWriter::write_packet(&mut writer, &packet).unwrap();
            CaptureWriter::flush(&mut writer).unwrap();
        }

        // Read using CaptureReader trait
        let cursor = Cursor::new(buffer);
        let mut reader = PcapReader::open(cursor).unwrap();

        assert_eq!(CaptureReader::linktype(&reader), LinkType::Ethernet);

        let packet = reader.next().unwrap().unwrap();
        assert_eq!(packet.ts_sec(), 1);
        assert_eq!(packet.ts_usec(), 500_000);
        assert_eq!(packet.data, vec![1, 2, 3, 4]);
    }
}
