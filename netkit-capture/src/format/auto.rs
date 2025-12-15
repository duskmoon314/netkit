//! Auto-detection and unified access to capture file formats.
//!
//! This module provides automatic format detection and a unified interface
//! for reading capture files regardless of their format (pcap or pcapng).
//!
//! # Example
//!
//! ```ignore
//! use std::fs::File;
//! use netkit_capture::format::auto::CaptureFile;
//!
//! // Automatically detect format and open
//! let file = File::open("capture.pcap")?; // or .pcapng
//! let mut reader = CaptureFile::open(file)?;
//!
//! println!("Format: {}", reader.format_name());
//! println!("Link type: {}", reader.linktype());
//!
//! for result in reader {
//!     let packet = result?;
//!     println!("Packet: {} bytes", packet.data.len());
//! }
//! ```

use std::io::{BufReader, Read, Seek, SeekFrom};

use crate::error::{CaptureError, CaptureResult};
use crate::format::pcap::{self, PcapReader};
use crate::format::pcapng::{self, PcapngReader};
use crate::linktype::LinkType;
use crate::packet::Packet;
use crate::CaptureReader;

/// Detected capture file format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureFormat {
    /// Classic pcap format (libpcap)
    Pcap,
    /// Pcap-ng format
    Pcapng,
}

impl CaptureFormat {
    /// Get the format name.
    pub fn name(&self) -> &'static str {
        match self {
            CaptureFormat::Pcap => "pcap",
            CaptureFormat::Pcapng => "pcapng",
        }
    }

    /// Get common file extensions for this format.
    pub fn extensions(&self) -> &'static [&'static str] {
        match self {
            CaptureFormat::Pcap => &["pcap", "cap", "dmp"],
            CaptureFormat::Pcapng => &["pcapng", "ntar"],
        }
    }
}

impl std::fmt::Display for CaptureFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Detect format from magic bytes.
fn detect_from_magic(magic: [u8; 4]) -> CaptureResult<CaptureFormat> {
    let magic_u32 = u32::from_be_bytes(magic);

    // Check pcap magic numbers (all 4 possibilities)
    if matches!(
        magic_u32,
        pcap::magic::BE_USEC | pcap::magic::BE_NSEC | pcap::magic::LE_USEC | pcap::magic::LE_NSEC
    ) {
        return Ok(CaptureFormat::Pcap);
    }

    // Check pcapng magic (SHB block type)
    if magic_u32 == pcapng::block_type::SHB {
        return Ok(CaptureFormat::Pcapng);
    }

    Err(CaptureError::InvalidMagic(magic_u32))
}

/// Detect the format of a capture file from its magic number.
///
/// Reads the first 4 bytes to determine the format, then seeks back.
/// Returns an error if the format is not recognized.
pub fn detect_format<R: Read + Seek>(reader: &mut R) -> CaptureResult<CaptureFormat> {
    let mut magic = [0u8; 4];
    reader.read_exact(&mut magic)?;
    reader.seek(SeekFrom::Start(0))?;
    detect_from_magic(magic)
}

/// Detect format from magic bytes without seeking.
///
/// Use this when you've already read the magic bytes.
pub fn detect_format_from_magic(magic: [u8; 4]) -> CaptureResult<CaptureFormat> {
    detect_from_magic(magic)
}

/// A unified capture file reader that handles both pcap and pcapng formats.
///
/// This enum wraps format-specific readers and provides a common interface
/// through the [`CaptureReader`] trait.
pub enum CaptureFile<R: Read> {
    /// Classic pcap format
    Pcap(PcapReader<R>),
    /// Pcapng format
    Pcapng(PcapngReader<R>),
}

impl<R: Read + Seek> CaptureFile<R> {
    /// Open a capture file with automatic format detection.
    ///
    /// Reads the magic number to detect the format, then opens the appropriate
    /// reader.
    pub fn open(mut reader: R) -> CaptureResult<Self> {
        let format = detect_format(&mut reader)?;

        match format {
            CaptureFormat::Pcap => {
                let pcap_reader = PcapReader::open(reader)?;
                Ok(CaptureFile::Pcap(pcap_reader))
            }
            CaptureFormat::Pcapng => {
                let pcapng_reader = PcapngReader::open(reader)?;
                Ok(CaptureFile::Pcapng(pcapng_reader))
            }
        }
    }
}

/// Helper macro to dispatch method calls to inner reader
macro_rules! dispatch {
    ($self:expr, $method:ident $(, $arg:expr)*) => {
        match $self {
            CaptureFile::Pcap(r) => r.$method($($arg),*),
            CaptureFile::Pcapng(r) => r.$method($($arg),*),
        }
    };
}

impl<R: Read> CaptureFile<R> {
    /// Get the detected format.
    pub fn format(&self) -> CaptureFormat {
        match self {
            CaptureFile::Pcap(_) => CaptureFormat::Pcap,
            CaptureFile::Pcapng(_) => CaptureFormat::Pcapng,
        }
    }

    /// Get the format name as a string.
    pub fn format_name(&self) -> &'static str {
        self.format().name()
    }

    /// Check if this is a pcap file.
    pub fn is_pcap(&self) -> bool {
        matches!(self, CaptureFile::Pcap(_))
    }

    /// Check if this is a pcapng file.
    pub fn is_pcapng(&self) -> bool {
        matches!(self, CaptureFile::Pcapng(_))
    }
}

impl<R: Read> Iterator for CaptureFile<R> {
    type Item = CaptureResult<Packet>;

    fn next(&mut self) -> Option<Self::Item> {
        dispatch!(self, next)
    }
}

impl<R: Read> CaptureReader for CaptureFile<R> {
    fn linktype(&self) -> LinkType {
        dispatch!(self, linktype)
    }

    fn snaplen(&self) -> u32 {
        dispatch!(self, snaplen)
    }

    fn is_nanosecond_precision(&self) -> bool {
        dispatch!(self, is_nanosecond_precision)
    }
}

/// Open a capture file with automatic format detection.
///
/// This is a convenience function that creates a [`CaptureFile`] from a reader.
///
/// # Example
///
/// ```ignore
/// use std::fs::File;
/// use netkit_capture::format::auto::open_capture;
///
/// let file = File::open("capture.pcap")?;
/// let mut reader = open_capture(file)?;
///
/// for packet in reader {
///     println!("{:?}", packet?);
/// }
/// ```
pub fn open_capture<R: Read + Seek>(reader: R) -> CaptureResult<CaptureFile<R>> {
    CaptureFile::open(reader)
}

/// Open a capture file from a path with automatic format detection.
///
/// # Example
///
/// ```ignore
/// use netkit_capture::format::auto::open_file;
///
/// let mut reader = open_file("capture.pcap")?;
/// for packet in reader {
///     println!("{:?}", packet?);
/// }
/// ```
pub fn open_file<P: AsRef<std::path::Path>>(
    path: P,
) -> CaptureResult<CaptureFile<std::io::BufReader<std::fs::File>>> {
    let file = std::fs::File::open(path)?;
    let reader = BufReader::new(file);
    CaptureFile::open(reader)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::pcap::PcapWriter;
    use crate::format::pcapng::PcapngWriter;
    use crate::CaptureWriter;
    use std::io::Cursor;

    #[test]
    fn test_detect_pcap_format() {
        let mut buffer = Vec::new();
        {
            let mut writer =
                PcapWriter::new(&mut buffer, false, false, 65535, LinkType::Ethernet).unwrap();
            let packet = Packet::new(1_000_000_000, 10, vec![0u8; 10], LinkType::Ethernet);
            CaptureWriter::write_packet(&mut writer, &packet).unwrap();
            writer.flush().unwrap();
        }

        let mut cursor = Cursor::new(buffer);
        let format = detect_format(&mut cursor).unwrap();
        assert_eq!(format, CaptureFormat::Pcap);
    }

    #[test]
    fn test_detect_pcapng_format() {
        let mut buffer = Vec::new();
        {
            let mut writer = PcapngWriter::new(&mut buffer, LinkType::Ethernet, 65535).unwrap();
            let packet = Packet::new(1_000_000_000, 10, vec![0u8; 10], LinkType::Ethernet);
            CaptureWriter::write_packet(&mut writer, &packet).unwrap();
            writer.flush().unwrap();
        }

        let mut cursor = Cursor::new(buffer);
        let format = detect_format(&mut cursor).unwrap();
        assert_eq!(format, CaptureFormat::Pcapng);
    }

    #[test]
    fn test_auto_open_pcap() {
        let mut buffer = Vec::new();
        {
            let mut writer =
                PcapWriter::new(&mut buffer, false, false, 65535, LinkType::Ethernet).unwrap();
            let packet = Packet::new(1_000_000_000, 10, vec![0u8; 10], LinkType::Ethernet);
            CaptureWriter::write_packet(&mut writer, &packet).unwrap();
            writer.flush().unwrap();
        }

        let cursor = Cursor::new(buffer);
        let mut reader = CaptureFile::open(cursor).unwrap();

        assert!(reader.is_pcap());
        assert_eq!(reader.format(), CaptureFormat::Pcap);
        assert_eq!(reader.linktype(), LinkType::Ethernet);

        let packet = reader.next().unwrap().unwrap();
        assert_eq!(packet.data.len(), 10);
    }

    #[test]
    fn test_auto_open_pcapng() {
        let mut buffer = Vec::new();
        {
            let mut writer = PcapngWriter::new(&mut buffer, LinkType::Ethernet, 65535).unwrap();
            let packet = Packet::new(1_000_000_000, 10, vec![0u8; 10], LinkType::Ethernet);
            CaptureWriter::write_packet(&mut writer, &packet).unwrap();
            writer.flush().unwrap();
        }

        let cursor = Cursor::new(buffer);
        let mut reader = CaptureFile::open(cursor).unwrap();

        assert!(reader.is_pcapng());
        assert_eq!(reader.format(), CaptureFormat::Pcapng);

        let packet = reader.next().unwrap().unwrap();
        assert_eq!(packet.data.len(), 10);
    }

    #[test]
    fn test_invalid_format() {
        let buffer = vec![0u8; 100]; // Not a valid capture file
        let mut cursor = Cursor::new(buffer);
        let result = detect_format(&mut cursor);
        assert!(result.is_err());
    }

    #[test]
    fn test_capture_format_display() {
        assert_eq!(CaptureFormat::Pcap.to_string(), "pcap");
        assert_eq!(CaptureFormat::Pcapng.to_string(), "pcapng");
    }

    #[test]
    fn test_capture_format_extensions() {
        assert!(CaptureFormat::Pcap.extensions().contains(&"pcap"));
        assert!(CaptureFormat::Pcapng.extensions().contains(&"pcapng"));
    }
}
