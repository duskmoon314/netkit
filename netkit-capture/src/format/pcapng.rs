//! PCAP Next Generation (pcapng) file format reader and writer.
//!
//! This module implements reading and writing of pcapng files as specified in
//! the IETF draft. Pcapng is an extensible format that supports:
//!
//! - Multiple interfaces with different link types
//! - Nanosecond timestamp precision
//! - Packet comments and annotations
//! - Name resolution records
//! - Custom metadata
//!
//! # Format Overview
//!
//! A pcapng file consists of a sequence of blocks:
//!
//! - **Section Header Block (SHB)** - Required, starts each section
//! - **Interface Description Block (IDB)** - Required, describes capture interfaces
//! - **Enhanced Packet Block (EPB)** - Contains captured packets
//! - **Simple Packet Block (SPB)** - Simplified packet format (single interface)
//! - Other optional blocks (name resolution, interface statistics, etc.)
//!
//! # Example
//!
//! ```ignore
//! use std::fs::File;
//! use netkit_capture::format::pcapng::PcapngReader;
//!
//! let file = File::open("capture.pcapng")?;
//! let mut reader = PcapngReader::open(file)?;
//!
//! for result in reader {
//!     let packet = result?;
//!     println!("Packet: {} bytes at interface {}", packet.data.len(), packet.interface_id);
//! }
//! ```

use std::io::{BufReader, BufWriter, Read, Write};

use crate::error::{CaptureError, CaptureResult};
use crate::linktype::LinkType;
use crate::packet::Packet;
use crate::traits::{CaptureReader, CaptureWriter};

/// Block type constants for pcapng.
pub mod block_type {
    /// Section Header Block
    pub const SHB: u32 = 0x0A0D0D0A;
    /// Interface Description Block
    pub const IDB: u32 = 0x00000001;
    /// Simple Packet Block (deprecated)
    pub const SPB: u32 = 0x00000003;
    /// Name Resolution Block
    pub const NRB: u32 = 0x00000004;
    /// Interface Statistics Block
    pub const ISB: u32 = 0x00000005;
    /// Enhanced Packet Block
    pub const EPB: u32 = 0x00000006;
    /// Custom Block (copyable)
    pub const CB_COPY: u32 = 0x00000BAD;
    /// Custom Block (not copyable)
    pub const CB_NO_COPY: u32 = 0x40000BAD;
}

/// Byte-order magic for pcapng (used to detect endianness).
pub const BYTE_ORDER_MAGIC: u32 = 0x1A2B3C4D;

/// Option codes for pcapng blocks.
pub mod option_code {
    /// End of options
    pub const END_OF_OPT: u16 = 0;
    /// Comment
    pub const COMMENT: u16 = 1;
    // SHB options
    /// Hardware description (SHB)
    pub const SHB_HARDWARE: u16 = 2;
    /// OS description (SHB)
    pub const SHB_OS: u16 = 3;
    /// User application (SHB)
    pub const SHB_USERAPPL: u16 = 4;
    // IDB options
    /// Interface name (IDB)
    pub const IF_NAME: u16 = 2;
    /// Interface description (IDB)
    pub const IF_DESCRIPTION: u16 = 3;
    /// Interface speed (IDB)
    pub const IF_SPEED: u16 = 8;
    /// Timestamp resolution (IDB)
    pub const IF_TSRESOL: u16 = 9;
    /// Interface filter (IDB)
    pub const IF_FILTER: u16 = 11;
    /// Interface OS (IDB)
    pub const IF_OS: u16 = 12;
    // EPB options
    /// Packet flags (EPB)
    pub const EPB_FLAGS: u16 = 2;
    /// Packet hash (EPB)
    pub const EPB_HASH: u16 = 3;
    /// Drop count (EPB)
    pub const EPB_DROPCOUNT: u16 = 4;
    /// Packet ID (EPB)
    pub const EPB_PACKETID: u16 = 5;
    /// Queue ID (EPB)
    pub const EPB_QUEUE: u16 = 6;
    /// Verdict (EPB)
    pub const EPB_VERDICT: u16 = 7;
}

/// Section Header Block data.
#[derive(Debug, Clone)]
pub struct SectionHeader {
    /// Major version (usually 1)
    pub version_major: u16,
    /// Minor version (usually 0)
    pub version_minor: u16,
    /// Section length (-1 for unspecified)
    pub section_length: i64,
    /// Hardware description
    pub hardware: Option<String>,
    /// OS description
    pub os: Option<String>,
    /// User application
    pub user_appl: Option<String>,
}

impl Default for SectionHeader {
    fn default() -> Self {
        Self {
            version_major: 1,
            version_minor: 0,
            section_length: -1,
            hardware: None,
            os: None,
            user_appl: None,
        }
    }
}

/// Interface Description Block data.
#[derive(Debug, Clone)]
pub struct InterfaceDescription {
    /// Link type
    pub link_type: LinkType,
    /// Snapshot length (0 = no limit)
    pub snap_len: u32,
    /// Interface name
    pub name: Option<String>,
    /// Interface description
    pub description: Option<String>,
    /// Timestamp resolution (power of 10 or 2)
    /// Default is 6 (microseconds = 10^-6)
    pub ts_resol: u8,
    /// Whether ts_resol is power of 2 (true) or power of 10 (false)
    pub ts_resol_is_pow2: bool,
}

impl Default for InterfaceDescription {
    fn default() -> Self {
        Self {
            link_type: LinkType::Ethernet,
            snap_len: 0,
            name: None,
            description: None,
            ts_resol: 6, // microseconds
            ts_resol_is_pow2: false,
        }
    }
}

impl InterfaceDescription {
    /// Get timestamp units per second based on resolution.
    pub fn ts_units_per_second(&self) -> u64 {
        if self.ts_resol_is_pow2 {
            1u64 << self.ts_resol
        } else {
            10u64.pow(self.ts_resol as u32)
        }
    }

    /// Convert raw timestamp to nanoseconds.
    pub fn timestamp_to_ns(&self, ts_high: u32, ts_low: u32) -> i64 {
        let ts = ((ts_high as u64) << 32) | (ts_low as u64);
        let units_per_sec = self.ts_units_per_second();

        if units_per_sec >= 1_000_000_000 {
            // Higher than ns precision, divide
            (ts / (units_per_sec / 1_000_000_000)) as i64
        } else {
            // Lower than ns precision, multiply
            (ts * (1_000_000_000 / units_per_sec)) as i64
        }
    }

    /// Convert nanoseconds to raw timestamp.
    pub fn ns_to_timestamp(&self, ns: i64) -> (u32, u32) {
        let units_per_sec = self.ts_units_per_second();
        let ts = if units_per_sec >= 1_000_000_000 {
            (ns as u64) * (units_per_sec / 1_000_000_000)
        } else {
            (ns as u64) / (1_000_000_000 / units_per_sec)
        };
        ((ts >> 32) as u32, ts as u32)
    }
}

/// Reader for pcapng files.
#[derive(Debug)]
pub struct PcapngReader<R: Read> {
    reader: BufReader<R>,
    /// Whether the current section is big-endian
    big_endian: bool,
    /// Section header
    pub section: SectionHeader,
    /// Interface descriptions (indexed by interface ID)
    pub interfaces: Vec<InterfaceDescription>,
}

impl<R: Read> PcapngReader<R> {
    /// Open a pcapng file for reading.
    pub fn open(reader: R) -> CaptureResult<Self> {
        let mut reader = BufReader::new(reader);

        // Read first block type
        let mut buf = [0u8; 4];
        reader.read_exact(&mut buf)?;
        let block_type = u32::from_le_bytes(buf);

        if block_type != block_type::SHB {
            return Err(CaptureError::InvalidMagic(block_type));
        }

        // Read block total length
        reader.read_exact(&mut buf)?;
        let block_len = u32::from_le_bytes(buf);

        // Read byte-order magic
        reader.read_exact(&mut buf)?;
        let magic = u32::from_ne_bytes(buf);

        let big_endian = match magic {
            BYTE_ORDER_MAGIC => false, // Native endian matches LE
            0x4D3C2B1A => true,        // Swapped = BE
            _ => {
                // Try big-endian interpretation
                let magic_be = u32::from_be_bytes(buf);
                if magic_be == BYTE_ORDER_MAGIC {
                    true
                } else {
                    return Err(CaptureError::InvalidMagic(magic));
                }
            }
        };

        // Re-interpret block_len if needed
        let block_len = if big_endian {
            u32::from_be_bytes(block_len.to_le_bytes())
        } else {
            block_len
        };

        // Read version
        let mut ver_buf = [0u8; 4];
        reader.read_exact(&mut ver_buf)?;
        let (version_major, version_minor) = if big_endian {
            (
                u16::from_be_bytes([ver_buf[0], ver_buf[1]]),
                u16::from_be_bytes([ver_buf[2], ver_buf[3]]),
            )
        } else {
            (
                u16::from_le_bytes([ver_buf[0], ver_buf[1]]),
                u16::from_le_bytes([ver_buf[2], ver_buf[3]]),
            )
        };

        // Read section length
        let mut len_buf = [0u8; 8];
        reader.read_exact(&mut len_buf)?;
        let section_length = if big_endian {
            i64::from_be_bytes(len_buf)
        } else {
            i64::from_le_bytes(len_buf)
        };

        // Skip remaining SHB content (options + trailing length)
        // Block structure: type(4) + len(4) + magic(4) + ver(4) + seclen(8) + options + len(4)
        // Already read: 4 + 4 + 4 + 4 + 8 = 24 bytes
        let remaining = block_len as usize - 24 - 4; // -4 for trailing length
        if remaining > 0 {
            let mut skip_buf = vec![0u8; remaining];
            reader.read_exact(&mut skip_buf)?;
            // TODO: Parse SHB options
        }

        // Read trailing block length
        reader.read_exact(&mut buf)?;

        let section = SectionHeader {
            version_major,
            version_minor,
            section_length,
            hardware: None,
            os: None,
            user_appl: None,
        };

        Ok(Self {
            reader,
            big_endian,
            section,
            interfaces: Vec::new(),
        })
    }

    /// Read a u16 with correct endianness.
    fn read_u16(&mut self) -> CaptureResult<u16> {
        let mut buf = [0u8; 2];
        self.reader.read_exact(&mut buf)?;
        Ok(if self.big_endian {
            u16::from_be_bytes(buf)
        } else {
            u16::from_le_bytes(buf)
        })
    }

    /// Read a u32 with correct endianness.
    fn read_u32(&mut self) -> CaptureResult<u32> {
        let mut buf = [0u8; 4];
        self.reader.read_exact(&mut buf)?;
        Ok(if self.big_endian {
            u32::from_be_bytes(buf)
        } else {
            u32::from_le_bytes(buf)
        })
    }

    /// Read the next block, returning packet data if it's a packet block.
    fn read_next_block(&mut self) -> CaptureResult<Option<Packet>> {
        loop {
            // Read block type
            let block_type = match self.read_u32() {
                Ok(t) => t,
                Err(CaptureError::Io(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    return Ok(None);
                }
                Err(e) => return Err(e),
            };

            // Read block length
            let block_len = self.read_u32()?;

            match block_type {
                block_type::SHB => {
                    // New section - skip for now (would need to reset interfaces)
                    self.skip_block_content(block_len, 8)?;
                }
                block_type::IDB => {
                    self.read_idb(block_len)?;
                }
                block_type::EPB => {
                    return self.read_epb(block_len).map(Some);
                }
                block_type::SPB => {
                    return self.read_spb(block_len).map(Some);
                }
                _ => {
                    // Skip unknown block
                    self.skip_block_content(block_len, 8)?;
                }
            }
        }
    }

    /// Skip block content (block_len - already_read - trailing_len).
    fn skip_block_content(&mut self, block_len: u32, already_read: u32) -> CaptureResult<()> {
        let to_skip = block_len - already_read - 4; // -4 for trailing length
        if to_skip > 0 {
            let mut buf = vec![0u8; to_skip as usize];
            self.reader.read_exact(&mut buf)?;
        }
        // Read trailing length
        let mut buf = [0u8; 4];
        self.reader.read_exact(&mut buf)?;
        Ok(())
    }

    /// Read Interface Description Block.
    fn read_idb(&mut self, block_len: u32) -> CaptureResult<()> {
        let link_type = LinkType::from(self.read_u16()? as u32);
        let _reserved = self.read_u16()?;
        let snap_len = self.read_u32()?;

        let mut iface = InterfaceDescription {
            link_type,
            snap_len,
            ..Default::default()
        };

        // Read options
        // Block: type(4) + len(4) + linktype(2) + reserved(2) + snaplen(4) + options + len(4)
        // Already read: 8 + 8 = 16 bytes of content
        let options_len = block_len as usize - 16 - 4;
        if options_len > 0 {
            let mut options_buf = vec![0u8; options_len];
            self.reader.read_exact(&mut options_buf)?;
            self.parse_idb_options(&mut iface, &options_buf);
        }

        // Read trailing length
        let mut buf = [0u8; 4];
        self.reader.read_exact(&mut buf)?;

        self.interfaces.push(iface);
        Ok(())
    }

    /// Parse IDB options.
    fn parse_idb_options(&self, iface: &mut InterfaceDescription, data: &[u8]) {
        let mut pos = 0;
        while pos + 4 <= data.len() {
            let code = if self.big_endian {
                u16::from_be_bytes([data[pos], data[pos + 1]])
            } else {
                u16::from_le_bytes([data[pos], data[pos + 1]])
            };
            let len = if self.big_endian {
                u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize
            } else {
                u16::from_le_bytes([data[pos + 2], data[pos + 3]]) as usize
            };
            pos += 4;

            if code == option_code::END_OF_OPT {
                break;
            }

            if pos + len > data.len() {
                break;
            }

            match code {
                option_code::IF_NAME => {
                    iface.name = String::from_utf8_lossy(&data[pos..pos + len])
                        .trim_end_matches('\0')
                        .to_string()
                        .into();
                }
                option_code::IF_DESCRIPTION => {
                    iface.description = String::from_utf8_lossy(&data[pos..pos + len])
                        .trim_end_matches('\0')
                        .to_string()
                        .into();
                }
                option_code::IF_TSRESOL => {
                    if len >= 1 {
                        let val = data[pos];
                        iface.ts_resol_is_pow2 = (val & 0x80) != 0;
                        iface.ts_resol = val & 0x7F;
                    }
                }
                _ => {}
            }

            // Align to 4 bytes
            pos += (len + 3) & !3;
        }
    }

    /// Read Enhanced Packet Block.
    fn read_epb(&mut self, block_len: u32) -> CaptureResult<Packet> {
        let interface_id = self.read_u32()?;
        let ts_high = self.read_u32()?;
        let ts_low = self.read_u32()?;
        let captured_len = self.read_u32()?;
        let orig_len = self.read_u32()?;

        // Read packet data
        let mut data = vec![0u8; captured_len as usize];
        self.reader.read_exact(&mut data)?;

        // Skip padding to 4-byte alignment
        let padding = (4 - (captured_len % 4)) % 4;
        if padding > 0 {
            let mut pad_buf = vec![0u8; padding as usize];
            self.reader.read_exact(&mut pad_buf)?;
        }

        // Skip options and trailing length
        // Block: type(4) + len(4) + ifid(4) + ts(8) + caplen(4) + origlen(4) + data + pad + opts + len(4)
        // Content read: 20 + data + padding
        let content_read = 20 + captured_len + padding;
        let remaining = block_len - 8 - content_read - 4;
        if remaining > 0 {
            let mut skip_buf = vec![0u8; remaining as usize];
            self.reader.read_exact(&mut skip_buf)?;
            // TODO: Parse EPB options
        }

        // Read trailing length
        let mut buf = [0u8; 4];
        self.reader.read_exact(&mut buf)?;

        // Convert timestamp and get linktype
        let (timestamp_ns, linktype) = if (interface_id as usize) < self.interfaces.len() {
            let iface = &self.interfaces[interface_id as usize];
            (iface.timestamp_to_ns(ts_high, ts_low), iface.link_type)
        } else {
            // Default to microseconds if interface not found
            let ts = ((ts_high as u64) << 32) | (ts_low as u64);
            ((ts * 1000) as i64, LinkType::default())
        };

        Ok(Packet::new(timestamp_ns, orig_len, data)
            .with_interface(interface_id)
            .with_linktype(linktype))
    }

    /// Read Simple Packet Block.
    fn read_spb(&mut self, block_len: u32) -> CaptureResult<Packet> {
        let orig_len = self.read_u32()?;

        // SPB captured length is min(orig_len, snaplen) but we calculate from block size
        // Block: type(4) + len(4) + origlen(4) + data + pad + len(4)
        let data_and_pad = block_len - 16;
        let captured_len = std::cmp::min(orig_len, data_and_pad);

        let mut data = vec![0u8; captured_len as usize];
        self.reader.read_exact(&mut data)?;

        // Skip remaining (padding)
        let remaining = data_and_pad - captured_len;
        if remaining > 0 {
            let mut skip_buf = vec![0u8; remaining as usize];
            self.reader.read_exact(&mut skip_buf)?;
        }

        // Read trailing length
        let mut buf = [0u8; 4];
        self.reader.read_exact(&mut buf)?;

        // SPB uses interface 0 by default, no timestamp
        let linktype = self.interfaces.first().map(|i| i.link_type).unwrap_or_default();

        Ok(Packet::new(0, orig_len, data).with_linktype(linktype))
    }

    /// Get the primary link type (from first interface).
    pub fn linktype(&self) -> LinkType {
        self.interfaces
            .first()
            .map(|i| i.link_type)
            .unwrap_or_default()
    }

    /// Get the snapshot length (from first interface).
    pub fn snaplen(&self) -> u32 {
        self.interfaces
            .first()
            .map(|i| {
                if i.snap_len == 0 {
                    u32::MAX
                } else {
                    i.snap_len
                }
            })
            .unwrap_or(u32::MAX)
    }
}

impl<R: Read> Iterator for PcapngReader<R> {
    type Item = CaptureResult<Packet>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.read_next_block() {
            Ok(Some(pkt)) => Some(Ok(pkt)),
            Ok(None) => None,
            Err(e) => Some(Err(e)),
        }
    }
}

impl<R: Read> CaptureReader for PcapngReader<R> {
    fn linktype(&self) -> LinkType {
        self.linktype()
    }

    fn snaplen(&self) -> u32 {
        self.snaplen()
    }

    fn is_nanosecond_precision(&self) -> bool {
        // Check if any interface has nanosecond precision
        self.interfaces.iter().any(|i| {
            if i.ts_resol_is_pow2 {
                i.ts_resol >= 30 // 2^30 > 10^9
            } else {
                i.ts_resol >= 9 // 10^9 = nanoseconds
            }
        })
    }
}

/// Writer for pcapng files.
#[derive(Debug)]
pub struct PcapngWriter<W: Write> {
    writer: BufWriter<W>,
    /// Interfaces that have been written
    interfaces: Vec<InterfaceDescription>,
}

impl<W: Write> PcapngWriter<W> {
    /// Create a new pcapng writer with default section header.
    pub fn new(writer: W, linktype: LinkType, snaplen: u32) -> CaptureResult<Self> {
        let mut writer = BufWriter::new(writer);

        // Write Section Header Block
        Self::write_shb(&mut writer, None)?;

        // Write Interface Description Block
        let iface = InterfaceDescription {
            link_type: linktype,
            snap_len: snaplen,
            ts_resol: 9, // nanoseconds
            ts_resol_is_pow2: false,
            ..Default::default()
        };
        Self::write_idb(&mut writer, &iface)?;

        Ok(Self {
            writer,
            interfaces: vec![iface],
        })
    }

    /// Write Section Header Block.
    fn write_shb<WW: Write>(writer: &mut WW, section: Option<&SectionHeader>) -> CaptureResult<()> {
        let section = section.cloned().unwrap_or_default();

        // Calculate block length (no options for now)
        let block_len: u32 = 28; // type(4) + len(4) + magic(4) + ver(4) + seclen(8) + len(4)

        let mut buf = Vec::with_capacity(block_len as usize);
        buf.extend_from_slice(&block_type::SHB.to_le_bytes());
        buf.extend_from_slice(&block_len.to_le_bytes());
        buf.extend_from_slice(&BYTE_ORDER_MAGIC.to_le_bytes());
        buf.extend_from_slice(&section.version_major.to_le_bytes());
        buf.extend_from_slice(&section.version_minor.to_le_bytes());
        buf.extend_from_slice(&section.section_length.to_le_bytes());
        buf.extend_from_slice(&block_len.to_le_bytes());

        writer.write_all(&buf)?;
        Ok(())
    }

    /// Write Interface Description Block.
    fn write_idb<WW: Write>(writer: &mut WW, iface: &InterfaceDescription) -> CaptureResult<()> {
        // Options: if_tsresol
        let tsresol_opt = [
            option_code::IF_TSRESOL.to_le_bytes()[0],
            option_code::IF_TSRESOL.to_le_bytes()[1],
            1,
            0, // length = 1
            if iface.ts_resol_is_pow2 {
                0x80 | iface.ts_resol
            } else {
                iface.ts_resol
            },
            0,
            0,
            0, // padding to 4 bytes
        ];
        let end_opt = [0u8; 4]; // opt_endofopt

        let options_len = tsresol_opt.len() + end_opt.len();
        let block_len: u32 = (20 + options_len) as u32; // type(4) + len(4) + lt(2) + res(2) + snap(4) + opts + len(4)

        let mut buf = Vec::with_capacity(block_len as usize);
        buf.extend_from_slice(&block_type::IDB.to_le_bytes());
        buf.extend_from_slice(&block_len.to_le_bytes());
        buf.extend_from_slice(&(iface.link_type.as_u32() as u16).to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes()); // reserved
        buf.extend_from_slice(&iface.snap_len.to_le_bytes());
        buf.extend_from_slice(&tsresol_opt);
        buf.extend_from_slice(&end_opt);
        buf.extend_from_slice(&block_len.to_le_bytes());

        writer.write_all(&buf)?;
        Ok(())
    }

    /// Write Enhanced Packet Block.
    fn write_epb(&mut self, packet: &Packet) -> CaptureResult<()> {
        let interface_id = packet.interface_id;
        let iface = self
            .interfaces
            .get(interface_id as usize)
            .ok_or(CaptureError::UnknownInterface(interface_id))?;

        let (ts_high, ts_low) = iface.ns_to_timestamp(packet.timestamp_ns);
        let captured_len = packet.data.len() as u32;
        let orig_len = packet.orig_len;

        // Padding to 4-byte alignment
        let padding = (4 - (captured_len % 4)) % 4;

        // Block length
        let block_len: u32 = 32 + captured_len + padding; // type(4) + len(4) + ifid(4) + ts(8) + caplen(4) + origlen(4) + data + pad + len(4)

        let mut buf = Vec::with_capacity(block_len as usize);
        buf.extend_from_slice(&block_type::EPB.to_le_bytes());
        buf.extend_from_slice(&block_len.to_le_bytes());
        buf.extend_from_slice(&interface_id.to_le_bytes());
        buf.extend_from_slice(&ts_high.to_le_bytes());
        buf.extend_from_slice(&ts_low.to_le_bytes());
        buf.extend_from_slice(&captured_len.to_le_bytes());
        buf.extend_from_slice(&orig_len.to_le_bytes());
        buf.extend_from_slice(&packet.data);
        buf.extend_from_slice(&vec![0u8; padding as usize]);
        buf.extend_from_slice(&block_len.to_le_bytes());

        self.writer.write_all(&buf)?;
        Ok(())
    }

    /// Flush the writer.
    pub fn flush(&mut self) -> CaptureResult<()> {
        self.writer.flush()?;
        Ok(())
    }

    /// Get the primary link type.
    pub fn linktype(&self) -> LinkType {
        self.interfaces
            .first()
            .map(|i| i.link_type)
            .unwrap_or_default()
    }

    /// Get the snapshot length.
    pub fn snaplen(&self) -> u32 {
        self.interfaces.first().map(|i| i.snap_len).unwrap_or(0)
    }
}

impl<W: Write> CaptureWriter for PcapngWriter<W> {
    fn write_packet(&mut self, packet: &Packet) -> CaptureResult<()> {
        self.write_epb(packet)
    }

    fn flush(&mut self) -> CaptureResult<()> {
        self.writer.flush()?;
        Ok(())
    }

    fn linktype(&self) -> LinkType {
        self.linktype()
    }

    fn snaplen(&self) -> u32 {
        self.snaplen()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_write_and_read_pcapng() {
        let mut buffer = Vec::new();

        // Write
        {
            let mut writer = PcapngWriter::new(&mut buffer, LinkType::Ethernet, 65535).unwrap();

            let packet = Packet::new(1_500_000_000_000, 100, vec![0u8; 100]); // 1500 seconds in ns
            CaptureWriter::write_packet(&mut writer, &packet).unwrap();
            writer.flush().unwrap();
        }

        // Read
        let cursor = Cursor::new(buffer);
        let mut reader = PcapngReader::open(cursor).unwrap();

        // Read first packet - this will also read the IDB
        let packet = reader.next().unwrap().unwrap();

        // Now interfaces should be populated
        assert_eq!(reader.interfaces.len(), 1);
        assert_eq!(reader.linktype(), LinkType::Ethernet);

        assert_eq!(packet.data.len(), 100);
        assert_eq!(packet.orig_len, 100);
        assert_eq!(packet.linktype, Some(LinkType::Ethernet));
        // Timestamp should be preserved (within rounding)
        assert!((packet.timestamp_ns - 1_500_000_000_000).abs() < 1000);
    }

    #[test]
    fn test_interface_timestamp_conversion() {
        // Microsecond resolution (default)
        let iface = InterfaceDescription::default();
        assert_eq!(iface.ts_units_per_second(), 1_000_000);

        let (hi, lo) = iface.ns_to_timestamp(1_500_000_000); // 1.5 seconds
        let ns = iface.timestamp_to_ns(hi, lo);
        assert_eq!(ns, 1_500_000_000);

        // Nanosecond resolution
        let iface_ns = InterfaceDescription {
            ts_resol: 9,
            ts_resol_is_pow2: false,
            ..Default::default()
        };
        assert_eq!(iface_ns.ts_units_per_second(), 1_000_000_000);

        let (hi, lo) = iface_ns.ns_to_timestamp(1_500_000_001);
        let ns = iface_ns.timestamp_to_ns(hi, lo);
        assert_eq!(ns, 1_500_000_001);
    }

    #[test]
    fn test_section_header() {
        let mut buffer = Vec::new();

        {
            let _writer = PcapngWriter::new(&mut buffer, LinkType::Ethernet, 65535).unwrap();
        }

        let cursor = Cursor::new(buffer);
        let reader = PcapngReader::open(cursor).unwrap();

        assert_eq!(reader.section.version_major, 1);
        assert_eq!(reader.section.version_minor, 0);
    }
}
