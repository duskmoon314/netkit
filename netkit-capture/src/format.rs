//! Capture file format implementations.
//!
//! This module provides readers and writers for various capture file formats:
//!
//! - [`pcap`] - Classic pcap format (libpcap)
//! - [`pcapng`] - Next-generation pcap format
//! - [`auto`] - Automatic format detection

pub mod auto;
pub mod pcap;
pub mod pcapng;

pub use auto::{open_capture, open_file, CaptureFile, CaptureFormat};
pub use pcap::{PcapHeader, PcapPacketHeader, PcapReader, PcapWriter};
pub use pcapng::{PcapngReader, PcapngWriter};
