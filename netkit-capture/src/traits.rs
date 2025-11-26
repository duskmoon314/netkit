//! Traits for reading and writing capture files.

use crate::error::CaptureResult;
use crate::linktype::LinkType;
use crate::packet::Packet;

/// A reader for capture files.
///
/// This trait provides a common interface for reading packets from any
/// capture format (pcap, pcapng, etc.). Implementations should handle
/// format-specific details and present a unified `Packet` type.
///
/// # Example
///
/// ```ignore
/// fn process_capture(reader: impl CaptureReader) -> CaptureResult<u64> {
///     println!("Link type: {:?}", reader.linktype());
///     println!("Snaplen: {}", reader.snaplen());
///     
///     let mut count = 0;
///     for packet in reader {
///         let pkt = packet?;
///         count += 1;
///     }
///     Ok(count)
/// }
/// ```
pub trait CaptureReader: Iterator<Item = CaptureResult<Packet>> {
    /// Get the primary link type of the capture.
    ///
    /// For pcapng with multiple interfaces, this returns the link type
    /// of the first interface.
    fn linktype(&self) -> LinkType;

    /// Get the snapshot length (maximum captured bytes per packet).
    fn snaplen(&self) -> u32;

    /// Check if timestamps have nanosecond resolution.
    ///
    /// Returns `true` for pcap-ng (always nanoseconds) and pcap files
    /// with the nanosecond magic number.
    fn is_nanosecond_precision(&self) -> bool;
}

/// A writer for capture files.
///
/// This trait provides a common interface for writing packets to any
/// capture format. Implementations handle format-specific encoding.
///
/// # Example
///
/// ```ignore
/// fn write_packets(
///     mut writer: impl CaptureWriter,
///     packets: &[Packet],
/// ) -> CaptureResult<()> {
///     for pkt in packets {
///         writer.write_packet(pkt)?;
///     }
///     writer.flush()?;
///     Ok(())
/// }
/// ```
pub trait CaptureWriter {
    /// Write a packet to the capture file.
    ///
    /// The packet will be converted to the appropriate format.
    /// Timestamps are converted based on the writer's precision setting.
    fn write_packet(&mut self, packet: &Packet) -> CaptureResult<()>;

    /// Flush any buffered data to the underlying writer.
    fn flush(&mut self) -> CaptureResult<()>;

    /// Get the link type being written.
    fn linktype(&self) -> LinkType;

    /// Get the snapshot length.
    fn snaplen(&self) -> u32;
}

/// Extension trait for converting between capture formats.
///
/// This is automatically implemented for any type that implements
/// `CaptureReader`.
pub trait CaptureReaderExt: CaptureReader + Sized {
    /// Write all packets to a writer, converting formats if necessary.
    ///
    /// Returns the number of packets written.
    fn write_to<W: CaptureWriter>(self, writer: &mut W) -> CaptureResult<u64> {
        let mut count = 0;
        for packet in self {
            writer.write_packet(&packet?)?;
            count += 1;
        }
        writer.flush()?;
        Ok(count)
    }

    /// Collect all packets into a vector.
    fn collect_packets(self) -> CaptureResult<Vec<Packet>> {
        self.collect()
    }
}

impl<T: CaptureReader> CaptureReaderExt for T {}
