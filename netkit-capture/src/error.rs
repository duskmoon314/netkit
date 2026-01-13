//! Error types for capture file operations.

use std::io;

/// Errors that can occur when reading or writing capture files.
#[derive(Debug, thiserror::Error)]
pub enum CaptureError {
    /// I/O error from underlying reader/writer.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    /// Invalid or unrecognized magic number in file header.
    #[error("invalid magic number: {0:#010X}")]
    InvalidMagic(u32),

    /// Unsupported or unknown link type.
    #[error("unsupported link type: {0}")]
    UnsupportedLinkType(u32),

    /// Packet data is truncated or incomplete.
    #[error("truncated packet: expected {expected} bytes. {msg}")]
    TruncatedPacket { expected: usize, msg: String },

    /// Invalid block in pcapng file.
    #[error("invalid block: {0}")]
    InvalidBlock(String),

    /// Unsupported capture file format.
    #[error("unsupported format: {0}")]
    UnsupportedFormat(String),

    /// Invalid or corrupted file structure.
    #[error("corrupted file: {0}")]
    CorruptedFile(String),

    /// Interface ID not found (pcapng).
    #[error("unknown interface ID: {0}")]
    UnknownInterface(u32),

    /// Timestamp conversion error.
    #[error("timestamp error: {0}")]
    TimestampError(String),
}

/// Result type alias for capture operations.
pub type CaptureResult<T> = Result<T, CaptureError>;
