use std::{
    cmp::min,
    io::{BufReader, Read},
};

// use deku::prelude::*;

#[derive(Debug)]
pub struct PcapReader<R: Read> {
    pub header: PcapHeader,

    pub big_endian: bool,

    pub nano_seconds: bool,

    reader: BufReader<R>,
}

impl<R: Read> PcapReader<R> {
    pub fn new(reader: R) -> Self {
        let mut reader = BufReader::new(reader);

        let mut magic_number: [u8; 4] = [0; 4];
        reader.read_exact(&mut magic_number).unwrap();

        let magic_number = u32::from_be_bytes(magic_number);

        let (big_endian, nano_seconds) = match magic_number {
            0xA1B2C3D4 => (true, false),
            0xA1B23C4D => (true, true),
            0xD4C3B2A1 => (false, false),
            0x4D3CB2A1 => (false, true),
            _ => panic!("Invalid magic number: {:#X}", magic_number),
        };

        let mut buffer: [u8; 20] = [0; 20];
        reader.read_exact(&mut buffer).unwrap();

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
                magic_number: u32::from_be(magic_number),
                version_major: u16::from_le_bytes([buffer[0], buffer[1]]),
                version_minor: u16::from_le_bytes([buffer[2], buffer[3]]),
                thiszone: i32::from_le_bytes([buffer[4], buffer[5], buffer[6], buffer[7]]),
                sigfigs: u32::from_le_bytes([buffer[8], buffer[9], buffer[10], buffer[11]]),
                snaplen: u32::from_le_bytes([buffer[12], buffer[13], buffer[14], buffer[15]]),
                network: u32::from_le_bytes([buffer[16], buffer[17], buffer[18], buffer[19]]),
            }
        };

        Self {
            header,
            big_endian,
            nano_seconds,
            reader,
        }
    }

    pub fn next_packet(&mut self) -> Option<(PacketHeader, Vec<u8>)> {
        let mut buffer: [u8; 16] = [0; 16];
        match self.reader.read_exact(&mut buffer) {
            Ok(_) => (),
            Err(_) => return None,
        }

        let header = if self.big_endian {
            PacketHeader {
                ts_sec: u32::from_be_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]),
                ts_usec: u32::from_be_bytes([buffer[4], buffer[5], buffer[6], buffer[7]]),
                incl_len: u32::from_be_bytes([buffer[8], buffer[9], buffer[10], buffer[11]]),
                orig_len: u32::from_be_bytes([buffer[12], buffer[13], buffer[14], buffer[15]]),
            }
        } else {
            PacketHeader {
                ts_sec: u32::from_le_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]),
                ts_usec: u32::from_le_bytes([buffer[4], buffer[5], buffer[6], buffer[7]]),
                incl_len: u32::from_le_bytes([buffer[8], buffer[9], buffer[10], buffer[11]]),
                orig_len: u32::from_le_bytes([buffer[12], buffer[13], buffer[14], buffer[15]]),
            }
        };

        // Read bytes
        let data_len = min(header.incl_len, self.header.snaplen) as usize;
        let mut data = vec![0; data_len];
        self.reader.read_exact(&mut data).unwrap_or_else(|_| {
            panic!(
                "Failed to read {} bytes (orig_len: {}, snaplen: {})",
                header.incl_len, header.orig_len, self.header.snaplen
            );
        });

        Some((header, data))
    }
}

impl<R: Read> Iterator for PcapReader<R> {
    type Item = (PacketHeader, Vec<u8>);

    fn next(&mut self) -> Option<Self::Item> {
        self.next_packet()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PcapHeader {
    /// Magic number, used to detect the file format and byte ordering
    pub magic_number: u32,

    /// Major version number
    pub version_major: u16,

    /// Minor version number
    pub version_minor: u16,

    /// GMT to local correction
    pub thiszone: i32,

    /// Accuracy of timestamps
    ///
    /// Wireshark says this is always 0 in all tools
    pub sigfigs: u32,

    /// Snapshot length
    pub snaplen: u32,

    /// Data link type
    pub network: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketHeader {
    /// Timestamp seconds
    pub ts_sec: u32,

    /// Timestamp microseconds (or nanoseconds)
    pub ts_usec: u32,

    /// Number of bytes of packet saved in file
    pub incl_len: u32,

    /// Actual length of packet
    pub orig_len: u32,
}
