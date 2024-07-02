use std::io::{BufReader, Read};

// use deku::prelude::*;

#[derive(Debug)]
pub struct PcapReader<R: Read> {
    pub header: PcapHeader,

    pub big_endian: bool,

    reader: BufReader<R>,
}

impl<R: Read> PcapReader<R> {
    pub fn new(reader: R) -> Self {
        let mut reader = BufReader::new(reader);

        let mut magic_number: [u8; 4] = [0; 4];
        reader.read_exact(&mut magic_number).unwrap();

        let big_endian = if magic_number[0] == 0xa1 {
            true
        } else if magic_number[3] == 0xa1 {
            false
        } else {
            panic!("Invalid magic number: {:?}", magic_number);
        };

        let mut buffer: [u8; 20] = [0; 20];
        reader.read_exact(&mut buffer).unwrap();

        let header = if big_endian {
            PcapHeader {
                magic_number: u32::from_be_bytes(magic_number),
                version_major: u16::from_be_bytes([buffer[0], buffer[1]]),
                version_minor: u16::from_be_bytes([buffer[2], buffer[3]]),
                thiszone: i32::from_be_bytes([buffer[4], buffer[5], buffer[6], buffer[7]]),
                sigfigs: u32::from_be_bytes([buffer[8], buffer[9], buffer[10], buffer[11]]),
                snaplen: u32::from_be_bytes([buffer[12], buffer[13], buffer[14], buffer[15]]),
                network: u32::from_be_bytes([buffer[16], buffer[17], buffer[18], buffer[19]]),
            }
        } else {
            PcapHeader {
                magic_number: u32::from_le_bytes(magic_number),
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

        // Read incl_len bytes
        let mut data = vec![0; header.incl_len as usize];
        self.reader.read_exact(&mut data).unwrap();

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
    pub magic_number: u32,
    pub version_major: u16,
    pub version_minor: u16,
    pub thiszone: i32,
    pub sigfigs: u32,
    pub snaplen: u32,
    pub network: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketHeader {
    pub ts_sec: u32,
    pub ts_usec: u32,
    pub incl_len: u32,
    pub orig_len: u32,
}
