use std::{net::Ipv4Addr, path::PathBuf};

use clap::Parser;
use netkit::capture::LinkType;
use netkit::capture::format::pcap::{PcapPacketHeader, PcapWriter};
use netkit::packet::prelude::*;

#[derive(Debug, Parser)]
struct Cli {
    /// The path to the output file
    output: PathBuf,
}

fn main() -> anyhow::Result<()> {
    let args = Cli::parse();

    let mut output_file = std::fs::File::create(args.output)?;
    let mut writer = PcapWriter::new_be(&mut output_file, 65535, LinkType::Ethernet)?;

    let pkt = eth!(
        dst: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06],
        src: [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC],
        eth_type: EthType::Ipv4,
        payload: ipv4!(
            src: Ipv4Addr::new(10, 1, 1, 1),
            dst: Ipv4Addr::new(10, 2, 2, 2),
            protocol: IpProtocol::Udp,
            payload: udp!(
                src_port: 1234u16,
                dst_port: 80u16,
                length: 10u16,
                checksum: 0u16,
                payload: [0x01, 0x02]
            )
        )
    );

    let len = pkt.inner().len() as u32;

    for i in 0..10 {
        let hdr = PcapPacketHeader {
            ts_sec: i,
            ts_usec: 0,
            incl_len: len,
            orig_len: len,
        };

        writer.write_packet_raw(hdr, &pkt)?;
    }

    writer.flush()?;

    Ok(())
}
