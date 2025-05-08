use std::path::PathBuf;

use clap::Parser;
use netkit::capture::file::pcap::PcapReader;
use netkit::packet::prelude::*;

#[derive(Debug, Parser)]
struct Args {
    pcap_file: PathBuf,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    println!("Reading pcap file: {:?}", args.pcap_file);

    let file = std::fs::File::open(&args.pcap_file)?;

    let reader = PcapReader::new(file);

    println!("Global header: {:#x?}", reader.header);

    for (hdr, data) in reader {
        println!("Packet: {:?}", hdr);

        let packet = Eth::new(data).unwrap();
        println!("Packet: {:?}", packet);
    }

    Ok(())
}
