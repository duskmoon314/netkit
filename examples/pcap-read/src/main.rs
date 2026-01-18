use std::path::PathBuf;

use clap::Parser;
// use netkit::capture::format::pcap::PcapReader;
use netkit::capture::{from_reader, CaptureReader};

#[derive(Debug, Parser)]
struct Args {
    pcap_file: PathBuf,

    #[clap(long, default_value_t)]
    payload: bool,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let file = std::fs::File::open(&args.pcap_file)?;

    let reader = from_reader(file)?;

    println!(
        "Reading {} file: {:?} snaplen: {}",
        reader.format(),
        args.pcap_file,
        reader.snaplen()
    );

    for packet in reader {
        let packet = packet?;

        println!(
            "Pkt (ts: {}, orig len: {}, cap len: {}, linktype: {})",
            packet.timestamp_ns,
            packet.orig_len,
            packet.data.len(),
            packet.linktype
        );

        if args.payload {
            println!("  Payload: {:02X?}", packet.data);
        }
    }

    Ok(())
}
