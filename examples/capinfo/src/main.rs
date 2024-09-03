use std::path::PathBuf;

use clap::{Args, Parser, ValueEnum};
use netkit::capture::file::pcap::PcapReader;
// use netkit::packet::layer::eth::eth_type;
// use netkit::packet::layer::eth::EthPayload;
// use netkit::packet::layer::ip::IpPayload;
use netkit::packet::prelude::*;
use polars::prelude::*;

/// Capinfo (netkit)
///
/// An alternative to well-known wireshark's capinfos tool.
///
/// Print information about capture files.
#[derive(Debug, Parser)]
#[command(about, long_about)]
struct Cli {
    infiles: Vec<PathBuf>,

    #[command(flatten)]
    flags: Flags,
}

#[derive(Debug, Args)]
struct Flags {
    /// Whether dump the inner table of all packets
    #[arg(long, value_enum)]
    dump: Option<DumpFormat>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum DumpFormat {
    Csv,
    Json,
    Parquet,
}

fn main() -> anyhow::Result<()> {
    let args = Cli::parse();

    println!("Args: {args:?}");

    for file in args.infiles {
        info(file, &args.flags)?
    }

    Ok(())
}

fn info(file_path: PathBuf, args: &Flags) -> anyhow::Result<()> {
    let file = std::fs::File::open(file_path.clone())?;
    let reader = PcapReader::new(file);

    let start = std::time::Instant::now();

    let mut timestamp = Vec::new();
    let mut length = Vec::new();
    let mut eth_type: Vec<u16> = Vec::new();
    let mut src_ip4 = Vec::new();
    let mut dst_ip4 = Vec::new();
    let mut ip_proto = Vec::new();
    let mut src_port = Vec::new();
    let mut dst_port = Vec::new();
    let mut tcp_flags = Vec::new();

    let mut meta = 0;

    reader.for_each(|(hdr, data)| {
        let eth = match Eth::new(data) {
            Ok(eth) => eth,
            Err(_err) => {
                // eprintln!("Error: {:?}", e);
                return;
            }
        };

        if eth.ipv4().is_none() {
            return;
        }

        timestamp.push(hdr.ts_sec as i64 * 1_000_000_000 + hdr.ts_usec as i64 * 1_000);
        length.push(hdr.orig_len);
        eth_type.push(eth.eth_type().get().into());

        if let Some(ip) = eth.ipv4() {
            src_ip4.push(ip.src().get().into());
            dst_ip4.push(ip.dst().get().into());
            ip_proto.push(ip.protocol().get().into());

            if let Some(tcp) = ip.tcp() {
                src_port.push(tcp.src_port().get());
                dst_port.push(tcp.dst_port().get());
                tcp_flags.push(tcp.flags().raw());
            } else if let Some(udp) = ip.udp() {
                src_port.push(udp.src_port().get());
                dst_port.push(udp.dst_port().get());
                tcp_flags.push(0);
            } else {
                src_port.push(0);
                dst_port.push(0);
                tcp_flags.push(0);
            }
        } else {
            src_ip4.push(0);
            dst_ip4.push(0);
            ip_proto.push(0);

            src_port.push(0);
            dst_port.push(0);
            tcp_flags.push(0);
        }

        meta += 1;
    });

    println!("Total packets: {}", meta);

    let mut df = DataFrame::new(vec![
        Series::from_vec("timestamp", timestamp),
        Series::from_vec("length", length),
        Series::from_vec("eth_type", eth_type),
        Series::from_vec("src_ip4", src_ip4),
        Series::from_vec("dst_ip4", dst_ip4),
        Series::from_vec("ip_proto", ip_proto),
        Series::from_vec("src_port", src_port),
        Series::from_vec("dst_port", dst_port),
        Series::from_vec("tcp_flags", tcp_flags),
    ])?;

    df.sort_in_place(["timestamp"], Default::default())?;

    let elapsed = start.elapsed();

    let total_packets = df.height();
    let total_bytes = df.column("length").unwrap().sum::<u32>().unwrap();

    println!("Total packets: {}", total_packets);
    println!("Total bytes: {}", total_bytes);

    println!("Elapsed: {:?}", elapsed);

    if args.dump.is_some() {
        let start = std::time::Instant::now();

        match args.dump.unwrap() {
            DumpFormat::Csv => {
                let dump_path = file_path.with_extension("csv");

                println!("The inner table is dumping to CSV file: {:?}", dump_path);

                let mut writer = std::fs::File::create(dump_path)?;
                let mut writer = CsvWriter::new(&mut writer);
                writer.finish(&mut df)?;
            }
            DumpFormat::Json => {
                let dump_path = file_path.with_extension("json");

                println!("The inner table is dumping to JSON file: {:?}", dump_path);

                let mut writer = std::fs::File::create(dump_path)?;
                let mut writer = JsonWriter::new(&mut writer);
                writer.finish(&mut df)?;
            }
            DumpFormat::Parquet => {
                let dump_path = file_path.with_extension("parquet");

                println!(
                    "The inner table is dumping to parquet file: {:?}",
                    dump_path
                );

                let mut writer = std::fs::File::create(&dump_path)?;
                let writer = ParquetWriter::new(&mut writer);
                let writer = writer.with_row_group_size(Some(1024));
                let size = writer.finish(&mut df)?;

                println!("Dumped {size} bytes to {dump_path:?}");
            }
        }

        let elapsed = start.elapsed();
        println!("Elapsed: {:?}", elapsed);
    }

    Ok(())
}
