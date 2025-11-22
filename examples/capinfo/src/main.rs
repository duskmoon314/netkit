use std::path::PathBuf;
use std::time::Duration;

use clap::{Args, Parser, ValueEnum};
use log::{debug, error};
use netkit::capture::file::pcap::PcapReader;
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

    /// The batch size for dumping the inner table
    #[arg(long, default_value_t = 1000000)]
    dump_batch: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum DumpFormat {
    Csv,
    Parquet,
}

fn main() -> anyhow::Result<()> {
    let logger = env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .parse_default_env()
        .build();
    let level = logger.filter();

    let multi = indicatif::MultiProgress::new();
    indicatif_log_bridge::LogWrapper::new(multi.clone(), logger).try_init()?;
    log::set_max_level(level);

    let args = Cli::parse();

    debug!("Args: {args:?}");

    for file in args.infiles {
        info(file, &args.flags, &multi)?
    }

    Ok(())
}

fn info(file_path: PathBuf, args: &Flags, multi: &indicatif::MultiProgress) -> anyhow::Result<()> {
    let file = std::fs::File::open(file_path.clone())?;
    let reader = PcapReader::new(file);

    debug!("Pcap header: {:X?}", reader.header);

    let nanoseconds = reader.nanoseconds;
    let time_scale = if nanoseconds { 1_000_000_000 } else { 1_000_000 };
    debug!("Timestamp precision: {}", if nanoseconds { "nanoseconds" } else { "microseconds" });

    let pg = multi
        .add(indicatif::ProgressBar::no_length().with_finish(indicatif::ProgressFinish::Abandon));
    pg.set_style(indicatif::ProgressStyle::with_template(
        "[{elapsed_precise}] {human_pos:>12} pkts    {msg}",
    )?);
    pg.set_message(file_path.display().to_string());
    pg.enable_steady_tick(Duration::from_secs(1));

    let start = std::time::Instant::now();

    let mut reader = pg.wrap_iter(reader);
    let tmp_dir = tempfile::Builder::new()
        .prefix("netkit-capinfo-")
        .tempdir()?;
    debug!("Created temporary directory: {:?}", tmp_dir.path());

    {
        // for _ in 0..args.dump_batch {
        let mut timestamp = Vec::new();
        let mut length = Vec::new();
        let mut eth_type: Vec<u16> = Vec::new();
        let mut src_ip4 = Vec::new();
        let mut dst_ip4 = Vec::new();
        let mut ip_proto = Vec::new();
        let mut tos = Vec::new();
        let mut src_port = Vec::new();
        let mut dst_port = Vec::new();
        let mut tcp_flags = Vec::new();
        let mut tcp_window = Vec::new();
        let mut tcp_data_offset = Vec::new();
        let mut total_length = Vec::new();
        let mut ttl = Vec::new();
        let mut udp_length = Vec::new();

        let mut i = 0;

        for (idx, (hdr, data)) in reader.by_ref().enumerate() {
            if idx % args.dump_batch == args.dump_batch - 1 {
                let mut df = df!(
                    "timestamp" => timestamp.clone(),
                    "length" => length.clone(),
                    "eth_type" => eth_type.clone(),
                    "src_ip4" => src_ip4.clone(),
                    "dst_ip4" => dst_ip4.clone(),
                    "ip_proto" => ip_proto.clone(),
                    "tos" => tos.clone(),
                    "src_port" => src_port.clone(),
                    "dst_port" => dst_port.clone(),
                    "tcp_flags" => tcp_flags.clone(),
                    "tcp_window" => tcp_window.clone(),
                    "tcp_data_offset" => tcp_data_offset.clone(),
                    "total_length" => total_length.clone(),
                    "ttl" => ttl.clone(),
                    "udp_length" => udp_length.clone()
                )?;

                i = idx / args.dump_batch;

                let tmp_file = tmp_dir.path().join(format!("batch_{i}.parquet"));
                let writer = std::fs::File::create(&tmp_file)?;
                let writer = ParquetWriter::new(writer);

                writer.finish(&mut df)?;

                timestamp.clear();
                length.clear();
                eth_type.clear();
                src_ip4.clear();
                dst_ip4.clear();
                ip_proto.clear();
                tos.clear();
                src_port.clear();
                dst_port.clear();
                tcp_flags.clear();
                tcp_window.clear();
                tcp_data_offset.clear();
                total_length.clear();
                ttl.clear();
                udp_length.clear();
            }

            let eth = match Eth::new(data) {
                Ok(eth) => eth,
                Err(err) => {
                    error!("Error parsing Ethernet frame: {:?}", err);
                    continue;
                }
            };

            if let Some(ip) = eth.ipv4() {
                let ts = hdr.ts_sec as i64 * time_scale + hdr.ts_usec as i64;
                timestamp.push(ts);
                length.push(hdr.orig_len);
                eth_type.push(eth.eth_type().get().into());

                let src_addr: u32 = ip.src().get().into();
                let dst_addr: u32 = ip.dst().get().into();
                let protocol: u8 = ip.protocol().get().into();
                let len = ip.total_length().get();

                src_ip4.push(src_addr);
                dst_ip4.push(dst_addr);
                ip_proto.push(protocol);
                tos.push(ip.tos().get());
                total_length.push(len);
                ttl.push(ip.ttl().get());

                if let Some(tcp) = ip.tcp() {
                    src_port.push(tcp.src_port().get());
                    dst_port.push(tcp.dst_port().get());
                    tcp_flags.push(tcp.flags().raw());
                    tcp_window.push(tcp.window_size().get());
                    tcp_data_offset.push(tcp.data_offset().get());
                    udp_length.push(0);
                } else if let Some(udp) = ip.udp() {
                    src_port.push(udp.src_port().get());
                    dst_port.push(udp.dst_port().get());
                    tcp_flags.push(0);
                    tcp_window.push(0);
                    tcp_data_offset.push(0);
                    udp_length.push(udp.length().get());
                } else {
                    src_port.push(0);
                    dst_port.push(0);
                    tcp_flags.push(0);
                    tcp_window.push(0);
                    tcp_data_offset.push(0);
                    udp_length.push(0);
                }
            } else {
                debug!("No IPv4 packet found, skipping");
                continue;
            }
        }

        let mut df = df!(
            "timestamp" => timestamp,
            "length" => length,
            "eth_type" => eth_type,
            "src_ip4" => src_ip4,
            "dst_ip4" => dst_ip4,
            "ip_proto" => ip_proto,
            "tos" => tos,
            "src_port" => src_port,
            "dst_port" => dst_port,
            "tcp_flags" => tcp_flags,
            "tcp_window" => tcp_window,
            "tcp_data_offset" => tcp_data_offset,
            "total_length" => total_length,
            "ttl" => ttl,
            "udp_length" => udp_length
        )?;

        let tmp_file = tmp_dir.path().join(format!("batch_{}.parquet", i + 1));
        let writer = std::fs::File::create(&tmp_file)?;
        let writer = ParquetWriter::new(writer);

        writer.finish(&mut df)?;
    }

    let mut files = tmp_dir
        .path()
        .read_dir()?
        .into_iter()
        .filter_map(|entry| entry.ok().and_then(|e| Some(e.path())))
        .collect::<Vec<_>>();
    files.sort();

    println!("Elapsed: {:?}", start.elapsed());

    let lf = LazyFrame::scan_parquet_files(
        Arc::from(files.into_boxed_slice()),
        ScanArgsParquet {
            low_memory: true,
            ..Default::default()
        },
    )?;
    // .sort(["timestamp"], Default::default());

    if let Some(dump_format) = args.dump {
        match dump_format {
            DumpFormat::Csv => {
                let dump_path = file_path.with_extension("csv");
                debug!("Dumping to CSV file: {:?}", dump_path);

                let lf_dump = lf.sink_csv(
                    SinkTarget::Path(Arc::new(dump_path)),
                    CsvWriterOptions::default(),
                    None,
                    SinkOptions::default(),
                )?;
                lf_dump.collect()?;
            }
            DumpFormat::Parquet => {
                let dump_path = file_path.with_extension("parquet");
                debug!("Dumping to parquet file: {:?}", dump_path);

                let lf_dump = lf.sink_parquet(
                    SinkTarget::Path(Arc::new(dump_path)),
                    ParquetWriteOptions {
                        row_group_size: Some(65536),
                        ..Default::default()
                    },
                    None,
                    SinkOptions::default(),
                )?;
                lf_dump.collect()?;
            }
        }
    }

    println!("Elapsed: {:?}", start.elapsed());

    // let mut flow_meta: HashMap<(u32, u32, u8, u16, u16), (u32, u16, u16, u32, i64, i64, i64)> =
    //     HashMap::new();

    // let mut meta = 0;

    // reader.for_each(|(hdr, data)| {
    //     let eth = match Eth::new(data) {
    //         Ok(eth) => eth,
    //         Err(_err) => {
    //             // eprintln!("Error: {:?}", e);
    //             return;
    //         }
    //     };

    //     if eth.ipv4().is_none() {
    //         return;
    //     }

    //     let timestamp_ns = hdr.ts_sec as i64 * 1_000_000_000 + hdr.ts_usec as i64;
    //     let timestamp_ms = timestamp_ns / 1_000;
    //     timestamp.push(timestamp_ns);
    //     length.push(hdr.orig_len);
    //     eth_type.push(eth.eth_type().get().into());

    //     if let Some(ip) = eth.ipv4() {
    //         let src_addr: u32 = ip.src().get().into();
    //         let dst_addr: u32 = ip.dst().get().into();
    //         let protocol: u8 = ip.protocol().get().into();
    //         let len = ip.total_length().get();

    //         src_ip4.push(src_addr);
    //         dst_ip4.push(dst_addr);
    //         ip_proto.push(protocol);
    //         tos.push(ip.tos().get());
    //         total_length.push(len);
    //         ttl.push(ip.ttl().get());

    //         let src_p;
    //         let dst_p;

    //         if let Some(tcp) = ip.tcp() {
    //             src_p = tcp.src_port().get();
    //             dst_p = tcp.dst_port().get();

    //             src_port.push(src_p);
    //             dst_port.push(dst_p);
    //             tcp_flags.push(tcp.flags().raw());
    //             tcp_window.push(tcp.window_size().get());
    //             tcp_data_offset.push(tcp.data_offset().get());
    //             udp_length.push(0);
    //         } else if let Some(udp) = ip.udp() {
    //             src_p = udp.src_port().get();
    //             dst_p = udp.dst_port().get();

    //             src_port.push(src_p);
    //             dst_port.push(dst_p);
    //             tcp_flags.push(0);
    //             tcp_window.push(0);
    //             tcp_data_offset.push(0);
    //             udp_length.push(udp.length().get());
    //         } else {
    //             src_p = 0;
    //             dst_p = 0;

    //             src_port.push(0);
    //             dst_port.push(0);
    //             tcp_flags.push(0);
    //             tcp_window.push(0);
    //             tcp_data_offset.push(0);
    //             udp_length.push(0);
    //         }

    //         let key = (src_addr, dst_addr, protocol, src_p, dst_p);
    //         flow_meta
    //             .entry(key)
    //             .and_modify(|e| {
    //                 e.0 += 1;
    //                 e.1 = e.1.min(len);
    //                 e.2 = e.2.max(len);
    //                 e.3 += len as u32;
    //                 let ipdd = timestamp_ms - e.4;
    //                 e.5 = e.5.min(ipdd);
    //                 e.6 = e.6.max(ipdd);
    //                 e.4 = timestamp_ms;

    //                 total_pkts.push(e.0);
    //                 max_len.push(e.2);
    //                 min_len.push(e.1);
    //                 avg_len.push((e.3 / e.0) as u16);
    //                 ipd.push(ipdd);
    //                 min_ipd.push(e.5);
    //                 max_ipd.push(e.6);
    //             })
    //             .or_insert_with(|| {
    //                 total_pkts.push(1);
    //                 max_len.push(len);
    //                 min_len.push(len);
    //                 avg_len.push(len);
    //                 ipd.push(0);
    //                 min_ipd.push(u32::MAX as i64);
    //                 max_ipd.push(0);

    //                 (1, len, len, len as u32, timestamp_ms, i64::MAX, 0)
    //             });
    //     } else {
    //         // src_ip4.push(0);
    //         // dst_ip4.push(0);
    //         // ip_proto.push(0);
    //         // tos.push(0);
    //         // total_length.push(0);
    //         // ttl.push(0);

    //         // src_port.push(0);
    //         // dst_port.push(0);
    //         // tcp_flags.push(0);
    //         // tcp_window.push(0);
    //         // tcp_data_offset.push(0);
    //         // udp_length.push(0);

    //         unreachable!("No IPv4 packet");
    //     }

    //     meta += 1;
    // });

    // println!("Total packets: {}", meta);

    // let mut df = DataFrame::new(vec![
    //     Series::from_vec("timestamp", timestamp),
    //     Series::from_vec("length", length),
    //     Series::from_vec("eth_type", eth_type),
    //     Series::from_vec("src_ip4", src_ip4),
    //     Series::from_vec("dst_ip4", dst_ip4),
    //     Series::from_vec("ip_proto", ip_proto),
    //     Series::from_vec("tos", tos),
    //     Series::from_vec("src_port", src_port),
    //     Series::from_vec("dst_port", dst_port),
    //     Series::from_vec("tcp_flags", tcp_flags),
    //     Series::from_vec("tcp_window", tcp_window),
    //     Series::from_vec("tcp_data_offset", tcp_data_offset),
    //     Series::from_vec("total_length", total_length),
    //     Series::from_vec("ttl", ttl),
    //     Series::from_vec("udp_length", udp_length),
    //     Series::from_vec("total_pkts", total_pkts),
    //     Series::from_vec("max_len", max_len),
    //     Series::from_vec("min_len", min_len),
    //     Series::from_vec("avg_len", avg_len),
    //     Series::from_vec("ipd", ipd),
    //     Series::from_vec("min_ipd", min_ipd),
    //     Series::from_vec("max_ipd", max_ipd),
    // ])?;

    // df.sort_in_place(["timestamp"], Default::default())?;

    // let elapsed = start.elapsed();

    // let total_packets = df.height();
    // let total_bytes = df.column("length").unwrap().sum::<u32>().unwrap();

    // println!("Total packets: {}", total_packets);
    // println!("Total bytes: {}", total_bytes);

    // println!("Elapsed: {:?}", elapsed);

    // if args.dump.is_some() {
    //     let start = std::time::Instant::now();

    //     match args.dump.unwrap() {
    //         DumpFormat::Csv => {
    //             let dump_path = file_path.with_extension("csv");

    //             println!("The inner table is dumping to CSV file: {:?}", dump_path);

    //             let mut writer = std::fs::File::create(dump_path)?;
    //             let mut writer = CsvWriter::new(&mut writer);
    //             writer.finish(&mut df)?;
    //         }
    //         // DumpFormat::Json => {
    //         //     let dump_path = file_path.with_extension("json");

    //         //     println!("The inner table is dumping to JSON file: {:?}", dump_path);

    //         //     let mut writer = std::fs::File::create(dump_path)?;
    //         //     let mut writer = JsonWriter::new(&mut writer);
    //         //     writer.finish(&mut df)?;
    //         // }
    //         DumpFormat::Parquet => {
    //             let dump_path = file_path.with_extension("parquet");

    //             println!(
    //                 "The inner table is dumping to parquet file: {:?}",
    //                 dump_path
    //             );

    //             let mut writer = std::fs::File::create(&dump_path)?;
    //             let writer = ParquetWriter::new(&mut writer);
    //             let writer = writer.with_row_group_size(Some(1024));
    //             let size = writer.finish(&mut df)?;

    //             println!("Dumped {size} bytes to {dump_path:?}");
    //         }
    //     }

    //     let elapsed = start.elapsed();
    //     println!("Elapsed: {:?}", elapsed);
    // }

    Ok(())
}
