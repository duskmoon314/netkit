use std::path::PathBuf;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use clap::{Args, Parser, ValueEnum};
use log::{debug, error, info};
use netkit::capture::file::pcap::PcapReader;
use netkit::capture::linktype::LinkType;
use netkit::packet::prelude::*;
use polars::prelude::*;

/// Statistics collected during packet processing
#[derive(Default, Debug)]
struct Statistics {
    total_packets: u64,
    total_bytes: u64,
    ipv4_packets: u64,
    non_ipv4_packets: u64,
    tcp_packets: u64,
    udp_packets: u64,
    other_ip_packets: u64,
    parse_errors: u64,
    first_timestamp: Option<i64>,
    last_timestamp: Option<i64>,
}

impl Statistics {
    fn duration_secs(&self) -> f64 {
        if let (Some(first), Some(last)) = (self.first_timestamp, self.last_timestamp) {
            (last - first) as f64 / 1_000_000_000.0
        } else {
            0.0
        }
    }

    fn throughput_mbps(&self) -> f64 {
        let duration = self.duration_secs();
        if duration > 0.0 {
            (self.total_bytes as f64 * 8.0) / (duration * 1_000_000.0)
        } else {
            0.0
        }
    }

    fn packet_rate(&self) -> f64 {
        let duration = self.duration_secs();
        if duration > 0.0 {
            self.total_packets as f64 / duration
        } else {
            0.0
        }
    }
}

/// Columnar batch collector for packet data
/// Directly stores data in column format to avoid intermediate struct allocation
struct PacketBatch {
    timestamp: Vec<i64>,
    length: Vec<u32>,
    eth_type: Vec<u16>,
    src_ip4: Vec<u32>,
    dst_ip4: Vec<u32>,
    ip_proto: Vec<u8>,
    tos: Vec<u8>,
    src_port: Vec<u16>,
    dst_port: Vec<u16>,
    tcp_flags: Vec<u8>,
    tcp_window: Vec<u16>,
    tcp_data_offset: Vec<u8>,
    total_length: Vec<u16>,
    ttl: Vec<u8>,
    udp_length: Vec<u16>,
    capacity: usize,
}

impl PacketBatch {
    fn new(capacity: usize) -> Self {
        Self {
            timestamp: Vec::with_capacity(capacity),
            length: Vec::with_capacity(capacity),
            eth_type: Vec::with_capacity(capacity),
            src_ip4: Vec::with_capacity(capacity),
            dst_ip4: Vec::with_capacity(capacity),
            ip_proto: Vec::with_capacity(capacity),
            tos: Vec::with_capacity(capacity),
            src_port: Vec::with_capacity(capacity),
            dst_port: Vec::with_capacity(capacity),
            tcp_flags: Vec::with_capacity(capacity),
            tcp_window: Vec::with_capacity(capacity),
            tcp_data_offset: Vec::with_capacity(capacity),
            total_length: Vec::with_capacity(capacity),
            ttl: Vec::with_capacity(capacity),
            udp_length: Vec::with_capacity(capacity),
            capacity,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn push(
        &mut self,
        timestamp: i64,
        length: u32,
        eth_type: u16,
        src_ip4: u32,
        dst_ip4: u32,
        ip_proto: u8,
        tos: u8,
        src_port: u16,
        dst_port: u16,
        tcp_flags: u8,
        tcp_window: u16,
        tcp_data_offset: u8,
        total_length: u16,
        ttl: u8,
        udp_length: u16,
    ) {
        self.timestamp.push(timestamp);
        self.length.push(length);
        self.eth_type.push(eth_type);
        self.src_ip4.push(src_ip4);
        self.dst_ip4.push(dst_ip4);
        self.ip_proto.push(ip_proto);
        self.tos.push(tos);
        self.src_port.push(src_port);
        self.dst_port.push(dst_port);
        self.tcp_flags.push(tcp_flags);
        self.tcp_window.push(tcp_window);
        self.tcp_data_offset.push(tcp_data_offset);
        self.total_length.push(total_length);
        self.ttl.push(ttl);
        self.udp_length.push(udp_length);
    }

    fn is_full(&self) -> bool {
        self.timestamp.len() >= self.capacity
    }

    #[allow(dead_code)]
    fn len(&self) -> usize {
        self.timestamp.len()
    }

    fn is_empty(&self) -> bool {
        self.timestamp.is_empty()
    }

    /// Convert batch to DataFrame using std::mem::take for zero-copy transfer
    fn as_dataframe(&mut self) -> PolarsResult<DataFrame> {
        df!(
            "timestamp" => std::mem::take(&mut self.timestamp),
            "length" => std::mem::take(&mut self.length),
            "eth_type" => std::mem::take(&mut self.eth_type),
            "src_ip4" => std::mem::take(&mut self.src_ip4),
            "dst_ip4" => std::mem::take(&mut self.dst_ip4),
            "ip_proto" => std::mem::take(&mut self.ip_proto),
            "tos" => std::mem::take(&mut self.tos),
            "src_port" => std::mem::take(&mut self.src_port),
            "dst_port" => std::mem::take(&mut self.dst_port),
            "tcp_flags" => std::mem::take(&mut self.tcp_flags),
            "tcp_window" => std::mem::take(&mut self.tcp_window),
            "tcp_data_offset" => std::mem::take(&mut self.tcp_data_offset),
            "total_length" => std::mem::take(&mut self.total_length),
            "ttl" => std::mem::take(&mut self.ttl),
            "udp_length" => std::mem::take(&mut self.udp_length)
        )
    }
}

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
        .filter_level(log::LevelFilter::Warn)
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

/// Process a single packet based on link type
/// Returns (eth_type, ipv4_packet_data) if successful
fn process_packet<'a>(
    linktype: LinkType,
    data: &'a [u8],
    stats: &mut Statistics,
) -> Option<(u16, &'a [u8])> {
    match linktype {
        LinkType::Ethernet => {
            // Parse Ethernet frame
            match Eth::new(data) {
                Ok(eth) => {
                    let eth_type = eth.eth_type().get().into();
                    // Check if it's IPv4 (EtherType 0x0800)
                    if eth_type == 0x0800u16 {
                        // IPv4 packet starts after Ethernet header (14 bytes)
                        if data.len() > 14 {
                            Some((eth_type, &data[14..]))
                        } else {
                            error!("Ethernet frame too short for IPv4");
                            stats.parse_errors += 1;
                            None
                        }
                    } else {
                        stats.non_ipv4_packets += 1;
                        None
                    }
                }
                Err(err) => {
                    error!("Error parsing Ethernet frame: {:?}", err);
                    stats.parse_errors += 1;
                    None
                }
            }
        }
        LinkType::Ipv4 | LinkType::Raw => {
            // Parse IPv4 directly without link layer (verify it's valid IPv4)
            match Ipv4::new(data) {
                Ok(_ip) => Some((0x0800u16, data)),
                Err(err) => {
                    error!("Error parsing IPv4 packet: {:?}", err);
                    stats.parse_errors += 1;
                    None
                }
            }
        }
        _ => {
            error!("Unsupported link type: {:?}", linktype);
            stats.parse_errors += 1;
            None
        }
    }
}

fn info(file_path: PathBuf, args: &Flags, multi: &indicatif::MultiProgress) -> anyhow::Result<()> {
    let file = std::fs::File::open(file_path.clone())?;
    let file_size = file.metadata()?.len();
    let reader = PcapReader::new(file);

    debug!("Pcap header: {:X?}", reader.header);

    let nanoseconds = reader.nanoseconds;
    let time_scale = if nanoseconds {
        1_000_000_000
    } else {
        1_000_000
    };
    debug!(
        "Timestamp precision: {}",
        if nanoseconds {
            "nanoseconds"
        } else {
            "microseconds"
        }
    );

    let linktype: LinkType = reader.header.network.into();

    let pg = multi
        .add(indicatif::ProgressBar::no_length().with_finish(indicatif::ProgressFinish::Abandon));
    pg.set_style(indicatif::ProgressStyle::with_template(
        "[{elapsed_precise}] {human_pos:>12} pkts    {msg}",
    )?);
    pg.set_message(file_path.display().to_string());
    pg.enable_steady_tick(Duration::from_secs(1));

    let start = Instant::now();
    let mut stats = Statistics::default();

    let mut reader = pg.wrap_iter(reader);
    let tmp_dir = tempfile::Builder::new()
        .prefix("netkit-capinfo-")
        .tempdir()?;
    debug!("Created temporary directory: {:?}", tmp_dir.path());

    let mut batch = PacketBatch::new(args.dump_batch);
    let mut batch_count = 0;

    for (hdr, data) in reader.by_ref() {
        stats.total_packets += 1;
        stats.total_bytes += hdr.orig_len as u64;

        let ts = hdr.ts_sec as i64 * time_scale + hdr.ts_usec as i64;
        if stats.first_timestamp.is_none() {
            stats.first_timestamp = Some(ts);
        }
        stats.last_timestamp = Some(ts);

        // Process packet based on link type
        let (eth_type, ip_data) = match process_packet(linktype, &data, &mut stats) {
            Some(result) => result,
            None => continue,
        };

        // Parse the IPv4 packet from the extracted data
        let ip = match Ipv4::new(ip_data) {
            Ok(ip) => ip,
            Err(err) => {
                error!("Error parsing IPv4 from extracted data: {:?}", err);
                stats.parse_errors += 1;
                continue;
            }
        };

        {
            stats.ipv4_packets += 1;

            let src_addr: u32 = ip.src().get().into();
            let dst_addr: u32 = ip.dst().get().into();
            let protocol: u8 = ip.protocol().get().into();
            let len = ip.total_length().get();

            let (src_port, dst_port, tcp_flags, tcp_window, tcp_data_offset, udp_length) =
                if let Some(tcp) = ip.tcp() {
                    stats.tcp_packets += 1;
                    (
                        tcp.src_port().get(),
                        tcp.dst_port().get(),
                        tcp.flags().raw(),
                        tcp.window_size().get(),
                        tcp.data_offset().get(),
                        0,
                    )
                } else if let Some(udp) = ip.udp() {
                    stats.udp_packets += 1;
                    (
                        udp.src_port().get(),
                        udp.dst_port().get(),
                        0,
                        0,
                        0,
                        udp.length().get(),
                    )
                } else {
                    stats.other_ip_packets += 1;
                    (0, 0, 0, 0, 0, 0)
                };

            if args.dump.is_some() {
                batch.push(
                    ts,
                    hdr.orig_len,
                    eth_type,
                    src_addr,
                    dst_addr,
                    protocol,
                    ip.tos().get(),
                    src_port,
                    dst_port,
                    tcp_flags,
                    tcp_window,
                    tcp_data_offset,
                    len,
                    ip.ttl().get(),
                    udp_length,
                );

                if batch.is_full() {
                    let mut df = batch.as_dataframe()?;
                    let tmp_file = tmp_dir
                        .path()
                        .join(format!("batch_{}.parquet", batch_count));
                    let writer = std::fs::File::create(&tmp_file)?;
                    ParquetWriter::new(writer).finish(&mut df)?;
                    batch_count += 1;
                }
            }
        }
    }

    if args.dump.is_some() && !batch.is_empty() {
        let mut df = batch.as_dataframe()?;
        let tmp_file = tmp_dir
            .path()
            .join(format!("batch_{}.parquet", batch_count));
        let writer = std::fs::File::create(&tmp_file)?;
        ParquetWriter::new(writer).finish(&mut df)?;
    }

    let processing_time = start.elapsed();

    pg.finish_and_clear();

    // Print statistics
    println!("\n{}", "=".repeat(70));
    println!("File: {}", file_path.display());
    println!("{}", "=".repeat(70));

    // File statistics
    println!("\n📁 File Information:");
    println!(
        "  File size:              {:>12} bytes ({:.2} MB)",
        file_size,
        file_size as f64 / 1_048_576.0
    );

    // Packet statistics
    println!("\n📊 Packet Statistics:");
    println!("  Total packets:          {:>12}", stats.total_packets);
    println!(
        "  Total bytes:            {:>12} ({:.2} MB)",
        stats.total_bytes,
        stats.total_bytes as f64 / 1_048_576.0
    );
    println!(
        "  Average packet size:    {:>12.2} bytes",
        if stats.total_packets > 0 {
            stats.total_bytes as f64 / stats.total_packets as f64
        } else {
            0.0
        }
    );

    // Protocol breakdown
    println!("\n🔍 Protocol Breakdown:");
    println!(
        "  IPv4 packets:           {:>12} ({:>6.2}%)",
        stats.ipv4_packets,
        stats.ipv4_packets as f64 / stats.total_packets as f64 * 100.0
    );
    println!(
        "    - TCP:                {:>12} ({:>6.2}%)",
        stats.tcp_packets,
        stats.tcp_packets as f64 / stats.total_packets as f64 * 100.0
    );
    println!(
        "    - UDP:                {:>12} ({:>6.2}%)",
        stats.udp_packets,
        stats.udp_packets as f64 / stats.total_packets as f64 * 100.0
    );
    println!(
        "    - Other IP:           {:>12} ({:>6.2}%)",
        stats.other_ip_packets,
        stats.other_ip_packets as f64 / stats.total_packets as f64 * 100.0
    );
    println!(
        "  Non-IPv4 packets:       {:>12} ({:>6.2}%)",
        stats.non_ipv4_packets,
        stats.non_ipv4_packets as f64 / stats.total_packets as f64 * 100.0
    );

    if stats.parse_errors > 0 {
        println!("  Parse errors:           {:>12}", stats.parse_errors);
    }

    // Timing statistics
    let duration = stats.duration_secs();
    println!("\n⏱️  Timing Information:");
    if let (Some(first), Some(last)) = (stats.first_timestamp, stats.last_timestamp) {
        // Timestamps are stored in the resolution of time_scale (either ns or µs)
        // Convert to seconds and nanoseconds for chrono
        let first_secs = first / time_scale;
        let first_subsec_ns = ((first % time_scale) * (1_000_000_000 / time_scale)) as u32;
        let last_secs = last / time_scale;
        let last_subsec_ns = ((last % time_scale) * (1_000_000_000 / time_scale)) as u32;

        let first_dt = DateTime::from_timestamp(first_secs, first_subsec_ns)
            .unwrap_or(DateTime::<Utc>::MIN_UTC);
        let last_dt =
            DateTime::from_timestamp(last_secs, last_subsec_ns).unwrap_or(DateTime::<Utc>::MIN_UTC);

        let timestamp_unit = if nanoseconds { "ns" } else { "µs" };

        println!("  First packet:");
        println!(
            "    Time:                 {}",
            first_dt.format("%Y-%m-%d %H:%M:%S%.6f UTC")
        );
        println!("    Timestamp:            {} {}", first, timestamp_unit);
        println!("  Last packet:");
        println!(
            "    Time:                 {}",
            last_dt.format("%Y-%m-%d %H:%M:%S%.6f UTC")
        );
        println!("    Timestamp:            {} {}", last, timestamp_unit);
        println!("  Capture duration:       {:>12.6} seconds", duration);
    }
    println!(
        "  Processing time:        {:>12.6} seconds",
        processing_time.as_secs_f64()
    );
    println!(
        "  Processing speed:       {:>12.2} packets/sec",
        stats.total_packets as f64 / processing_time.as_secs_f64()
    );
    println!(
        "  Processing throughput:  {:>12.2} MB/sec",
        stats.total_bytes as f64 / processing_time.as_secs_f64() / 1_048_576.0
    );

    // Capture rate (if we have timing info)
    if duration > 0.0 {
        println!("\n📈 Capture Rates (from timestamps):");
        println!(
            "  Packet rate:            {:>12.2} packets/sec",
            stats.packet_rate()
        );
        println!(
            "  Data rate:              {:>12.2} Mbps",
            stats.throughput_mbps()
        );
        println!(
            "  Data rate:              {:>12.2} MB/sec",
            stats.total_bytes as f64 / duration / 1_048_576.0
        );
    }

    let mut files = tmp_dir
        .path()
        .read_dir()?
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .collect::<Vec<_>>();
    files.sort();

    // Use Polars for advanced statistics if we have data
    if !files.is_empty() {
        let lf = LazyFrame::scan_parquet_files(
            Arc::from(files.clone().into_boxed_slice()),
            ScanArgsParquet {
                low_memory: true,
                ..Default::default()
            },
        )?;

        // Compute advanced statistics using Polars
        info!("Computing advanced statistics...");
        let stats_start = Instant::now();

        // Aggregate statistics
        let agg_df = lf
            .clone()
            .select([
                // Basic stats
                col("length").sum().alias("total_bytes_check"),
                col("length").mean().alias("avg_packet_size"),
                col("length").min().alias("min_packet_size"),
                col("length").max().alias("max_packet_size"),
                col("length").std(1).alias("std_packet_size"),
                // Protocol counts
                (col("ip_proto").eq(lit(6u8))).sum().alias("tcp_count"),
                (col("ip_proto").eq(lit(17u8))).sum().alias("udp_count"),
                // Port statistics (top ports)
                col("src_port").n_unique().alias("unique_src_ports"),
                col("dst_port").n_unique().alias("unique_dst_ports"),
                // IP statistics
                col("src_ip4").n_unique().alias("unique_src_ips"),
                col("dst_ip4").n_unique().alias("unique_dst_ips"),
                // TTL statistics
                col("ttl").mean().alias("avg_ttl"),
                col("ttl").min().alias("min_ttl"),
                col("ttl").max().alias("max_ttl"),
            ])
            .collect()?;

        // Top ports analysis
        let top_dst_ports = lf
            .clone()
            .filter(col("dst_port").neq(lit(0u16)))
            .group_by([col("dst_port")])
            .agg([col("dst_port").count().alias("count")])
            .sort(
                ["count"],
                SortMultipleOptions::default().with_order_descending(true),
            )
            .limit(10)
            .collect()?;

        // Top IPs (by packet count)
        let top_src_ips = lf
            .clone()
            .group_by([col("src_ip4")])
            .agg([
                col("src_ip4").count().alias("count"),
                col("length").sum().alias("bytes"),
            ])
            .sort(
                ["count"],
                SortMultipleOptions::default().with_order_descending(true),
            )
            .limit(5)
            .collect()?;

        let top_dst_ips = lf
            .clone()
            .group_by([col("dst_ip4")])
            .agg([
                col("dst_ip4").count().alias("count"),
                col("length").sum().alias("bytes"),
            ])
            .sort(
                ["count"],
                SortMultipleOptions::default().with_order_descending(true),
            )
            .limit(5)
            .collect()?;

        let stats_time = stats_start.elapsed();

        // Print advanced statistics
        println!("\n📊 Advanced Statistics:");
        if agg_df.height() > 0 {
            if let Some(avg_size) = agg_df
                .column("avg_packet_size")
                .ok()
                .and_then(|c| c.f64().ok())
                .and_then(|s| s.get(0))
            {
                println!("  Avg packet size:        {:>12.2} bytes", avg_size);
            }
            if let Some(min_size) = agg_df
                .column("min_packet_size")
                .ok()
                .and_then(|c| c.u32().ok())
                .and_then(|s| s.get(0))
            {
                println!("  Min packet size:        {:>12} bytes", min_size);
            }
            if let Some(max_size) = agg_df
                .column("max_packet_size")
                .ok()
                .and_then(|c| c.u32().ok())
                .and_then(|s| s.get(0))
            {
                println!("  Max packet size:        {:>12} bytes", max_size);
            }
            if let Some(std_size) = agg_df
                .column("std_packet_size")
                .ok()
                .and_then(|c| c.f64().ok())
                .and_then(|s| s.get(0))
            {
                println!("  Std dev packet size:    {:>12.2} bytes", std_size);
            }
        }

        println!("\n🌐 Network Statistics:");
        if agg_df.height() > 0 {
            if let Some(unique_src) = agg_df
                .column("unique_src_ips")
                .ok()
                .and_then(|c| c.u32().ok())
                .and_then(|s| s.get(0))
            {
                println!("  Unique source IPs:      {:>12}", unique_src);
            }
            if let Some(unique_dst) = agg_df
                .column("unique_dst_ips")
                .ok()
                .and_then(|c| c.u32().ok())
                .and_then(|s| s.get(0))
            {
                println!("  Unique dest IPs:        {:>12}", unique_dst);
            }
            if let Some(unique_src_ports) = agg_df
                .column("unique_src_ports")
                .ok()
                .and_then(|c| c.u32().ok())
                .and_then(|s| s.get(0))
            {
                println!("  Unique source ports:    {:>12}", unique_src_ports);
            }
            if let Some(unique_dst_ports) = agg_df
                .column("unique_dst_ports")
                .ok()
                .and_then(|c| c.u32().ok())
                .and_then(|s| s.get(0))
            {
                println!("  Unique dest ports:      {:>12}", unique_dst_ports);
            }
        }

        println!("\n🔝 Top Destination Ports:");
        if let (Ok(port_col), Ok(count_col)) = (
            top_dst_ports.column("dst_port").and_then(|c| c.u16()),
            top_dst_ports.column("count").and_then(|c| c.u32()),
        ) {
            for i in 0..top_dst_ports.height().min(10) {
                if let (Some(port), Some(count)) = (port_col.get(i), count_col.get(i)) {
                    let pct = count as f64 / stats.ipv4_packets as f64 * 100.0;
                    println!(
                        "  Port {:>5}:              {:>12} ({:>6.2}%)",
                        port, count, pct
                    );
                }
            }
        }

        println!("\n🔝 Top Source IPs (by packets):");
        if let (Ok(ip_col), Ok(count_col), Ok(bytes_col)) = (
            top_src_ips.column("src_ip4").and_then(|c| c.u32()),
            top_src_ips.column("count").and_then(|c| c.u32()),
            top_src_ips.column("bytes").and_then(|c| c.u32()),
        ) {
            for i in 0..top_src_ips.height().min(5) {
                if let (Some(ip), Some(count), Some(bytes)) =
                    (ip_col.get(i), count_col.get(i), bytes_col.get(i))
                {
                    let ip_str = format!(
                        "{}.{}.{}.{}",
                        (ip >> 24) & 0xFF,
                        (ip >> 16) & 0xFF,
                        (ip >> 8) & 0xFF,
                        ip & 0xFF
                    );
                    println!(
                        "  {:>15}:          {:>12} pkts, {:>10.2} MB",
                        ip_str,
                        count,
                        bytes as f64 / 1_048_576.0
                    );
                }
            }
        }

        println!("\n🔝 Top Destination IPs (by packets):");
        if let (Ok(ip_col), Ok(count_col), Ok(bytes_col)) = (
            top_dst_ips.column("dst_ip4").and_then(|c| c.u32()),
            top_dst_ips.column("count").and_then(|c| c.u32()),
            top_dst_ips.column("bytes").and_then(|c| c.u32()),
        ) {
            for i in 0..top_dst_ips.height().min(5) {
                if let (Some(ip), Some(count), Some(bytes)) =
                    (ip_col.get(i), count_col.get(i), bytes_col.get(i))
                {
                    let ip_str = format!(
                        "{}.{}.{}.{}",
                        (ip >> 24) & 0xFF,
                        (ip >> 16) & 0xFF,
                        (ip >> 8) & 0xFF,
                        ip & 0xFF
                    );
                    println!(
                        "  {:>15}:          {:>12} pkts, {:>10.2} MB",
                        ip_str,
                        count,
                        bytes as f64 / 1_048_576.0
                    );
                }
            }
        }

        println!(
            "\n  Statistics computation: {:>12.6} seconds",
            stats_time.as_secs_f64()
        );

        if args.dump.is_some() {
            let dump_start = Instant::now();

            match args.dump.unwrap() {
                DumpFormat::Csv => {
                    let dump_path = file_path.with_extension("csv");
                    info!("Dumping to CSV file: {:?}", dump_path);

                    let lf_dump = lf.sink_csv(
                        SinkTarget::Path(Arc::new(dump_path.clone())),
                        CsvWriterOptions::default(),
                        None,
                        SinkOptions::default(),
                    )?;
                    lf_dump.collect()?;

                    let dump_size = std::fs::metadata(&dump_path)?.len();
                    println!("\n💾 Export Information:");
                    println!("  Format:                 CSV");
                    println!("  Output file:            {}", dump_path.display());
                    println!(
                        "  Output size:            {} bytes ({:.2} MB)",
                        dump_size,
                        dump_size as f64 / 1_048_576.0
                    );
                }
                DumpFormat::Parquet => {
                    let dump_path = file_path.with_extension("parquet");
                    info!("Dumping to Parquet file: {:?}", dump_path);

                    let lf_dump = lf.sink_parquet(
                        SinkTarget::Path(Arc::new(dump_path.clone())),
                        ParquetWriteOptions {
                            row_group_size: Some(65536),
                            ..Default::default()
                        },
                        None,
                        SinkOptions::default(),
                    )?;
                    lf_dump.collect()?;

                    let dump_size = std::fs::metadata(&dump_path)?.len();
                    println!("\n💾 Export Information:");
                    println!("  Format:                 Parquet");
                    println!("  Output file:            {}", dump_path.display());
                    println!(
                        "  Output size:            {} bytes ({:.2} MB)",
                        dump_size,
                        dump_size as f64 / 1_048_576.0
                    );
                    println!(
                        "  Compression ratio:      {:.2}x",
                        file_size as f64 / dump_size as f64
                    );
                }
            }

            println!(
                "  Export time:            {:>12.6} seconds",
                dump_start.elapsed().as_secs_f64()
            );
        }
    }

    println!("\n{}\n", "=".repeat(70));

    Ok(())
}
