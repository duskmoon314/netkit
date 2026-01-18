use std::collections::{HashMap, HashSet, LinkedList};
use std::fs::File;
use std::path::PathBuf;
use std::time::Duration;

use clap::{Parser, ValueEnum};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use indicatif_log_bridge::LogWrapper;
use log::{debug, info};
use netkit::capture::format::pcap::PcapWriter;
use netkit::capture::{CaptureReader, LinkType, Packet, from_path};
use netkit::packet::layer::eth;
use netkit::packet::layer::ip::protocol::IpProtocol;
use netkit::packet::prelude::*;

/// Split granularity for pcap files
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum SplitGranularity {
    /// Split by source IP address
    SrcIp,
    /// Split by destination IP address
    DstIp,
    /// Source and destination IPs (ordered)
    Tuple2,
    /// Source and destination IPs (symmetric: min,max order)
    Tuple2Sym,
    /// Source and destination IPs and protocol (ordered)
    Tuple3,
    /// Source and destination IPs and protocol (symmetric)
    Tuple3Sym,
    /// Source and destination IPs, ports (ordered)
    Tuple4,
    /// Source and destination IPs, ports (symmetric)
    Tuple4Sym,
    /// Source and destination IPs, ports, protocol (5-tuple)
    Tuple5,
    /// Source and destination IPs, ports, protocol (symmetric)
    Tuple5Sym,
}

/// pcap-split (netkit)
///
/// Split a pcap/pcapng file into multiple smaller pcap files based on specified granularity.
#[derive(Debug, Parser)]
#[command(version, about, long_about)]
struct Cli {
    /// Input capture file (pcap or pcapng)
    input: PathBuf,

    /// Output directory for split pcap files
    output: PathBuf,

    /// Split granularity
    #[clap(short, long, value_enum)]
    granularity: SplitGranularity,

    /// Number of output files to create (0 = unlimited)
    #[clap(short, long, default_value = "0")]
    number: usize,

    /// Use two-pass mode to reduce memory for large pcaps
    /// First pass: count packets per flow
    /// Second pass: write only top N flows to files
    #[clap(long)]
    two_pass: bool,
}

/// Flow key for splitting packets
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum FlowKey {
    Ip(u32),
    Tuple2(u32, u32),
    Tuple3(u32, u32, IpProtocol),
    Tuple4(u32, u32, u16, u16),
    Tuple5(u32, u32, u16, u16, IpProtocol),
}

impl FlowKey {
    /// Create a flow key from packet data based on granularity
    fn from_packet(
        granularity: SplitGranularity,
        src_ip: u32,
        dst_ip: u32,
        protocol: IpProtocol,
        src_port: u16,
        dst_port: u16,
    ) -> Self {
        match granularity {
            SplitGranularity::SrcIp => FlowKey::Ip(src_ip),
            SplitGranularity::DstIp => FlowKey::Ip(dst_ip),
            SplitGranularity::Tuple2 => FlowKey::Tuple2(src_ip, dst_ip),
            SplitGranularity::Tuple2Sym => {
                let (ip1, ip2) = if src_ip <= dst_ip {
                    (src_ip, dst_ip)
                } else {
                    (dst_ip, src_ip)
                };
                FlowKey::Tuple2(ip1, ip2)
            }
            SplitGranularity::Tuple3 => FlowKey::Tuple3(src_ip, dst_ip, protocol),
            SplitGranularity::Tuple3Sym => {
                let (ip1, ip2) = if src_ip <= dst_ip {
                    (src_ip, dst_ip)
                } else {
                    (dst_ip, src_ip)
                };
                FlowKey::Tuple3(ip1, ip2, protocol)
            }
            SplitGranularity::Tuple4 => FlowKey::Tuple4(src_ip, dst_ip, src_port, dst_port),
            SplitGranularity::Tuple4Sym => {
                let (ip1, ip2, port1, port2) = if (src_ip, src_port) <= (dst_ip, dst_port) {
                    (src_ip, dst_ip, src_port, dst_port)
                } else {
                    (dst_ip, src_ip, dst_port, src_port)
                };
                FlowKey::Tuple4(ip1, ip2, port1, port2)
            }
            SplitGranularity::Tuple5 => {
                FlowKey::Tuple5(src_ip, dst_ip, src_port, dst_port, protocol)
            }
            SplitGranularity::Tuple5Sym => {
                let (ip1, ip2, port1, port2) = if (src_ip, src_port) <= (dst_ip, dst_port) {
                    (src_ip, dst_ip, src_port, dst_port)
                } else {
                    (dst_ip, src_ip, dst_port, src_port)
                };
                FlowKey::Tuple5(ip1, ip2, port1, port2, protocol)
            }
        }
    }

    /// Generate filename for this flow key
    fn to_filename(&self) -> String {
        use std::net::Ipv4Addr;

        match self {
            FlowKey::Ip(ip) => {
                format!("{}.pcap", Ipv4Addr::from(*ip))
            }
            FlowKey::Tuple2(ip1, ip2) => {
                format!("{}_{}.pcap", Ipv4Addr::from(*ip1), Ipv4Addr::from(*ip2))
            }
            FlowKey::Tuple3(ip1, ip2, proto) => {
                format!(
                    "{}_{}_{}.pcap",
                    Ipv4Addr::from(*ip1),
                    Ipv4Addr::from(*ip2),
                    proto
                )
            }
            FlowKey::Tuple4(ip1, ip2, port1, port2) => {
                format!(
                    "{}:{}_{:}:{}.pcap",
                    Ipv4Addr::from(*ip1),
                    port1,
                    Ipv4Addr::from(*ip2),
                    port2
                )
            }
            FlowKey::Tuple5(ip1, ip2, port1, port2, proto) => {
                format!(
                    "{}:{}_{:}:{}_{}.pcap",
                    Ipv4Addr::from(*ip1),
                    port1,
                    Ipv4Addr::from(*ip2),
                    port2,
                    proto
                )
            }
        }
    }
}

/// Process a packet based on link type and extract IPv4 flow information
fn process_packet(linktype: LinkType, data: &[u8]) -> Option<(u32, u32, IpProtocol, u16, u16)> {
    let ip_data = match linktype {
        LinkType::Ethernet => {
            // Parse Ethernet frame
            let eth = Eth::new(data).ok()?;
            if eth.eth_type().get() == EthType::Ipv4 && data.len() > eth::MIN_HEADER_LENGTH {
                Some(&data[eth::MIN_HEADER_LENGTH..])
            } else {
                None
            }
        }
        LinkType::Ipv4 | LinkType::Raw => {
            // Validate IPv4 packet and return data
            Ipv4::new(data).ok()?;
            Some(data)
        }
        _ => None,
    }?;

    // Parse IPv4 packet
    let ip = Ipv4::new(ip_data).ok()?;
    let src_ip = ip.src().get().into();
    let dst_ip = ip.dst().get().into();
    let protocol = ip.protocol().get();

    // Extract port information if TCP or UDP
    let (src_port, dst_port) = if let Some(tcp) = ip.tcp() {
        (tcp.src_port().get(), tcp.dst_port().get())
    } else if let Some(udp) = ip.udp() {
        (udp.src_port().get(), udp.dst_port().get())
    } else {
        (0, 0)
    };

    Some((src_ip, dst_ip, protocol, src_port, dst_port))
}

fn main() -> anyhow::Result<()> {
    let logger = env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .parse_default_env()
        .build();
    let level = logger.filter();

    let multi = MultiProgress::new();
    LogWrapper::new(multi.clone(), logger).try_init()?;
    log::set_max_level(level);

    let args = Cli::parse();

    // Create output directory if it doesn't exist
    if !args.output.exists() {
        std::fs::create_dir_all(&args.output)?;
    }

    // Open input capture file (auto-detects pcap/pcapng)
    let reader = from_path(&args.input)?;

    let linktype = reader.linktype();
    let nanoseconds = reader.is_nanosecond_precision();
    let snaplen = reader.snaplen();

    info!("Input format: {}", reader.format_name());
    info!("Link type: {}", linktype);
    debug!("Cli arguments: {:?}", args);

    info!(
        "Mode: {}",
        if args.two_pass {
            "two-pass (memory efficient)"
        } else {
            "single-pass (all in memory)"
        }
    );
    if args.number > 0 {
        info!("Will extract top {} flows", args.number);
    }

    if args.two_pass {
        // Two-pass mode needs to read file twice, drop reader first
        drop(reader);
        two_pass_split(args, linktype, nanoseconds, snaplen, multi)?;
    } else {
        // Single-pass mode: pass reader directly
        single_pass_split(args, reader, nanoseconds, snaplen, multi)?;
    }

    Ok(())
}

/// Single-pass mode: store all packets in memory, then sort and write
fn single_pass_split(
    args: Cli,
    reader: netkit::capture::CaptureFile<std::io::BufReader<File>>,
    nanoseconds: bool,
    snaplen: u32,
    multi: MultiProgress,
) -> anyhow::Result<()> {
    let linktype = reader.linktype();

    // Setup progress bar
    let pg = multi.add(ProgressBar::new_spinner().with_finish(indicatif::ProgressFinish::Abandon));
    pg.set_style(ProgressStyle::with_template(
        "[{elapsed_precise}] {human_pos:>12} pkts | {msg}",
    )?);
    pg.set_message(args.input.display().to_string());
    pg.enable_steady_tick(Duration::from_secs(1));

    // Map of flow keys to packets (using universal Packet type)
    let mut flows: HashMap<FlowKey, LinkedList<Packet>> = HashMap::new();
    let mut total_packets = 0u64;
    let mut skipped_packets = 0u64;
    let mut written_packets = 0u64;

    for result in pg.wrap_iter(reader) {
        let packet = result?;
        total_packets += 1;

        // Extract flow info
        let flow_info = match process_packet(linktype, &packet.data) {
            Some(info) => info,
            None => {
                debug!("Skipping non-IPv4 or malformed packet");
                skipped_packets += 1;
                continue;
            }
        };

        let flow_key = FlowKey::from_packet(
            args.granularity,
            flow_info.0,
            flow_info.1,
            flow_info.2,
            flow_info.3,
            flow_info.4,
        );

        // Append the packet into the corresponding flow, or create new flow
        let packet_list = flows.entry(flow_key).or_default();
        packet_list.push_back(packet);
    }

    // Write flows to files
    // If args.number > 0, limit to the longest 'number' flows
    // That is, sort flows by length and take the top 'number' flows

    let mut selected_flows = flows.into_iter().collect::<Vec<_>>();
    selected_flows.sort_by(|a, b| {
        let len_a = a.1.len();
        let len_b = b.1.len();
        len_b.cmp(&len_a)
    });
    let selected_flows = if args.number > 0 {
        selected_flows
            .into_iter()
            .take(args.number)
            .collect::<Vec<_>>()
    } else {
        selected_flows
    };

    let total_flows = selected_flows.len();

    let mut top_10_flow_keys = Vec::new();
    for (flow_key, packet_list) in selected_flows.iter().take(10) {
        top_10_flow_keys.push((flow_key.clone(), packet_list.len()));
    }

    let pg = multi.add(
        ProgressBar::new(selected_flows.len() as u64)
            .with_finish(indicatif::ProgressFinish::Abandon),
    );
    pg.set_style(ProgressStyle::with_template(
        "[{elapsed_precise}] {human_pos:>12}/{human_len:>12} flows written | {msg}",
    )?);
    pg.set_message("Writing output files");
    pg.enable_steady_tick(Duration::from_secs(1));

    for (flow_key, packet_list) in pg.wrap_iter(selected_flows.into_iter()) {
        let filename = flow_key.to_filename();
        let filepath = args.output.join(&filename);
        let file = File::create(&filepath).expect("Failed to create output file");
        debug!("Created output file: {}", filename);
        let mut writer = PcapWriter::new(file, false, nanoseconds, snaplen, linktype)
            .expect("Failed to create PcapWriter");

        written_packets += packet_list.len() as u64;

        for packet in packet_list {
            netkit::capture::CaptureWriter::write_packet(&mut writer, &packet)?;
        }

        writer.flush()?;
    }

    // Print summary
    println!("\n{}", "=".repeat(70));
    println!("Split Summary");
    println!("{}", "=".repeat(70));
    println!("Total packets processed: {}", total_packets);
    println!("Packets written:         {}", written_packets);
    println!("Packets skipped:         {}", skipped_packets);
    println!("Total flows in input:    {}", total_flows);
    println!("Top 10 flows by packet count:");
    println!("{:-<70}", "");
    for (key, count) in top_10_flow_keys {
        println!("{:50} {:>15} packets", key.to_filename(), count);
    }
    println!("{}", "=".repeat(70));

    Ok(())
}

/// Two-pass mode: first pass counts packets, second pass extracts top N flows
/// This is memory-efficient for large pcaps with many flows
fn two_pass_split(
    args: Cli,
    linktype: LinkType,
    nanoseconds: bool,
    snaplen: u32,
    multi: MultiProgress,
) -> anyhow::Result<()> {
    info!("Pass 1/2: Counting packets per flow...");

    // First pass: count packets per flow
    let reader = from_path(&args.input)?;

    let pg = multi.add(ProgressBar::new_spinner().with_finish(indicatif::ProgressFinish::Abandon));
    pg.set_style(ProgressStyle::with_template(
        "[{elapsed_precise}] Pass 1: {human_pos:>12} pkts | {msg}",
    )?);
    pg.set_message("Counting flows");
    pg.enable_steady_tick(Duration::from_secs(1));

    let mut flow_counts: HashMap<FlowKey, u64> = HashMap::new();
    let mut total_packets = 0u64;
    let mut skipped_packets = 0u64;

    for result in pg.wrap_iter(reader) {
        let packet = result?;
        total_packets += 1;

        // Extract flow info
        let flow_info = match process_packet(linktype, &packet.data) {
            Some(info) => info,
            None => {
                skipped_packets += 1;
                continue;
            }
        };

        let flow_key = FlowKey::from_packet(
            args.granularity,
            flow_info.0,
            flow_info.1,
            flow_info.2,
            flow_info.3,
            flow_info.4,
        );

        *flow_counts.entry(flow_key).or_insert(0) += 1;
    }

    pg.finish_and_clear();

    info!("Pass 1 complete: {} flows found", flow_counts.len());

    // Select top N flows by packet count
    let mut flows_vec: Vec<_> = flow_counts.into_iter().collect();
    flows_vec.sort_by(|a, b| b.1.cmp(&a.1)); // Sort by count descending

    let selected_flows: HashSet<FlowKey> = if args.number > 0 {
        flows_vec
            .into_iter()
            .take(args.number)
            .map(|(k, _)| k)
            .collect()
    } else {
        flows_vec.into_iter().map(|(k, _)| k).collect()
    };

    info!("Pass 2/2: Extracting {} flows...", selected_flows.len());

    // Second pass: extract only selected flows
    let reader = from_path(&args.input)?;

    let pg = multi.add(ProgressBar::new_spinner().with_finish(indicatif::ProgressFinish::Abandon));
    pg.set_style(ProgressStyle::with_template(
        "[{elapsed_precise}] Pass 2: {human_pos:>12} pkts | {msg}",
    )?);
    pg.set_message("Extracting flows");
    pg.enable_steady_tick(Duration::from_secs(1));

    let mut writers: HashMap<FlowKey, PcapWriter<File>> = HashMap::new();
    let mut packet_counts: HashMap<FlowKey, u64> = HashMap::new();
    let mut written_packets = 0u64;

    for result in pg.wrap_iter(reader) {
        let packet = result?;

        // Extract flow info
        let flow_info = match process_packet(linktype, &packet.data) {
            Some(info) => info,
            None => continue,
        };

        let flow_key = FlowKey::from_packet(
            args.granularity,
            flow_info.0,
            flow_info.1,
            flow_info.2,
            flow_info.3,
            flow_info.4,
        );

        // Skip if not in selected flows
        if !selected_flows.contains(&flow_key) {
            continue;
        }

        // Get or create writer for this flow
        let writer = writers.entry(flow_key.clone()).or_insert_with(|| {
            let filename = flow_key.to_filename();
            let filepath = args.output.join(&filename);
            let file = File::create(&filepath).expect("Failed to create output file");
            debug!("Created output file: {}", filename);
            PcapWriter::new(file, false, nanoseconds, snaplen, linktype)
                .expect("Failed to create PcapWriter")
        });

        // Write packet using CaptureWriter trait
        netkit::capture::CaptureWriter::write_packet(writer, &packet)?;
        *packet_counts.entry(flow_key).or_insert(0) += 1;
        written_packets += 1;
    }

    // Flush all writers
    for (_key, mut writer) in writers {
        writer.flush()?;
    }

    pg.finish_and_clear();

    // Print summary
    println!("\n{}", "=".repeat(70));
    println!("Split Summary (Two-Pass Mode)");
    println!("{}", "=".repeat(70));
    println!("Total packets processed: {}", total_packets);
    println!("Packets written:         {}", written_packets);
    println!("Packets skipped:         {}", skipped_packets);
    println!("Output files created:    {}", packet_counts.len());
    println!();

    // Sort flows by packet count
    let mut flows: Vec<_> = packet_counts.iter().collect();
    flows.sort_by(|a, b| b.1.cmp(a.1));

    println!("Top 10 flows by packet count:");
    println!("{:-<70}", "");
    for (key, count) in flows.iter().take(10) {
        println!("{:50} {:>15} packets", key.to_filename(), count);
    }
    println!("{}", "=".repeat(70));

    info!("Split complete: {} files created", packet_counts.len());

    Ok(())
}
