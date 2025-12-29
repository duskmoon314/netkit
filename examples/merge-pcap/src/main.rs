use std::io::BufReader;
use std::{collections::BinaryHeap, fs::File, net::Ipv4Addr, path::PathBuf, time::Duration};

use anyhow::anyhow;

use clap::{ArgAction, Parser};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use indicatif_log_bridge::LogWrapper;
use log::error;
use log::{debug, info};
use netkit::capture::format::pcap::PcapWriter;
use netkit::capture::packet::Packet;
use netkit::capture::{CaptureFile, LinkType};
use netkit::capture::{CaptureWriter, open_file};
use netkit::packet::prelude::*;
use rand::seq::IndexedRandom;
use rand::{SeedableRng, rngs::StdRng};
use serde::Deserialize;

/// merge-pcap (netkit)
///
/// A tool to merge multiple pcap files into one based on the given requirements
#[derive(Debug, Parser, Deserialize)]
#[command(version, about, long_about)]
struct Cli {
    /// Erase the timestamp of packets
    ///
    /// If true, the program will remove the original timestamp of the packets
    /// in the pcap files, which is useful if the absolute time is not important
    /// for your analysis.
    #[arg(short, long, action = ArgAction::SetTrue)]
    erase_timestamp: Option<bool>,

    /// The config file to use
    ///
    /// If provided, the program will ignore the same option provided in the cli
    /// and use the config file instead.
    #[arg(short, long)]
    #[serde(skip)]
    config_file: Option<PathBuf>,

    /// The output file to write the merged pcap to
    #[arg(short, long)]
    output_file: Option<PathBuf>,

    /// The input files to merge
    ///
    /// When present in cli arguments, only the path is supported. If more
    /// options are needed, please use the config file.
    ///
    /// The pcap files should be in order, otherwise the output pcap may not be
    /// correct.
    #[arg(value_parser = InputFile::parse)]
    input_files: Vec<InputFile>,

    /// The snapshot length of the output pcap file
    #[arg(long)]
    snaplen: Option<u32>,

    /// The precision of the timestamp
    #[arg(long, action = ArgAction::SetTrue)]
    nanoseconds: Option<bool>,
}

impl Cli {
    fn merge_config(&mut self, config: &Cli) {
        if let Some(erase_timestamp) = config.erase_timestamp {
            self.erase_timestamp = Some(erase_timestamp);
        }

        if let Some(output_file) = config.output_file.clone() {
            self.output_file = Some(output_file);
        }

        if !config.input_files.is_empty() {
            self.input_files = config.input_files.clone();
        }

        if let Some(snaplen) = config.snaplen {
            self.snaplen = Some(snaplen);
        }

        if let Some(nanoseconds) = config.nanoseconds {
            self.nanoseconds = Some(nanoseconds);
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
#[serde(from = "String")]
enum IpMap {
    Ip(std::net::IpAddr),
    Net(ipnet::IpNet),
    Map(ipnet::IpNet, ipnet::IpNet),
}

impl From<String> for IpMap {
    fn from(value: String) -> Self {
        if let Ok(ip) = value.parse::<std::net::IpAddr>() {
            IpMap::Ip(ip)
        } else if let Ok(net) = value.parse::<ipnet::IpNet>() {
            IpMap::Net(net)
        } else {
            let parts: Vec<&str> = value.split(':').collect();
            if parts.len() == 2 {
                if let (Ok(src), Ok(dst)) = (parts[0].parse(), parts[1].parse()) {
                    IpMap::Map(src, dst)
                } else {
                    panic!("Invalid IP map format: {}", value);
                }
            } else {
                panic!("Invalid IP map format: {}", value);
            }
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
struct InputFile {
    /// The path to the input file
    path: PathBuf,

    /// The start time offset of each group of the input file
    ///
    /// The offset is considered in seconds. If erase_timestamp is true, the
    /// start time must be positive to arrange the packets sequentially. If
    /// erase_timestamp is false, the start time can be negative to shift the
    /// packets to the past.
    start_time: Vec<i32>,

    /// The number of times to repeat the input file in one group
    repeat: u32,

    /// The number of parallel input files
    parallel: u32,

    /// Rewrite source IP address
    srcipmap: Vec<IpMap>,

    /// Rewrite destination IP address
    dstipmap: Vec<IpMap>,
}

impl Default for InputFile {
    fn default() -> Self {
        InputFile {
            path: PathBuf::new(),
            start_time: vec![0],
            repeat: 1,
            parallel: 1,
            srcipmap: vec![],
            dstipmap: vec![],
        }
    }
}

impl InputFile {
    /// Parse the cli argument for input files
    fn parse(s: &str) -> Result<InputFile, clap::Error> {
        let path = PathBuf::from(s);

        Ok(InputFile {
            path,
            start_time: vec![0],
            repeat: 1,
            parallel: 1,
            srcipmap: vec![],
            dstipmap: vec![],
        })
    }

    fn into_iter(self, cli: &Cli, pg: ProgressBar) -> InputFileIterator {
        let reader = open_file(&self.path)
            .unwrap_or_else(|e| panic!("Unable to open pcap file {}: {}", self.path.display(), e));

        let src_ip_pool = self
            .srcipmap
            .iter()
            .filter(|m| {
                matches!(
                    m,
                    IpMap::Ip(std::net::IpAddr::V4(_)) | IpMap::Net(ipnet::IpNet::V4(_))
                )
            })
            .flat_map(|m| match m {
                IpMap::Ip(std::net::IpAddr::V4(ip)) => ipnet::Ipv4AddrRange::new(*ip, *ip),
                IpMap::Net(ipnet::IpNet::V4(net)) => net.hosts(),
                _ => unreachable!(),
            })
            .collect::<Vec<Ipv4Addr>>();
        let dst_ip_pool = self
            .dstipmap
            .iter()
            .filter(|m| {
                matches!(
                    m,
                    IpMap::Ip(std::net::IpAddr::V4(_)) | IpMap::Net(ipnet::IpNet::V4(_))
                )
            })
            .flat_map(|m| match m {
                IpMap::Ip(std::net::IpAddr::V4(ip)) => ipnet::Ipv4AddrRange::new(*ip, *ip),
                IpMap::Net(ipnet::IpNet::V4(net)) => net.hosts(),
                _ => unreachable!(),
            })
            .collect::<Vec<Ipv4Addr>>();

        InputFileIterator {
            file: self,
            reader,
            current: 0,
            original_first_packet_time: None,
            first_packet_time: None,
            last_packet_time: 0,
            erase_timestamp: cli.erase_timestamp.unwrap_or(false),
            pg,
            rng: StdRng::from_os_rng(),
            src_ip_pool,
            dst_ip_pool,
        }
    }
}

struct InputFileIterator {
    file: InputFile,
    reader: CaptureFile<BufReader<File>>,
    current: u32,
    original_first_packet_time: Option<i64>,
    first_packet_time: Option<i64>,
    last_packet_time: i64,
    erase_timestamp: bool,
    pg: ProgressBar,
    rng: StdRng,
    src_ip_pool: Vec<Ipv4Addr>,
    dst_ip_pool: Vec<Ipv4Addr>,
}

impl Iterator for InputFileIterator {
    type Item = Vec<Packet>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut packet = loop {
            match self.reader.next() {
                Some(Ok(pkt)) => break pkt,
                Some(Err(e)) => {
                    error!(
                        "Error reading packet from {}: {}",
                        self.file.path.display(),
                        e
                    );
                    continue;
                } // Skip errors
                None => {
                    self.current += 1;

                    if self.current == self.file.start_time.len() as u32 * self.file.repeat {
                        self.pg
                            .finish_with_message(format!("{} done", self.file.path.display()));

                        return None;
                    }

                    self.reader = open_file(&self.file.path).unwrap_or_else(|e| {
                        panic!(
                            "Unable to open pcap file {}: {}",
                            self.file.path.display(),
                            e
                        )
                    });
                    self.first_packet_time = None;
                }
            }
        };

        let timestamp = packet.timestamp_ns;

        if self.first_packet_time.is_none() {
            // A new start of pcap, may be repeat or a new group

            self.original_first_packet_time = Some(timestamp);

            let new_ts;
            if self.current.is_multiple_of(self.file.repeat) {
                // A new group

                if self.erase_timestamp {
                    new_ts = (self.file.start_time[(self.current / self.file.repeat) as usize]
                        as i64)
                        * 1_000_000_000;
                } else {
                    new_ts = timestamp
                        + (self.file.start_time[(self.current / self.file.repeat) as usize] as i64)
                            * 1_000_000_000;
                }
            } else {
                // same group, repeating
                new_ts = self.last_packet_time + 1_000_000_000;
            }

            self.first_packet_time = Some(new_ts);
            packet.timestamp_ns = new_ts;
        } else {
            // Same group same repeat subgroup
            // Calculate the time offset

            let current_packet_time = timestamp
                - self
                    .original_first_packet_time
                    .expect("No first packet time")
                + self.first_packet_time.expect("No first packet time");

            packet.timestamp_ns = current_packet_time;
        }

        self.last_packet_time = packet.timestamp_ns;

        self.pg.inc(1);

        let mut items = vec![packet; self.file.parallel as usize];

        if self.src_ip_pool.is_empty() && self.dst_ip_pool.is_empty() {
            return Some(items);
        }

        for item in items.iter_mut() {
            let mut eth = Eth::new(&mut item.data).expect("Failed to parse Ethernet header");

            let mut ipv4 = match eth.ipv4_mut() {
                Some(ipv4) => ipv4,
                None => {
                    // If no IPv4 header, skip IP rewriting
                    continue;
                }
            };

            // TODO: handle IpMap::Map case

            if !self.src_ip_pool.is_empty() {
                let src_ip = self.src_ip_pool.choose(&mut self.rng).unwrap();

                ipv4.src_mut().set(*src_ip);
            }

            if !self.dst_ip_pool.is_empty() {
                let dst_ip = self.dst_ip_pool.choose(&mut self.rng).unwrap();

                ipv4.dst_mut().set(*dst_ip);
            }
        }

        Some(items)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PacketHeapItem {
    index: usize,
    packet: Packet,
}

impl PartialOrd for PacketHeapItem {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PacketHeapItem {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Reverse ordering for min-heap
        other.packet.timestamp_ns.cmp(&self.packet.timestamp_ns)
    }
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
    let pg_style = ProgressStyle::with_template(
        "{prefix:3} [{elapsed_precise}] {human_pos:>12} pkts    {msg}",
    )?;

    let mut args = Cli::parse();

    if let Some(ref config_file) = args.config_file {
        match config_file.extension() {
            Some(ext) if ext == "json" => {
                let config = std::fs::read_to_string(config_file)?;
                let config: Cli = serde_json::from_str(&config)?;

                args.merge_config(&config);
            }
            None => {
                return Err(anyhow!(
                    "Cannot determine the file type of the config file. Please provide a file with .json extension."
                ));
            }
            _ => {
                return Err(anyhow!(
                    "Unsupported config file type. Please provide a file with .json extension."
                ));
            }
        }
    }

    debug!("Parsed arguments: {args:?}");

    let start = std::time::Instant::now();

    let output_file = args.output_file.clone().expect("Output file is required");

    let write_pg = multi.add(ProgressBar::no_length());
    write_pg.set_style(pg_style.clone());
    write_pg.set_prefix("OUT");
    write_pg.set_message(output_file.display().to_string());
    write_pg.enable_steady_tick(Duration::from_secs(1));

    let mut output_file = std::fs::File::create(&output_file)
        .map_err(|e| anyhow!("Failed to create output file: {}", e))?;

    let mut packet_heap: BinaryHeap<PacketHeapItem> =
        BinaryHeap::with_capacity(args.input_files.len());

    let mut input_files = args
        .input_files
        .iter()
        .map(|input_file| {
            let pg = multi.add(ProgressBar::no_length());
            pg.set_style(pg_style.clone());
            pg.set_prefix("IN");
            pg.set_message(input_file.path.display().to_string());
            pg.enable_steady_tick(Duration::from_secs(1));

            input_file.clone().into_iter(&args, pg)
        })
        .collect::<Vec<_>>();

    for (i, input_file) in input_files.iter_mut().enumerate() {
        if let Some(item) = input_file.next() {
            packet_heap.extend(
                item.into_iter()
                    .map(|packet| PacketHeapItem { index: i, packet }),
            );
        }
    }

    debug!("Packet heap initialized: {packet_heap:?}");

    let linktype = packet_heap
        .peek()
        .map(|item| item.packet.linktype)
        .unwrap_or(LinkType::Ethernet);

    let mut pcap_writer = PcapWriter::new(
        &mut output_file,
        false,
        args.nanoseconds.unwrap_or(false),
        args.snaplen.unwrap_or(65535),
        linktype,
    )
    .map_err(|e| anyhow!("Failed to create pcap writer: {}", e))?;

    while let Some(item) = packet_heap.pop() {
        // debug!("Processing packet: {item:?}");

        let input_file = &mut input_files[item.index];

        pcap_writer
            .write_packet(&item.packet)
            .map_err(|e| anyhow!("Failed to write packet: {}", e))?;

        write_pg.inc(1);

        if packet_heap.len() < args.input_files.len() {
            if let Some(next_item) = input_file.next() {
                packet_heap.extend(next_item.into_iter().map(|packet| PacketHeapItem {
                    index: item.index,
                    packet,
                }));
            }
        }
    }

    pcap_writer.flush()?;

    write_pg.finish_with_message("done");

    info!(
        "Merged pcap files into {}, taken {} seconds",
        args.output_file.unwrap().display(),
        start.elapsed().as_secs_f64()
    );

    Ok(())
}
