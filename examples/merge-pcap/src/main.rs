use std::{collections::BinaryHeap, fs::File, path::PathBuf, time::Duration};

use anyhow::anyhow;

use clap::Parser;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use indicatif_log_bridge::LogWrapper;
use log::{debug, info};
use netkit::capture::file::pcap::{PacketHeader, PcapReader, PcapWriter};
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
    #[arg(short, long)]
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
    #[arg(long)]
    nano_seconds: Option<bool>,
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

        if let Some(nano_seconds) = config.nano_seconds {
            self.nano_seconds = Some(nano_seconds);
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
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
}

impl InputFile {
    /// Parse the cli argument for input files
    fn parse(s: &str) -> Result<InputFile, clap::Error> {
        let path = PathBuf::from(s);

        Ok(InputFile {
            path,
            start_time: vec![0],
            repeat: 1,
        })
    }

    fn into_iter(self, cli: &Cli, pg: ProgressBar) -> InputFileIterator {
        let reader = PcapReader::new(File::open(&self.path).unwrap());

        InputFileIterator {
            path: self.path.clone(),
            reader,
            start_time: self.start_time.clone(),
            repeat: self.repeat,
            current: 0,
            original_first_packet_time: None,
            first_packet_time: None,
            last_packet_time: (0, 0),
            nano_seconds: cli.nano_seconds.unwrap_or(false),
            erase_timestamp: cli.erase_timestamp.unwrap_or(false),
            pg,
        }
    }
}

#[derive(Debug)]
struct InputFileIterator {
    path: PathBuf,
    reader: PcapReader<File>,
    start_time: Vec<i32>,
    repeat: u32,
    current: u32,
    original_first_packet_time: Option<u64>,
    first_packet_time: Option<(u32, u32)>,
    last_packet_time: (u32, u32),
    nano_seconds: bool,
    erase_timestamp: bool,
    pg: ProgressBar,
}

impl Iterator for InputFileIterator {
    type Item = (PacketHeader, Vec<u8>);

    fn next(&mut self) -> Option<Self::Item> {
        let mut item = loop {
            match self.reader.next_packet() {
                Some(item) => break item,
                None => {
                    self.current += 1;

                    if self.current == self.start_time.len() as u32 * self.repeat {
                        self.pg
                            .finish_with_message(format!("{} done", self.path.display()));

                        return None;
                    }

                    self.reader = PcapReader::new(File::open(&self.path).unwrap());
                    self.first_packet_time = None;
                }
            }
        };

        let time_scale: u64 = if self.reader.nano_seconds {
            1_000_000_000
        } else {
            1_000_000
        };

        // let temp_last_packet_time = self.last_packet_time;
        // self.last_packet_time = (item.0.ts_sec, item.0.ts_usec);

        if self.first_packet_time.is_none() {
            // A new start of pcap, may be repeat or a new group

            // self.first_packet_time = Some((item.0.ts_sec, item.0.ts_usec));
            self.original_first_packet_time =
                Some(item.0.ts_sec as u64 * time_scale + item.0.ts_usec as u64);

            if self.current % self.repeat == 0 {
                // A new group

                if self.erase_timestamp {
                    item.0.ts_sec = self.start_time[(self.current / self.repeat) as usize] as u32;
                    item.0.ts_usec = 0;
                } else {
                    item.0.ts_sec = (item.0.ts_sec as i32
                        + self.start_time[(self.current / self.repeat) as usize])
                        as u32;
                }
            } else {
                // same group, repeating

                item.0.ts_sec = self.last_packet_time.0 + 1;
                item.0.ts_usec = 0;
            }

            self.first_packet_time = Some((item.0.ts_sec, item.0.ts_usec));
        } else {
            // Same group same repeat subgroup
            // Calculate the time offset

            let current_packet_time = item.0.ts_sec as u64 * time_scale + item.0.ts_usec as u64;

            let current_packet_time = current_packet_time
                - self
                    .original_first_packet_time
                    .expect("No first packet time");

            item.0.ts_sec =
                (current_packet_time / time_scale) as u32 + self.first_packet_time.unwrap().0;
            item.0.ts_usec =
                (current_packet_time % time_scale) as u32 + self.first_packet_time.unwrap().1;
        }

        self.last_packet_time = (item.0.ts_sec, item.0.ts_usec);

        match (self.nano_seconds, self.reader.nano_seconds) {
            (true, false) => item.0.ts_usec *= 1000,
            (false, true) => item.0.ts_usec /= 1000,
            _ => {}
        }

        self.pg.inc(1);

        Some(item)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PacketHeapItem {
    index: usize,
    header: PacketHeader,
    data: Vec<u8>,
}

impl PartialOrd for PacketHeapItem {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PacketHeapItem {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        if self.header.ts_sec == other.header.ts_sec {
            self.header.ts_usec.cmp(&other.header.ts_usec).reverse()
        } else {
            self.header.ts_sec.cmp(&other.header.ts_sec).reverse()
        }
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

    let mut pcap_writer = PcapWriter::new(
        &mut output_file,
        false,
        args.nano_seconds.unwrap_or(false),
        args.snaplen.unwrap_or(65535),
    )
    .map_err(|e| anyhow!("Failed to create pcap writer: {}", e))?;

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
            packet_heap.push(PacketHeapItem {
                index: i,
                header: item.0,
                data: item.1,
            });
        }
    }

    debug!("Packet heap initialized: {packet_heap:?}");

    while let Some(item) = packet_heap.pop() {
        // debug!("Processing packet: {item:?}");

        let input_file = &mut input_files[item.index];

        pcap_writer
            .write_packet(item.header, &item.data)
            .map_err(|e| anyhow!("Failed to write packet: {}", e))?;

        write_pg.inc(1);

        if let Some(next_item) = input_file.next() {
            packet_heap.push(PacketHeapItem {
                index: item.index,
                header: next_item.0,
                data: next_item.1,
            });
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
