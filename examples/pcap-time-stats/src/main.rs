use std::{collections::HashMap, fs::File, path::PathBuf, time::Duration};

use chrono::{DateTime, DurationRound, TimeDelta, Utc};
use clap::Parser;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use indicatif_log_bridge::LogWrapper;
use log::{debug, info};
use netkit::capture::file::pcap::PcapReader;
use serde::Serialize;

/// pcap-time-stats (netkit)
///
/// A tool reads a pcap file and writes a csv file with statistics over the time
/// intervals.
#[derive(Debug, Parser)]
#[command(version, about, long_about)]
struct Cli {
    /// Input pcap file
    input: PathBuf,

    /// Output csv file
    output: PathBuf,

    /// Duration of each statistic
    #[arg(short, long, default_value = "1s")]
    duration: humantime::Duration,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct Stats {
    /// time
    time: chrono::DateTime<Utc>,

    /// number of packets
    packets: usize,

    /// number of bytes
    bytes: usize,
}

impl PartialOrd for Stats {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.time.partial_cmp(&other.time)
    }
}

impl Ord for Stats {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.time.cmp(&other.time)
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

    let args = Cli::parse();

    debug!("Args: {:?}", args);

    let reader = PcapReader::new(File::open(&args.input)?);

    let pg = multi.add(ProgressBar::no_length());
    pg.set_style(ProgressStyle::with_template(
        "IN [{elapsed_precise}] {human_pos:>12} pkts    {msg}",
    )?);
    pg.set_message(args.input.display().to_string());
    pg.enable_steady_tick(Duration::from_secs(1));

    let nanoseconds = reader.nanoseconds;
    let duration: TimeDelta = TimeDelta::from_std(args.duration.into())?;

    let mut results: HashMap<DateTime<Utc>, Stats> = HashMap::new();

    for (header, _data) in pg.wrap_iter(reader) {
        let mut sec = header.ts_sec;
        let mut nsec = if nanoseconds {
            header.ts_usec
        } else {
            header.ts_usec * 1000
        };

        if nsec >= 1_000_000_000 {
            sec += nsec / 1_000_000_000;
            nsec %= 1_000_000_000;
        }

        let date_time = DateTime::from_timestamp(sec as i64, nsec)
            .ok_or(anyhow::anyhow!(
                "Invalid timestamp in packet header: {:?}",
                header
            ))?
            .duration_round(duration)?;

        let bytes = header.orig_len as usize;

        results
            .entry(date_time)
            .and_modify(|stat| {
                stat.packets += 1;
                stat.bytes += bytes;
            })
            .or_insert(Stats {
                time: date_time,
                packets: 1,
                bytes,
            });
    }

    let mut results: Vec<Stats> = results.into_values().collect();
    results.sort();

    let pg = multi.add(ProgressBar::new(results.len() as u64));
    pg.set_style(ProgressStyle::with_template(
        "OUT [{elapsed_precise}] {bar:40} {human_pos:>12} pkts    {msg}",
    )?);
    pg.set_message(args.output.display().to_string());
    pg.enable_steady_tick(Duration::from_secs(1));

    let mut writer = csv::Writer::from_path(&args.output)?;

    for stat in pg.wrap_iter(results.into_iter()) {
        writer.serialize(stat)?;
    }

    writer.flush()?;

    info!("Statistics written to {}", args.output.display());

    Ok(())
}
