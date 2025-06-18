use std::{fs::File, path::PathBuf, time::Duration};

use anyhow::anyhow;
use clap::Parser;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use indicatif_log_bridge::LogWrapper;
use log::debug;
use netkit::{
    capture::file::pcap::{PcapReader, PcapWriter},
    packet::prelude::*,
};
use rand::{SeedableRng, rngs::StdRng, seq::IndexedRandom};

/// pcap-rewrite (netkit)
#[derive(Debug, Parser)]
#[command(version, about, long_about)]
struct Cli {
    /// Input pcap file
    input: PathBuf,

    /// Output pcap file
    output: PathBuf,

    /// Seed for randomization
    #[arg(short, long, default_value_t = 42)]
    seed: u64,

    /// Rewrite source IP address to value in this field
    #[arg(short = 'S', long, value_delimiter = ',')]
    srcipmap: Vec<IpMap>,

    /// Rewrite destination IPv4 address to value in this field
    #[arg(short = 'D', long, value_delimiter = ',')]
    dstipmap: Vec<IpMap>,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
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
        "[{elapsed_precise}] processed {human_pos:>12} pkts    {msg}",
    )?;

    let args = Cli::parse();

    debug!("Arguments: {:#?}", args);

    let pg = multi.add(ProgressBar::no_length().with_finish(indicatif::ProgressFinish::AndLeave));
    pg.set_style(pg_style.clone());
    pg.set_message(format!(
        "{} -> {}",
        args.input.display(),
        args.output.display()
    ));
    pg.enable_steady_tick(Duration::from_secs(1));

    let rdr = PcapReader::new(File::open(&args.input)?);

    let mut wtr = PcapWriter::new(
        File::create(&args.output)?,
        rdr.big_endian,
        rdr.nanoseconds,
        rdr.snaplen(),
    )?;

    let mut rng = StdRng::seed_from_u64(args.seed);

    let dst_ipv4_pool = args
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
        .collect::<Vec<_>>();

    for (hdr, data) in pg.wrap_iter(rdr) {
        let mut eth = Eth::new(data)?;

        if let Some(mut ipv4) = eth.ipv4_mut() {
            ipv4.dst_mut()
                .set(*dst_ipv4_pool.choose(&mut rng).ok_or(anyhow!(
                    "No dest IPv4 addresses available in the provided map"
                ))?);
        }

        wtr.write_packet(hdr, eth.inner())?;
    }

    Ok(())
}
