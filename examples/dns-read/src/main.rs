use std::fs::File;
use std::io::BufReader;
use std::net::Ipv4Addr;
use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;
use log::{debug, error, info};
use netkit::capture::{LinkType, open_capture};
use netkit::packet::layer::eth;
use netkit::packet::prelude::*;

#[derive(Parser, Debug)]
#[command(author, version, about = "Read and parse DNS packets from pcap files")]
struct Args {
    /// Input pcap/pcapng file
    #[arg(value_name = "CAP_FILE")]
    input: PathBuf,
}

fn main() -> Result<()> {
    let args = Args::parse();

    env_logger::init();

    info!("Reading DNS packets from: {}", args.input.display());

    let file = File::open(&args.input)?;
    let reader = open_capture(BufReader::new(file))?;

    let mut total_packets = 0u64;
    let mut dns_packets = 0u64;
    let mut parse_errors = 0u64;

    for result in reader {
        let packet = result?;
        total_packets += 1;

        let ipv4 = match packet.linktype {
            LinkType::Ethernet => {
                let eth = Eth::new(&packet.data)?;
                if eth.eth_type().get() == EthType::Ipv4 {
                    Ipv4::new(&packet.data[eth::MIN_HEADER_LENGTH..])?
                } else {
                    debug!("Skipping non-IPv4 packet");
                    continue;
                }
            }
            _ => {
                error!("Unsupported link type: {:?}", packet.linktype);
                continue;
            }
        };

        if let Some(udp) = ipv4.udp() {
            // Check if it's DNS (port 53)
            let src_port = udp.src_port().get();
            let dst_port = udp.dst_port().get();

            if src_port != 53 && dst_port != 53 {
                debug!("Assume not DNS (ports: {} -> {})", src_port, dst_port);
                continue;
            }

            // Parse DNS layer
            let dns = match Dns::new(udp.payload()) {
                Ok(dns) => dns,
                Err(e) => {
                    error!("Failed to parse DNS packet: {}", e);
                    parse_errors += 1;
                    continue;
                }
            };

            dns_packets += 1;

            // Print DNS packet information
            print_dns_packet(&dns, src_port, dst_port);
        }
    }

    println!("\n=== Summary ===");
    println!("Total packets:  {}", total_packets);
    println!("DNS packets:    {}", dns_packets);
    println!("Parse errors:   {}", parse_errors);

    Ok(())
}

fn print_dns_packet(dns: &Dns<&[u8]>, src_port: u16, dst_port: u16) {
    println!("\n----- DNS {src_port} -> {dst_port} -----");
    println!("Transaction ID: 0x{:04x}", dns.id().get());

    print!("Flags: ");
    if dns.qr().get() {
        print!("QR ");
    }
    print!("Op({}) ", dns.opcode().get());
    if dns.aa().get() {
        print!("AA ");
    }
    if dns.tc().get() {
        print!("TC ");
    }
    if dns.rd().get() {
        print!("RD ");
    }
    if dns.ra().get() {
        print!("RA ");
    }
    println!("RCode({})", dns.rcode().get());

    // println!(
    //     "Questions: {} Answers: {} Authority: {} Additional: {}",
    //     dns.qdcount().get(),
    //     dns.ancount().get(),
    //     dns.nscount().get(),
    //     dns.arcount().get()
    // );

    if dns.qdcount().get() > 0 {
        println!("[Questions] {}", dns.qdcount().get());
        for (i, question) in dns.questions().enumerate() {
            let name = match dns.resolve_name(&question.qname()) {
                Ok(name) => name,
                Err(e) => {
                    error!("Failed to resolve question name: {}", e);
                    question.qname().to_string()
                }
            };

            println!(
                "  [{i}] {name} {} {}",
                question.qtype().get(),
                question.qclass().get()
            );
        }
    }

    if dns.ancount().get() > 0 {
        println!("[Answers] {}", dns.ancount().get());
        for (i, answer) in dns.answers().enumerate() {
            let name = match dns.resolve_name(&answer.name()) {
                Ok(name) => name,
                Err(e) => {
                    error!("Failed to resolve answer name: {}", e);
                    answer.name().to_string()
                }
            };

            print!(
                "  [{i}] {name} {} {} TTL={} ({} bytes)",
                answer.rrtype().get(),
                answer.class().get(),
                answer.ttl().get(),
                answer.rdata().len()
            );

            match answer.rrtype().get() {
                DnsRrType::A => {
                    let ip: [u8; 4] = answer.rdata().try_into().expect("Invalid A record length");
                    let ip = Ipv4Addr::from(ip);
                    println!(" -> {ip}");
                }

                DnsRrType::AAAA => {
                    let ip: [u8; 16] = answer
                        .rdata()
                        .try_into()
                        .expect("Invalid AAAA record length");
                    let ip = std::net::Ipv6Addr::from(ip);
                    println!(" -> {ip}");
                }

                DnsRrType::CNAME | DnsRrType::NS | DnsRrType::PTR => {
                    // RDATA is a domain name, try to resolve it
                    let rdata_name = unsafe { DnsName::new_unchecked(answer.rdata()) };
                    let target = match dns.resolve_name(&rdata_name) {
                        Ok(name) => name,
                        Err(e) => {
                            error!("Failed to resolve RDATA name: {}", e);
                            rdata_name.to_string()
                        }
                    };
                    println!(" -> {}", target);
                }

                DnsRrType::MX => {
                    let preference = u16::from_be_bytes([answer.rdata()[0], answer.rdata()[1]]);
                    let exchange_name = unsafe { DnsName::new_unchecked(&answer.rdata()[2..]) };
                    let exchange = match dns.resolve_name(&exchange_name) {
                        Ok(name) => name,
                        Err(e) => {
                            error!("Failed to resolve MX exchange name: {}", e);
                            exchange_name.to_string()
                        }
                    };

                    println!(" -> {} {}", preference, exchange);
                }

                DnsRrType::TXT => {
                    // TXT records are length-prefixed strings
                    let mut offset = 0;
                    let mut texts = Vec::new();
                    while offset < answer.rdata().len() {
                        let len = answer.rdata()[offset] as usize;
                        offset += 1;
                        if offset + len <= answer.rdata().len() {
                            if let Ok(text) =
                                std::str::from_utf8(&answer.rdata()[offset..offset + len])
                            {
                                texts.push(text);
                            }
                            offset += len;
                        } else {
                            break;
                        }
                    }
                    println!(" -> \"{}\"", texts.join(""));
                }

                t => {
                    println!();
                    error!("unsupported record type: {t}");
                }
            }
        }
    }

    if dns.nscount().get() > 0 {
        println!("[Authority] {}", dns.nscount().get());
        for (i, authority) in dns.authorities().enumerate() {
            let name = match dns.resolve_name(&authority.name()) {
                Ok(name) => name,
                Err(e) => {
                    error!("Failed to resolve authority name: {}", e);
                    authority.name().to_string()
                }
            };

            println!(
                "  [{i}] {name} {} {} TTL={} ({} bytes)",
                authority.rrtype().get(),
                authority.class().get(),
                authority.ttl().get(),
                authority.rdata().len()
            );
        }
    }

    if dns.arcount().get() > 0 {
        println!("[Additional] {}", dns.arcount().get());
        for (i, additional) in dns.additionals().enumerate() {
            let name = match dns.resolve_name(&additional.name()) {
                Ok(name) => name,
                Err(e) => {
                    error!("Failed to resolve additional name: {}", e);
                    additional.name().to_string()
                }
            };

            println!(
                "  [{i}] {name} {} {} TTL={} ({} bytes)",
                additional.rrtype().get(),
                additional.class().get(),
                additional.ttl().get(),
                additional.rdata().len()
            );
        }
    }
}
