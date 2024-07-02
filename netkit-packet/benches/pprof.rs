use std::io::Cursor;

use criterion::{criterion_group, criterion_main, Criterion};
// use deku::DekuReader;
use pprof::criterion::{Output, PProfProfiler};

use netkit_packet::prelude::*;

// const OPTS_SKIP_ETH_PAYLOAD: LayerOpts = LayerOpts {
//     skip_raw: false,
//     skip_eth_payload: true,
//     skip_ip_payload: false,
//     skip_tcp_payload: false,
//     skip_udp_payload: false,
// };

// const OPTS_SKIP_IP_PAYLOAD: LayerOpts = LayerOpts {
//     skip_raw: false,
//     skip_eth_payload: false,
//     skip_ip_payload: true,
//     skip_tcp_payload: false,
//     skip_udp_payload: false,
// };

const DATA: [u8; 46] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // dst mac
    0x06, 0x05, 0x04, 0x03, 0x02, 0x01, // src mac
    0x08, 0x00, // eth type ipv4
    0x45, // version 4, ihl 5
    0x00, // dscp 0, ecn 0
    0x00, 0x20, // total length 20 + 8 + 4 = 32
    0x00, 0x00, // identification 0
    0x00, 0x00, // flags 0, fragment offset 0
    0x40, // ttl 64
    0x11, // protocol udp
    0x00, 0x00, // checksum 0 (TODO: check this)
    0x7f, 0x00, 0x00, 0x01, // src ip
    0x7f, 0x00, 0x00, 0x02, // dst ip
    0x04, 0xd2, 0x04, 0xd3, // src port 1234, dst port 1235
    0x00, 0x0c, // length 12
    0x00, 0x00, // checksum 0 (TODO: check this)
    0x01, 0x02, 0x03, 0x04, // payload
];

// fn deku_read<T: for<'a> DekuReader<'a, Ctx>, Ctx>(
//     mut reader: impl deku::no_std_io::Read,
//     ctx: Ctx,
// ) {
//     let mut reader = deku::reader::Reader::new(&mut reader);
//     let _v = T::from_reader_with_ctx(&mut reader, ctx).unwrap();
// }

fn read_eth(c: &mut Criterion) {
    c.bench_function("read_eth_mac_addr", |b| {
        b.iter_batched(
            || &DATA[0..6],
            |data| EthAddr::from_slice(data),
            criterion::BatchSize::SmallInput,
        )
    });

    c.bench_function("read_eth_type", |b| {
        b.iter_batched(
            || &DATA[12..14],
            |data| EthType::from(u16::from_be_bytes([data[0], data[1]])),
            criterion::BatchSize::SmallInput,
        )
    });

    c.bench_function("read_eth_no_payload", |b| {
        b.iter_batched(
            || DATA.as_ref(),
            |data| Eth::new(data),
            criterion::BatchSize::SmallInput,
        )
    });

    c.bench_function("read_eth_ip_no_payload", |b| {
        b.iter_batched(
            || DATA,
            |data| Eth::new(data),
            criterion::BatchSize::SmallInput,
        )
    });
}

// fn read_ip(c: &mut Criterion) {
//     c.bench_function("read_ip_protocol", |b| {
//         b.iter_batched(
//             || Cursor::new(&DATA[9..10]),
//             |data| deku_read::<IpProtocol, ()>(data, ()),
//             criterion::BatchSize::SmallInput,
//         )
//     });

//     c.bench_function("read_ip_addr", |b| {
//         b.iter_batched(
//             || Cursor::new(&DATA[12..16]),
//             |data| deku_read::<Ipv4Addr, ()>(data, ()),
//             criterion::BatchSize::SmallInput,
//         )
//     });

//     c.bench_function("read_ip_no_payload", |b| {
//         b.iter_batched(
//             || DATA[14..].as_ref(),
//             |data| Ipv4::from_reader(data, OPTS_SKIP_IP_PAYLOAD),
//             criterion::BatchSize::SmallInput,
//         )
//     });
// }

criterion_group! {
    name = benches;
    config = Criterion::default().with_profiler(PProfProfiler::new(100, Output::Flamegraph(None)));
    targets = read_eth,
}
criterion_main!(benches);
