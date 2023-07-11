use std::{mem, net::Ipv4Addr, ptr};

use aya::{
    include_bytes_aligned,
    maps::perf::AsyncPerfEventArray,
    programs::{tc, SchedClassifier, TcAttachType},
    util::online_cpus,
    Bpf,
};
use aya_log::BpfLogger;

use bytes::BytesMut;
use clap::Parser;

use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};
use tokio::signal;
mod error;

use crate::error::*;
use tc_perfbuf_common::TrafficLog;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "lo")]
    iface: String,
}

#[tokio::main]
async fn main() -> Result<(), crate::Error> {
    let opt = Opt::parse();

    env_logger::init();

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/tc-perfbuf"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/tc-perfbuf"
    ))?;

    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        println!("failed to initialize eBPF logger: {}", e);
    }
    // error adding clsact to the interface if it is already added is harmless
    // the full cleanup can be done with 'sudo tc qdisc del dev eth0 clsact'.
    let _ = tc::qdisc_add_clsact(&opt.iface);
    let program: &mut SchedClassifier = bpf.program_mut("tc").unwrap().try_into()?;
    program.load()?;
    let egress_linkid = program.attach(&opt.iface, TcAttachType::Egress)?;
    let ingress_linkid = program.attach(&opt.iface, TcAttachType::Ingress)?;

    println!("Ingress linkid {:?}", ingress_linkid);
    println!("Egress linkid {:?}", egress_linkid);

    // let cpus = online_cpus()?;
    // let num_cpus = cpus.len();
    // let mut events = AsyncPerfEventArray::try_from(bpf.map_mut("DATA")?)?;

    // for cpu in cpus {
    //     let mut buf = events.open(cpu, None)?;

    //     tokio::task::spawn(async move {
    //         let mut buffers = (0..num_cpus)
    //             .map(|_| BytesMut::with_capacity(9000))
    //             .collect::<Vec<_>>();

    //         loop {
    //             let events = buf.read_events(&mut buffers).await.unwrap();
    //             for i in 0..events.read {}
    //         }
    //     });
    // }

    println!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    println!("Exiting...");

    Ok(())
}
