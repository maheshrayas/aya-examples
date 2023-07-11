#![no_std]
#![no_main]

use aya_bpf::{
    bindings::__sk_buff,
    macros::{classifier, map},
    maps::PerfEventArray,
    programs::TcContext,
};
use aya_log_ebpf::info;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

use tc_perfbuf_common::TrafficLog;

#[map]
pub static DATA: PerfEventArray<TrafficLog> = PerfEventArray::new(0);

use core::mem;

use aya_bpf::bindings::TC_ACT_OK;

use memoffset::offset_of;

// #[allow(non_upper_case_globals)]
// #[allow(non_snake_case)]
// #[allow(non_camel_case_types)]
// #[allow(dead_code)]
// mod bindings;

// use bindings::{ethhdr, iphdr, ipv6hdr};

#[classifier(name = "tc")]
pub fn tc(ctx: TcContext) -> i32 {
    match unsafe { try_tc(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_tc(ctx: TcContext) -> Result<i32, i32> {
    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?; // (2)
    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {}
        _ => return Ok(TC_ACT_OK),
    }

    let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;

    // let if_index = ctx.ctx.ingress_ifindex;

    // info!(&ctx, "Meta len: {}", len,);

    let source_addr = u32::from_be(unsafe { (*ipv4hdr).src_addr });
    let dest_addr = u32::from_be(unsafe { (*ipv4hdr).dst_addr });

    let source_port = match unsafe { (*ipv4hdr).proto } {
        IpProto::Tcp => {
            let tcphdr: *const TcpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            u16::from_be(unsafe { (*tcphdr).source })
        }
        IpProto::Udp => {
            let udphdr: *const UdpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            u16::from_be(unsafe { (*udphdr).source })
        }
        _ => return Err(TC_ACT_OK),
    };

    let dest_port = match unsafe { (*ipv4hdr).proto } {
        IpProto::Tcp => {
            let tcphdr: *const TcpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            u16::from_be(unsafe { (*tcphdr).dest })
        }
        IpProto::Udp => {
            let udphdr: *const UdpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            u16::from_be(unsafe { (*udphdr).dest })
        }
        _ => return Err(TC_ACT_OK),
    };
    let tp = unsafe { (*ctx.skb.skb).ifindex };

    info!(
        &ctx,
        "destination ip: {}, source ip: {}, destination port: {}, source port: {}, classid {}",
        dest_addr,
        source_addr,
        dest_port,
        source_port,
        tp
    );

    unsafe {
        let log_entry = TrafficLog {
            source_addr,
            dest_addr,
            source_port,
            dest_port,
        };

        DATA.output(&ctx, &log_entry, 0);
    }

    Ok(TC_ACT_OK)
}

#[inline(always)]
unsafe fn ptr_at<T>(ctx: &TcContext, offset: usize) -> Result<*const T, i32> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(TC_ACT_OK);
    }

    Ok((start + offset) as *const T)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
