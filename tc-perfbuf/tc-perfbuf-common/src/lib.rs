#![no_std]

#[derive(Debug, Copy, Clone)]
#[repr(C)]

pub struct TrafficLog {
    pub source_addr: u32, // ipv4 source IP address
    pub dest_addr: u32,   // ipv4 destination IP address
    pub source_port: u16, // TCP or UDP remote port (sport for ingress)
    pub dest_port: u16,   // TCP or UDP local port (dport for ingress)
}
#[cfg(feature = "user")]
pub mod user {
    use super::*;

    unsafe impl aya::Pod for TrafficLog {}
}

unsafe impl Send for TrafficLog {}
