use thiserror::Error;

use aya::{
    include_bytes_aligned,
    maps::perf::AsyncPerfEventArray,
    programs::{Xdp, XdpFlags},
    util::online_cpus,
    Bpf,
};

#[derive(Error, Debug)]
pub enum Error {
    #[error("Ebpf Error: {source}")]
    BpfError {
        #[from]
        source: aya::BpfError,
    },

    #[error("Ebpf Program Load Error: {source}")]
    BpfProgramError {
        #[from]
        source: aya::programs::ProgramError,
    },
    #[error("Ebpf Map  Error: {source}")]
    BpfMapError {
        #[from]
        source: aya::maps::MapError,
    },
    #[error("IO Error: {source}")]
    IOError {
        #[from]
        source: std::io::Error,
    },
    #[error("Perf Buffer Error: {source}")]
    PerfBufferError {
        #[from]
        source: aya::maps::perf::PerfBufferError,
    },
    #[error("IllegalDocument")]
    IllegalDocument,
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
