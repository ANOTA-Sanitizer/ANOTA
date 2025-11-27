#![no_std]
use aya_ebpf::maps::{PerCpuArray, Array};
use aya_ebpf::macros::map;

pub const MAX_PATH: usize = 4096;
#[repr(C)]
pub struct Buf {
    pub buf: [u8; MAX_PATH],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct WatchConfig {
    pub enabled: u32,
    pub target_pid: u32,
}

#[map]
pub static mut BUF: PerCpuArray<Buf> = PerCpuArray::with_max_entries(1, 0);

#[map]
pub static mut WATCH_CONFIG: Array<WatchConfig> = Array::with_max_entries(1, 0);
