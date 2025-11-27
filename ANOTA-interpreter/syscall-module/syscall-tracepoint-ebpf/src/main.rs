#![no_std]
#![no_main]
mod process;
mod file;

use aya_ebpf::{
    macros::tracepoint,
    programs::TracePointContext,
    
    
};
// use aya_log_ebpf::info;

#[tracepoint]
pub fn enter_access(ctx: TracePointContext) -> u32 {
    match file::try_enter_access(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[tracepoint]
pub fn enter_execve(ctx: TracePointContext) -> u32 {
    match process::try_enter_execve(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[tracepoint]
pub fn enter_open(ctx: TracePointContext) -> u32 {
    match file::try_enter_open(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[tracepoint]
pub fn exit_open(ctx: TracePointContext) -> u32 {
    match file::try_exit_open(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[tracepoint]
pub fn enter_openat(ctx: TracePointContext) -> u32 {
    match file::try_enter_openat(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[tracepoint]
pub fn exit_openat(ctx: TracePointContext) -> u32 {
    match file::try_exit_openat(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[tracepoint]
pub fn enter_openat2(ctx: TracePointContext) -> u32 {
    match file::try_enter_openat2(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[tracepoint]
pub fn enter_write(ctx: TracePointContext) -> u32 {
    match file::try_enter_write(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[tracepoint]
pub fn enter_read(ctx: TracePointContext) -> u32 {
    match file::try_enter_read(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
