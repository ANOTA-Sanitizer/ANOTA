use aya_ebpf::{cty::c_int, helpers::{bpf_probe_read_user, bpf_probe_read_user_str_bytes}, programs::TracePointContext, BpfContext};
use syscall_tracepoint_common::{BUF, WATCH_CONFIG, MAX_PATH};
use aya_log_ebpf::info;

fn should_log(pid: u32) -> bool {
    unsafe {
        match WATCH_CONFIG.get_ptr(0) {
            Some(cfg_ptr) => {
                let cfg = *cfg_ptr;
                if cfg.enabled == 0 {
                    return false;
                }
                if cfg.target_pid != 0 && cfg.target_pid != pid {
                    return false;
                }
                true
            }
            None => false,
        }
    }
}

pub(super) fn try_enter_access(ctx: TracePointContext) -> Result<u32, u32> {
    let pid = ctx.pid();
    if !should_log(pid) {
        return Ok(0);
    }
    const FILENAME_OFFSET:usize = 16;
    let filename_addr: u64 = unsafe { ctx.read_at(FILENAME_OFFSET).map_err(|_| 0u32)?};
    // get the map-backed buffer that we're going to use as storage for the filename
    let buf = unsafe {
        let ptr = BUF.get_ptr_mut(0).ok_or(0u32)?;
        &mut *ptr
    };

    // read the filename
    let filename = unsafe {
        core::str::from_utf8_unchecked(bpf_probe_read_user_str_bytes(
            filename_addr as *const u8,
            &mut buf.buf,
        ).map_err(|_| 0u32)?)
    };

    if filename.len() < MAX_PATH {
        // log the filename
        info!(&ctx, "tracepoint sys_enter_access called with PID {} on file {}", pid, filename);
    }

    Ok(0)
}

pub(super) fn try_enter_open(ctx: TracePointContext) -> Result<u32, u32> {
    let pid = ctx.pid();
    if !should_log(pid) {
        return Ok(0);
    }
    const FILENAME_OFFSET:usize = 16;
    let filename_addr: u64 = unsafe { ctx.read_at(FILENAME_OFFSET).map_err(|_| 0u32)?};
    // get the map-backed buffer that we're going to use as storage for the filename
    let buf = unsafe {
        let ptr = BUF.get_ptr_mut(0).ok_or(0u32)?;
        &mut *ptr
    };

    // read the filename
    let filename = unsafe {
        core::str::from_utf8_unchecked(bpf_probe_read_user_str_bytes(
            filename_addr as *const u8,
            &mut buf.buf,
        ).map_err(|_| 0u32)?)
    };

    if filename.len() < MAX_PATH {
        // log the filename
        info!(&ctx, "tracepoint sys_enter_open called with PID {} on file {}", pid, filename);
    }

    Ok(0)
}

pub(super) fn try_exit_open(ctx: TracePointContext) -> Result<u32, u32> {
    let pid = ctx.pid();
    if !should_log(pid) {
        return Ok(0);
    }
    const FILE_DESCRIPTOR_OFFSET:usize = 16;
    let filedescriptor_addr: i64 = unsafe { ctx.read_at(FILE_DESCRIPTOR_OFFSET).map_err(|_| 0u32)?};
    let my_int: c_int = unsafe { bpf_probe_read_user(filedescriptor_addr as *const _).map_err(|_| 0u32)? };
    info!(&ctx, "tracepoint sys_exit_open called with PID {} and file descriptor {}", pid, my_int);
    Ok(0)
}

pub(super) fn try_exit_openat(ctx: TracePointContext) -> Result<u32, u32> {
    
    let pid = ctx.pid();
    if !should_log(pid) {
        return Ok(0);
    }
    const FILE_DESCRIPTOR_OFFSET:usize = 16;
    let filedescriptor_addr: i64 = unsafe { ctx.read_at(FILE_DESCRIPTOR_OFFSET).map_err(|_| 0u32)?};
    info!(&ctx, "tracepoint sys_exit_openat called with PID {} and file descriptor {}", pid, filedescriptor_addr);
    Ok(0)
}


pub(super) fn try_enter_openat(ctx: TracePointContext) -> Result<u32, u32> {
    let pid = ctx.pid();
    if !should_log(pid) {
        return Ok(0);
    }
    const FILENAME_OFFSET:usize = 24;
    let filename_addr: u64 = unsafe { ctx.read_at(FILENAME_OFFSET).map_err(|_| 0u32)?};
    // get the map-backed buffer that we're going to use as storage for the filename
    let buf = unsafe {
        let ptr = BUF.get_ptr_mut(0).ok_or(0u32)?;
        &mut *ptr
    };

    // read the filename
    let filename = unsafe {
        core::str::from_utf8_unchecked(bpf_probe_read_user_str_bytes(
            filename_addr as *const u8,
            &mut buf.buf,
        ).map_err(|_| 0u32)?)
    };

    if filename.len() < MAX_PATH {
        // log the filename
        info!(&ctx, "tracepoint sys_enter_openat called with PID {} on file {}", pid, filename);
    }

    Ok(0)
}

pub(super) fn try_enter_openat2(ctx: TracePointContext) -> Result<u32, u32> {
    let pid = ctx.pid();
    if !should_log(pid) {
        return Ok(0);
    }
    const FILENAME_OFFSET:usize = 24;
    let filename_addr: u64 = unsafe { ctx.read_at(FILENAME_OFFSET).map_err(|_| 0u32)?};
    // get the map-backed buffer that we're going to use as storage for the filename
    let buf = unsafe {
        let ptr = BUF.get_ptr_mut(0).ok_or(0u32)?;
        &mut *ptr
    };

    // read the filename
    let filename = unsafe {
        core::str::from_utf8_unchecked(bpf_probe_read_user_str_bytes(
            filename_addr as *const u8,
            &mut buf.buf,
        ).map_err(|_| 0u32)?)
    };

    if filename.len() < MAX_PATH {
        // log the filename
        info!(&ctx, "tracepoint sys_enter_openat2 called with PID {} on file {}", pid, filename);
    }

    Ok(0)
}


pub(super) fn try_enter_write(ctx: TracePointContext) -> Result<u32, u32> {
    let pid = ctx.pid();
    if !should_log(pid) {
        return Ok(0);
    }
    const FILE_DESCRIPTOR_OFFSET:usize = 16;
    let filedescriptor_addr: usize = unsafe { ctx.read_at(FILE_DESCRIPTOR_OFFSET).map_err(|_| 0u32)?};

    const CONTENT_OFFSET:usize = 24;
    let content_addr: u64 = unsafe { ctx.read_at(CONTENT_OFFSET).map_err(|_| 0u32)?};
    // get the map-backed buffer that we're going to use as storage for the content
    let buf = unsafe {
        let ptr = BUF.get_ptr_mut(0).ok_or(0u32)?;
        &mut *ptr
    };

    // read the content
    let content = unsafe {
        core::str::from_utf8_unchecked(bpf_probe_read_user_str_bytes(
            content_addr as *const u8,
            &mut buf.buf,
        ).map_err(|_| 0u32)?)
    };

    if content.len() < 20{
        info!(&ctx, "tracepoint sys_enter_write called with PID {} and file descriptor {} and write {}", pid, filedescriptor_addr, content);
    }
    else{
        info!(&ctx, "tracepoint sys_enter_write called with PID {} and file descriptor {} and write", pid, filedescriptor_addr);
    }
    Ok(0)
}

pub(super) fn try_enter_read(ctx: TracePointContext) -> Result<u32, u32> {
    let pid = ctx.pid();
    if !should_log(pid) {
        return Ok(0);
    }
    const FILE_DESCRIPTOR_OFFSET:usize = 16;
    let filedescriptor_addr: usize = unsafe { ctx.read_at(FILE_DESCRIPTOR_OFFSET).map_err(|_| 0u32)?};
    info!(&ctx, "tracepoint sys_enter_read called with PID {} and file descriptor {}", pid, filedescriptor_addr);
    Ok(0)
}
