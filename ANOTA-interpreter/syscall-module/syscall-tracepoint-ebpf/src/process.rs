use aya_ebpf::{programs::TracePointContext,helpers::bpf_probe_read_user_str_bytes,BpfContext};
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

pub(super) fn try_enter_execve(ctx: TracePointContext) -> Result<u32, u32> {
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
        info!(&ctx, "tracepoint sys_enter_execve called with PID {} on file {}", pid, filename);
    }

    Ok(0)
}
