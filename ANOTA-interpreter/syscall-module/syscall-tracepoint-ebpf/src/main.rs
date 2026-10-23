#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{
        bpf_get_current_pid_tgid, bpf_probe_read_user, bpf_probe_read_user_buf,
        bpf_probe_read_user_str_bytes,
    },
    macros::{map, tracepoint},
    maps::{HashMap, PerCpuArray, RingBuf},
    programs::TracePointContext,
    Global,
};
use syscall_tracepoint_common::*;

// Set from the running kernel's tracefs format by the userspace loader.
// sched_process_fork changed from fixed comm arrays to dynamic strings.
#[no_mangle]
static FORK_CHILD_PID_OFFSET: Global<u32> = Global::new(0);
#[no_mangle]
static ENTER_ID_OFFSET: Global<u32> = Global::new(0);
#[no_mangle]
static ENTER_ARGS_OFFSET: Global<u32> = Global::new(0);
#[no_mangle]
static EXIT_RET_OFFSET: Global<u32> = Global::new(0);

#[map]
static WATCHED: HashMap<u32, u64> = HashMap::with_max_entries(32768, 0);
#[map]
static SESSIONS: HashMap<u64, u64> = HashMap::with_max_entries(1024, 0);
#[map]
static PENDING: HashMap<u32, Event> = HashMap::with_max_entries(4096, 0);
#[map]
static SCRATCH: PerCpuArray<Event> = PerCpuArray::with_max_entries(1, 0);
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(16 * 1024 * 1024, 0);
/// Ring-buffer exhaustion, map exhaustion, or incomplete syscall pairing.
#[map]
static LOST: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

fn lost() {
    if let Some(ptr) = LOST.get_ptr_mut(0) {
        unsafe {
            *ptr = (*ptr).wrapping_add(1);
        }
    }
}

unsafe fn prepare(kind: u32) -> Option<&'static mut Event> {
    let id = bpf_get_current_pid_tgid();
    let tid = id as u32;
    let session = *WATCHED.get(&tid)?;
    let generation = *SESSIONS.get(&session)?;
    let event = &mut *SCRATCH.get_ptr_mut(0)?;
    event.session = session;
    event.generation = generation;
    event.pid = (id >> 32) as u32;
    event.tid = tid;
    event.kind = kind;
    event.flags = 0;
    event.syscall = 0;
    event.result = 0;
    event.args = [0; 6];
    event.path_len = [0; 2];
    event.address_len = 0;
    event.reserved = 0;
    Some(event)
}

unsafe fn capture_address(event: &mut Event, address: u64, length: u64) {
    // Fixed size reads avoid a variable-sized verifier memory access.
    if address == 0 || length < 2 {
        return;
    }
    let Ok(family) = bpf_probe_read_user::<u16>(address as *const u16) else {
        event.flags |= CAPTURE_ERROR;
        return;
    };
    let n = match family {
        2 if length >= 16 => 16,
        10 if length >= 28 => 28,
        _ => 0,
    };
    if n != 0 {
        if bpf_probe_read_user_buf(address as *const u8, &mut event.address[..n]).is_ok() {
            event.address_len = n as u32;
        } else {
            event.flags |= CAPTURE_ERROR;
        }
    }
}

#[tracepoint]
pub fn sys_enter(ctx: TracePointContext) -> u32 {
    if unsafe { enter(&ctx) }.is_err() {
        lost();
    }
    0
}

unsafe fn enter(ctx: &TracePointContext) -> Result<(), i32> {
    let Some(event) = prepare(EVENT_SYSCALL) else {
        return Ok(());
    };
    event.syscall = ctx.read_at::<u64>(ENTER_ID_OFFSET.load() as usize)?;
    event.args = ctx.read_at::<[u64; 6]>(ENTER_ARGS_OFFSET.load() as usize)?;
    let specs = path_arguments(event.syscall);
    for i in 0..2 {
        let (arg, _) = specs[i];
        if arg >= 0 && arg < 6 {
            match bpf_probe_read_user_str_bytes(
                event.args[arg as usize] as *const u8,
                &mut event.paths[i],
            ) {
                Ok(bytes) => {
                    event.path_len[i] = bytes.len() as u32;
                    if bytes.len() >= PATH_LEN - 1 {
                        event.flags |= PATH_TRUNCATED;
                    }
                }
                Err(_) => event.flags |= CAPTURE_ERROR,
            }
        }
    }
    match event.syscall {
        42 | 49 => capture_address(event, event.args[1], event.args[2]),
        44 => capture_address(event, event.args[4], event.args[5]),
        46 | 307 => {
            // msghdr, or the first msghdr in sendmmsg's mmsghdr array.
            let name = bpf_probe_read_user::<u64>(event.args[1] as *const u64);
            let len = bpf_probe_read_user::<u32>((event.args[1] + 8) as *const u32);
            if let (Ok(name), Ok(len)) = (name, len) {
                capture_address(event, name, len as u64);
            } else {
                event.flags |= CAPTURE_ERROR;
            }
        }
        437 => {
            // openat2's open_how.flags
            match bpf_probe_read_user::<u64>(event.args[2] as *const u64) {
                Ok(flags) => event.args[2] = flags,
                Err(_) => event.flags |= CAPTURE_ERROR,
            }
        }
        435 => {
            // clone3's clone_args.flags, consumed by sched_process_fork
            match bpf_probe_read_user::<u64>(event.args[0] as *const u64) {
                Ok(flags) => event.args[0] = flags,
                Err(_) => event.flags |= CAPTURE_ERROR,
            }
        }
        _ => {}
    }
    PENDING.insert(event.tid, &*event, 0)?;
    Ok(())
}

#[tracepoint]
pub fn sys_exit(ctx: TracePointContext) -> u32 {
    unsafe {
        let tid = bpf_get_current_pid_tgid() as u32;
        if let Some(ptr) = PENDING.get_ptr_mut(&tid) {
            let event = &mut *ptr;
            if let Ok(result) = ctx.read_at::<i64>(EXIT_RET_OFFSET.load() as usize) {
                event.result = result;
                if EVENTS.output::<Event>(&*event, 0).is_err() {
                    lost();
                }
            } else {
                lost();
            }
            let _ = PENDING.remove(&tid);
        }
    }
    0
}

#[tracepoint]
pub fn process_fork(ctx: TracePointContext) -> u32 {
    unsafe {
        let Some(event) = prepare(EVENT_FORK) else {
            return 0;
        };
        let Ok(child) = ctx.read_at::<u32>(FORK_CHILD_PID_OFFSET.load() as usize) else {
            lost();
            return 0;
        };
        if let Some(parent) = PENDING.get(&event.tid) {
            if matches!(parent.syscall, 56 | 435) {
                event.args[0] = parent.args[0];
            }
        }
        event.result = child as i64;
        // Inherit in the kernel before the child can execute its first syscall.
        if WATCHED.insert(&child, &event.session, 0).is_err() {
            lost();
        }
        if EVENTS.output::<Event>(&*event, 0).is_err() {
            lost();
        }
    }
    0
}

#[tracepoint]
pub fn process_exit(_ctx: TracePointContext) -> u32 {
    unsafe {
        if let Some(event) = prepare(EVENT_EXIT) {
            // exit/exit_group do not have a normal syscall-exit event.
            if let Some(pending) = PENDING.get(&event.tid) {
                if matches!(pending.syscall, 60 | 231)
                    && EVENTS.output::<Event>(pending, 0).is_err()
                {
                    lost();
                }
            }
            if EVENTS.output::<Event>(&*event, 0).is_err() {
                lost();
            }
        }
        let tid = bpf_get_current_pid_tgid() as u32;
        let _ = PENDING.remove(&tid);
        let _ = WATCHED.remove(&tid);
    }
    0
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // BPF programs cannot unwind; all accesses above are bounds checked.
    unsafe { core::hint::unreachable_unchecked() }
}
