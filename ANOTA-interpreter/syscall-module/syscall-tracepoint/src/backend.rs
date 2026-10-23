use anyhow::{bail, ensure, Context, Result};
use aya::{
    maps::{HashMap, MapData, PerCpuArray, RingBuf},
    programs::TracePoint,
    Ebpf, EbpfLoader,
};
use std::{collections::HashSet, fs, path::Path};
use syscall_tracepoint_common::Event;

fn field_offset(format: &str, field: &str, size: u32) -> Result<u32> {
    for line in format.lines() {
        let parts: Vec<_> = line.split(';').map(str::trim).collect();
        let Some(declaration) = parts.first().and_then(|s| s.strip_prefix("field:")) else {
            continue;
        };
        let name = declaration.split_whitespace().last().unwrap_or("");
        if name.split('[').next() != Some(field) {
            continue;
        }
        let number = |key: &str| -> Result<u32> {
            parts
                .iter()
                .find_map(|s| s.strip_prefix(key))
                .with_context(|| format!("missing {key} for tracepoint field {field}"))?
                .trim()
                .parse()
                .context("invalid tracepoint field number")
        };
        ensure!(
            number("size:")? == size,
            "unsupported size of tracepoint field {field}"
        );
        let offset = number("offset:")?;
        ensure!(
            offset >= 8 && offset <= 4096 - size,
            "invalid tracepoint field offset: {field}"
        );
        return Ok(offset);
    }
    bail!("missing tracepoint field {field}")
}

fn tracepoint_offset(event: &str, field: &str, size: u32) -> Result<u32> {
    let mut last_error = None;
    for root in ["/sys/kernel/tracing", "/sys/kernel/debug/tracing"] {
        let path = format!("{root}/events/{event}/format");
        match fs::read_to_string(&path) {
            Ok(format) => return field_offset(&format, field, size).with_context(|| path),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap()).with_context(|| format!("read {event}/format from tracefs"))
}

pub struct Kernel {
    _bpf: Ebpf,
    watched: HashMap<MapData, u32, u64>,
    sessions: HashMap<MapData, u64, u64>,
    events: RingBuf<MapData>,
    lost: PerCpuArray<MapData, u64>,
    last_lost: u64,
}

impl Kernel {
    pub fn load(path: &Path) -> Result<Self> {
        anyhow::ensure!(
            cfg!(target_arch = "x86_64"),
            "the syscall decoder currently supports native x86_64 Linux only"
        );
        let child_pid = tracepoint_offset("sched/sched_process_fork", "child_pid", 4)?;
        let enter_id = tracepoint_offset("raw_syscalls/sys_enter", "id", 8)?;
        let enter_args = tracepoint_offset("raw_syscalls/sys_enter", "args", 48)?;
        let exit_ret = tracepoint_offset("raw_syscalls/sys_exit", "ret", 8)?;
        let mut bpf = EbpfLoader::new()
            .override_global("FORK_CHILD_PID_OFFSET", &child_pid, true)
            .override_global("ENTER_ID_OFFSET", &enter_id, true)
            .override_global("ENTER_ARGS_OFFSET", &enter_args, true)
            .override_global("EXIT_RET_OFFSET", &exit_ret, true)
            .load_file(path)
            .context("load eBPF object (requires BPF/perf privileges)")?;
        let watched = HashMap::try_from(bpf.take_map("WATCHED").context("WATCHED map")?)?;
        let sessions = HashMap::try_from(bpf.take_map("SESSIONS").context("SESSIONS map")?)?;
        let events = RingBuf::try_from(bpf.take_map("EVENTS").context("EVENTS map")?)?;
        let lost = PerCpuArray::try_from(bpf.take_map("LOST").context("LOST map")?)?;
        // Attach lifecycle hooks before enabling any watched processes.
        for (program, category, point) in [
            ("process_fork", "sched", "sched_process_fork"),
            ("process_exit", "sched", "sched_process_exit"),
            ("sys_exit", "raw_syscalls", "sys_exit"),
            ("sys_enter", "raw_syscalls", "sys_enter"),
        ] {
            let p: &mut TracePoint = bpf
                .program_mut(program)
                .context("missing tracepoint program")?
                .try_into()?;
            p.load().with_context(|| format!("verify {program}"))?;
            p.attach(category, point)
                .with_context(|| format!("attach {category}:{point}"))?;
        }
        Ok(Self {
            _bpf: bpf,
            watched,
            sessions,
            events,
            lost,
            last_lost: 0,
        })
    }
    pub fn install(&mut self, session: u64, generation: u64, tids: &[u32]) -> Result<()> {
        self.sessions.insert(session, generation, 0)?;
        for tid in tids {
            self.watched.insert(*tid, session, 0)?;
        }
        Ok(())
    }
    pub fn update(&mut self, session: u64, generation: u64) -> Result<()> {
        self.sessions.insert(session, generation, 0)?;
        Ok(())
    }
    pub fn stop(&mut self, session: u64) -> Result<Vec<u32>> {
        // Disable capture first, then remove all surviving descendants/threads.
        self.sessions.remove(&session)?;
        let tids: Vec<_> = self
            .watched
            .iter()
            .filter_map(|entry| entry.ok())
            .filter_map(|(tid, s)| (s == session).then_some(tid))
            .collect();
        for tid in &tids {
            let _ = self.watched.remove(tid);
        }
        Ok(tids)
    }
    pub fn next(&mut self) -> Option<Event> {
        while let Some(bytes) = self.events.next() {
            if bytes.len() == std::mem::size_of::<Event>() {
                // Ring records need not have Rust's struct alignment.
                return Some(unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast::<Event>()) });
            }
            eprintln!(
                "ANOTA_SYSCALL monitor warning: unexpected event size {}",
                bytes.len()
            );
        }
        None
    }
    pub fn report_loss(&mut self) {
        if let Ok(counts) = self.lost.get(&0, 0) {
            let total: u64 = counts.iter().sum();
            if total != self.last_lost {
                eprintln!("ANOTA_SYSCALL monitor warning: {} events lost (ring/map capacity); coverage is incomplete",total-self.last_lost);
                self.last_lost = total;
            }
        }
    }
    pub fn live_sessions(&self) -> HashSet<u64> {
        self.watched
            .iter()
            .filter_map(|entry| entry.ok().map(|(_, s)| s))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fork_formats_with_fixed_and_dynamic_comm() {
        let old = "field:char parent_comm[16]; offset:8; size:16; signed:1;\n\
                   field:pid_t parent_pid; offset:24; size:4; signed:1;\n\
                   field:char child_comm[16]; offset:28; size:16; signed:1;\n\
                   field:pid_t child_pid; offset:44; size:4; signed:1;";
        let new = "field:__data_loc char[] parent_comm; offset:8; size:4; signed:0;\n\
                   field:pid_t parent_pid; offset:12; size:4; signed:1;\n\
                   field:__data_loc char[] child_comm; offset:16; size:4; signed:0;\n\
                   field:pid_t child_pid; offset:20; size:4; signed:1;";
        assert_eq!(field_offset(old, "child_pid", 4).unwrap(), 44);
        assert_eq!(field_offset(new, "child_pid", 4).unwrap(), 20);
        assert!(field_offset(new, "child_pid", 8).is_err());
        assert!(field_offset(new, "missing", 4).is_err());
    }

    #[test]
    fn syscall_argument_array_offset() {
        let format = "field:long id; offset:8; size:8; signed:1;\n\
                      field:unsigned long args[6]; offset:16; size:48; signed:0;";
        assert_eq!(field_offset(format, "id", 8).unwrap(), 8);
        assert_eq!(field_offset(format, "args", 48).unwrap(), 16);
        assert!(field_offset("field:long ret; size:8;", "ret", 8).is_err());
        assert!(field_offset("field:long ret; offset:4096; size:8;", "ret", 8).is_err());
    }
}
