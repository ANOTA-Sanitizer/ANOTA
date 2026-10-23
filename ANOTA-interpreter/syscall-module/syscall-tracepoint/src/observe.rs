use crate::policy::{normalize, Observation};
use anyhow::{Context, Result};
use std::{
    cell::RefCell,
    collections::HashMap,
    fs,
    net::{Ipv4Addr, Ipv6Addr},
    path::{Path, PathBuf},
    rc::Rc,
};
use syscall_tracepoint_common::*;

#[derive(Clone, Debug)]
enum Fd {
    File(PathBuf),
    Socket {
        protocol: Option<String>,
        ip: Option<String>,
    },
    Other,
}

#[derive(Clone)]
struct Task {
    cwd: Rc<RefCell<PathBuf>>,
    fds: Rc<RefCell<HashMap<i32, Fd>>>,
}

fn proc_fd(pid: u32, fd: i32) -> Option<Fd> {
    let path = fs::read_link(format!("/proc/{pid}/fd/{fd}")).ok()?;
    let text = path.to_string_lossy();
    if text.starts_with('/') {
        Some(Fd::File(PathBuf::from(text.trim_end_matches(" (deleted)"))))
    } else if text.starts_with("socket:") {
        Some(Fd::Socket {
            protocol: None,
            ip: None,
        })
    } else {
        Some(Fd::Other)
    }
}

fn initial_task(pid: u32) -> Result<Task> {
    let cwd = fs::read_link(format!("/proc/{pid}/cwd")).context("read tracee cwd")?;
    let mut fds = HashMap::new();
    for entry in fs::read_dir(format!("/proc/{pid}/fd"))
        .context("read tracee fds")?
        .flatten()
    {
        if let Ok(fd) = entry.file_name().to_string_lossy().parse() {
            if let Some(info) = proc_fd(pid, fd) {
                fds.insert(fd, info);
            }
        }
    }
    Ok(Task {
        cwd: Rc::new(RefCell::new(cwd)),
        fds: Rc::new(RefCell::new(fds)),
    })
}

#[derive(Default)]
pub struct Observer {
    tasks: HashMap<u32, Task>,
}

impl Observer {
    pub fn seed(&mut self, pid: u32, tids: &[u32]) -> Result<()> {
        let task = initial_task(pid)?;
        for tid in tids {
            self.tasks.insert(*tid, task.clone());
        }
        Ok(())
    }

    pub fn forget(&mut self, tids: &[u32]) {
        for tid in tids {
            self.tasks.remove(tid);
        }
    }

    pub fn observe(&mut self, event: &Event) -> Observation {
        let mut out = Observation::default();
        if event.kind == EVENT_EXIT {
            self.tasks.remove(&event.tid);
            return out;
        }
        if let std::collections::hash_map::Entry::Vacant(entry) = self.tasks.entry(event.tid) {
            match initial_task(event.pid) {
                Ok(task) => {
                    entry.insert(task);
                }
                Err(_) => {
                    out.incomplete
                        .push("cannot read tracee cwd/fd state".into());
                    entry.insert(Task {
                        cwd: Rc::new(RefCell::new(PathBuf::from("/"))),
                        fds: Rc::new(RefCell::new(HashMap::new())),
                    });
                }
            }
        }
        let task = self.tasks[&event.tid].clone();
        if event.kind == EVENT_FORK {
            let flags = event.args[0];
            self.tasks.insert(
                event.result as u32,
                Task {
                    cwd: if flags & 0x200 != 0 {
                        task.cwd.clone()
                    } else {
                        Rc::new(RefCell::new(task.cwd.borrow().clone()))
                    },
                    fds: if flags & 0x400 != 0 {
                        task.fds.clone()
                    } else {
                        Rc::new(RefCell::new(task.fds.borrow().clone()))
                    },
                },
            );
            return out;
        }
        if event.flags != 0 {
            out.incomplete
                .push(format!("argument capture flags={}", event.flags));
        }
        let nr = event.syscall;
        let mut path_values = Vec::new();
        for (slot, (arg, dirarg)) in path_arguments(nr).into_iter().enumerate() {
            if arg < 0 {
                continue;
            }
            let n = event.path_len[slot] as usize;
            if n >= PATH_LEN {
                out.incomplete.push("invalid path length".into());
                continue;
            }
            if n == 0 && event.flags & CAPTURE_ERROR != 0 {
                continue;
            }
            let raw = String::from_utf8_lossy(&event.paths[slot][..n]);
            let base = if dirarg < 0 || event.args[dirarg as usize] as i32 == AT_FDCWD {
                Some(task.cwd.borrow().clone())
            } else {
                match get_fd(&task, event.pid, event.args[dirarg as usize] as i32) {
                    Some(Fd::File(path)) => Some(path),
                    _ => None,
                }
            };
            if raw.starts_with('/') || base.is_some() {
                let full = if raw.starts_with('/') {
                    PathBuf::from(raw.as_ref())
                } else {
                    base.unwrap().join(raw.as_ref())
                };
                let resolved = resolve_path(event.pid, &full);
                path_values.push(resolved.clone());
                out.paths.push(resolved.to_string_lossy().into_owned());
            } else {
                out.incomplete
                    .push(format!("cannot resolve dirfd for path {raw:?}"));
            }
        }
        let fd_index = fd_argument(nr);
        let mut fds = Vec::new();
        if let Some(i) = fd_index {
            fds.push(event.args[i] as i32);
        }
        if nr == 40 {
            fds.push(event.args[0] as i32);
        }
        if nr == 275 || nr == 326 {
            fds.push(event.args[2] as i32);
        }
        let mut network = is_network(nr);
        for fd in fds {
            match get_fd(&task, event.pid, fd) {
                Some(Fd::File(path)) => out.paths.push(path.to_string_lossy().into_owned()),
                Some(Fd::Socket { protocol, ip }) => {
                    network = true;
                    if let Some(p) = protocol {
                        out.protocols.push(p);
                    }
                    if let Some(ip) = ip {
                        out.ips.push(ip);
                    }
                }
                Some(Fd::Other) => {}
                None if fd >= 0 => out.incomplete.push(format!("cannot resolve fd {fd}")),
                None => {}
            }
        }
        if nr == 41 || nr == 53 {
            let proto = protocol(event.args[0], event.args[1], event.args[2]);
            if let Some(p) = proto {
                out.protocols.push(p);
            }
        }
        let endpoint = address(event);
        if let Some(ip) = endpoint.as_ref() {
            out.ips = vec![ip.clone()];
        }
        if network {
            out.scopes.push("NETWORK".into());
        }
        if !out.paths.is_empty() {
            out.scopes.push("FILE".into());
        }
        if is_read(nr) || (nr == 9 && event.args[2] & 1 != 0) {
            out.scopes.push("READ".into());
        }
        if is_write(nr) || (nr == 9 && event.args[2] & 2 != 0) {
            out.scopes.push("WRITE".into());
        }
        if matches!(nr, 59 | 322) {
            out.scopes.push("EXECVE".into());
        }
        if matches!(nr, 2 | 257 | 437) {
            out.scopes.push("OPEN".into());
            let flags = if nr == 2 {
                event.args[1]
            } else {
                event.args[2]
            };
            if flags & 3 != 1 {
                out.scopes.push("READ".into());
            }
            if flags & 3 != 0 || flags & (0x40 | 0x200) != 0 {
                out.scopes.push("WRITE".into());
            }
        }
        out.paths.sort();
        out.paths.dedup();
        out.protocols.sort();
        out.protocols.dedup();
        if event.result >= 0 {
            let mut table = task.fds.borrow_mut();
            match nr {
                2 | 257 | 437 => {
                    if let Some(path) = path_values.first() {
                        // The fd may already be closed when userspace drains the ring.
                        table.insert(event.result as i32, Fd::File(path.clone()));
                    }
                }
                3 => {
                    table.remove(&(event.args[0] as i32));
                }
                436 => {
                    let (first, last) = (event.args[0], event.args[1]);
                    // CLOSE_RANGE_CLOEXEC marks descriptors; it does not close them now.
                    if event.args[2] & 4 == 0 {
                        table.retain(|fd, _| (*fd as u64) < first || (*fd as u64) > last);
                    }
                }
                32 | 33 | 292 | 72 if nr != 72 || matches!(event.args[1], 0 | 1030) => {
                    if let Some(info) = table.get(&(event.args[0] as i32)).cloned() {
                        table.insert(event.result as i32, info);
                    }
                }
                41 => {
                    table.insert(
                        event.result as i32,
                        Fd::Socket {
                            protocol: protocol(event.args[0], event.args[1], event.args[2]),
                            ip: None,
                        },
                    );
                }
                42 => {
                    let fd = event.args[0] as i32;
                    let proto = match table.get(&fd) {
                        Some(Fd::Socket { protocol, .. }) => protocol.clone(),
                        _ => None,
                    };
                    table.insert(
                        fd,
                        Fd::Socket {
                            protocol: proto,
                            ip: endpoint,
                        },
                    );
                }
                43 | 288 => {
                    let info = table
                        .get(&(event.args[0] as i32))
                        .cloned()
                        .unwrap_or(Fd::Socket {
                            protocol: None,
                            ip: None,
                        });
                    table.insert(event.result as i32, info);
                }
                80 => {
                    if let Some(path) = path_values.first() {
                        *task.cwd.borrow_mut() = path.clone();
                    }
                }
                81 => {
                    if let Some(Fd::File(path)) = table.get(&(event.args[0] as i32)) {
                        *task.cwd.borrow_mut() = path.clone();
                    }
                }
                _ => {}
            }
            drop(table);
            if matches!(nr, 59 | 322) {
                // exec unshares descriptor tables and applies close-on-exec.
                if let Ok(new_task) = initial_task(event.pid) {
                    self.tasks.insert(event.tid, new_task);
                }
            }
        }
        out
    }
}

fn get_fd(task: &Task, pid: u32, fd: i32) -> Option<Fd> {
    // Replay the event stream, not the tracee's current fd table: a fast tracee
    // can close/reuse an fd before userspace consumes the earlier event.
    task.fds
        .borrow()
        .get(&fd)
        .cloned()
        .or_else(|| proc_fd(pid, fd))
}

fn resolve_path(pid: u32, path: &Path) -> PathBuf {
    let root = PathBuf::from(format!("/proc/{pid}/root"));
    let Ok(host_root) = fs::canonicalize(&root) else {
        return normalize(path);
    };
    let host_path = root.join(path.strip_prefix("/").unwrap_or(path));
    let mut ancestor = host_path.as_path();
    let mut suffix = Vec::new();
    loop {
        if let Ok(mut resolved) = fs::canonicalize(ancestor) {
            for part in suffix.iter().rev() {
                resolved.push(part);
            }
            if let Ok(relative) = resolved.strip_prefix(&host_root) {
                return normalize(&Path::new("/").join(relative));
            }
            return normalize(path);
        }
        if let (Some(parent), Some(file)) = (ancestor.parent(), ancestor.file_name()) {
            suffix.push(file.to_owned());
            ancestor = parent;
        } else {
            return normalize(path);
        }
    }
}

fn protocol(family: u64, kind: u64, proto: u64) -> Option<String> {
    if !matches!(family, 2 | 10) {
        return None;
    }
    if proto != 0 {
        Some(proto.to_string())
    } else {
        match kind & 0xf {
            1 => Some("6".into()),
            2 => Some("17".into()),
            _ => None,
        }
    }
}

fn address(event: &Event) -> Option<String> {
    let family = u16::from_ne_bytes([event.address[0], event.address[1]]);
    match family {
        2 if event.address_len >= 16 => Some(
            Ipv4Addr::new(
                event.address[4],
                event.address[5],
                event.address[6],
                event.address[7],
            )
            .to_string(),
        ),
        10 if event.address_len >= 28 => {
            let bytes: [u8; 16] = event.address[8..24].try_into().ok()?;
            Some(Ipv6Addr::from(bytes).to_string())
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn syscall(nr: u64) -> Event {
        let mut e = Event::empty();
        e.pid = u32::MAX;
        e.tid = 100;
        e.kind = EVENT_SYSCALL;
        e.syscall = nr;
        e
    }
    fn observer() -> Observer {
        let mut o = Observer::default();
        o.tasks.insert(
            100,
            Task {
                cwd: Rc::new(RefCell::new("/work".into())),
                fds: Rc::new(RefCell::new(HashMap::new())),
            },
        );
        o
    }
    fn path(e: &mut Event, s: &str) {
        e.paths[0][..s.len()].copy_from_slice(s.as_bytes());
        e.path_len[0] = s.len() as u32;
    }
    #[test]
    fn openat_fd_read_dup_close_and_relative_paths() {
        let mut o = observer();
        let mut e = syscall(257);
        e.args[0] = AT_FDCWD as u64;
        e.result = 7;
        path(&mut e, "../secret");
        let obs = o.observe(&e);
        assert_eq!(obs.paths, vec!["/secret"]);
        assert!(obs.scopes.contains(&"READ".into()));
        e = syscall(32);
        e.args[0] = 7;
        e.result = 8;
        o.observe(&e);
        e = syscall(0);
        e.args[0] = 8;
        assert_eq!(o.observe(&e).paths, vec!["/secret"]);
        e = syscall(3);
        e.args[0] = 7;
        o.observe(&e);
        e = syscall(0);
        e.args[0] = 7;
        assert!(!o.observe(&e).incomplete.is_empty());
    }
    #[test]
    fn fork_inherits_fds_and_threads_share_them() {
        let mut o = observer();
        let mut e = syscall(2);
        path(&mut e, "/secret");
        e.result = 7;
        o.observe(&e);
        e.kind = EVENT_FORK;
        e.result = 101;
        e.args = [0; 6];
        o.observe(&e);
        e = syscall(0);
        e.tid = 101;
        e.args[0] = 7;
        assert_eq!(o.observe(&e).paths, vec!["/secret"]);
        e = syscall(3);
        e.args[0] = 7;
        o.observe(&e);
        e = syscall(0);
        e.tid = 101;
        e.args[0] = 7;
        assert_eq!(o.observe(&e).paths, vec!["/secret"]);
        e = syscall(0);
        e.kind = EVENT_FORK;
        e.result = 102;
        e.args[0] = 0x400;
        o.observe(&e);
        e = syscall(2);
        path(&mut e, "/shared");
        e.result = 9;
        o.observe(&e);
        e = syscall(0);
        e.tid = 102;
        e.args[0] = 9;
        assert_eq!(o.observe(&e).paths, vec!["/shared"]);
    }
    #[test]
    fn socket_protocol_and_ipv4_connect() {
        let mut o = observer();
        let mut e = syscall(41);
        e.args = [2, 1, 0, 0, 0, 0];
        e.result = 5;
        o.observe(&e);
        e = syscall(42);
        e.args[0] = 5;
        e.address_len = 16;
        e.address[0..2].copy_from_slice(&2u16.to_ne_bytes());
        e.address[4..8].copy_from_slice(&[127, 0, 0, 1]);
        let obs = o.observe(&e);
        assert_eq!(obs.ips, vec!["127.0.0.1"]);
        assert_eq!(obs.protocols, vec!["6"]);
        e = syscall(1);
        e.args[0] = 5;
        let obs = o.observe(&e);
        assert!(obs.scopes.contains(&"NETWORK".into()));
        assert_eq!(obs.ips, vec!["127.0.0.1"]);
    }
    #[test]
    fn descriptor_replay_does_not_use_a_reused_live_fd() {
        use std::os::fd::AsRawFd;
        let live = fs::File::open("/dev/null").unwrap();
        let mut o = observer();
        let mut e = syscall(2);
        e.pid = std::process::id();
        e.result = live.as_raw_fd() as i64;
        path(&mut e, "/captured-path");
        o.observe(&e);
        e = syscall(0);
        e.pid = std::process::id();
        e.args[0] = live.as_raw_fd() as u64;
        assert_eq!(o.observe(&e).paths, vec!["/captured-path"]);
    }

    #[test]
    fn rename_checks_both_paths_and_unix_sockets_are_not_tcp() {
        let mut o = observer();
        let mut e = syscall(82);
        e.result = -2;
        path(&mut e, "/safe/source");
        let dest = b"/outside/target";
        e.paths[1][..dest.len()].copy_from_slice(dest);
        e.path_len[1] = dest.len() as u32;
        assert_eq!(o.observe(&e).paths, vec!["/outside/target", "/safe/source"]);
        let mut e = syscall(41);
        e.args = [1, 1, 0, 0, 0, 0];
        assert!(o.observe(&e).protocols.is_empty());
    }
}
