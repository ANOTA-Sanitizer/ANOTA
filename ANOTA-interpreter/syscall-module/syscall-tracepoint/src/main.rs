mod backend;
mod observe;
mod policy;

use anyhow::{bail, ensure, Context, Result};
use backend::Kernel;
use observe::Observer;
use policy::{validate_request, Policy, Request};
use std::{
    collections::HashMap,
    env, fs,
    io::{BufRead, BufReader, Write},
    os::unix::{
        fs::{MetadataExt, PermissionsExt},
        io::AsRawFd,
        net::{UnixListener, UnixStream},
    },
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};
use syscall_tracepoint_common::{Event, EVENT_SYSCALL};

const MAX_REQUEST: u64 = 1024 * 1024;
static STOP: AtomicBool = AtomicBool::new(false);
extern "C" fn stop_signal(_: libc::c_int) {
    STOP.store(true, Ordering::Relaxed);
}

struct Session {
    pid: u32,
    birth: u64,
    generation: u64,
    history: HashMap<u64, Policy>,
    active: bool,
}

#[derive(Default)]
struct Monitor {
    kernel: Option<Kernel>,
    sessions: HashMap<u64, Session>,
    observer: Observer,
    sequence: u64,
}

fn birth(pid: u32) -> Result<u64> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    stat.rsplit_once(')')
        .context("malformed proc stat")?
        .1
        .split_whitespace()
        .nth(19)
        .context("missing proc starttime")?
        .parse()
        .context("invalid proc starttime")
}
fn tids(pid: u32) -> Result<Vec<u32>> {
    let mut result = Vec::new();
    for entry in fs::read_dir(format!("/proc/{pid}/task"))? {
        result.push(entry?.file_name().to_string_lossy().parse()?);
    }
    ensure!(!result.is_empty(), "target has no tasks");
    Ok(result)
}

impl Monitor {
    fn apply(&mut self, request: Request, peer: libc::ucred) -> Result<()> {
        validate_request(&request)?;
        let owner = fs::metadata(format!("/proc/{}", request.pid))
            .context("target process disappeared")?
            .uid();
        ensure!(
            peer.uid == 0 || owner == peer.uid,
            "target is owned by a different user"
        );
        let started = birth(request.pid)?;
        let existing = self.sessions.iter().find_map(|(id, s)| {
            (s.pid == request.pid && s.birth == started && s.active).then_some(*id)
        });
        if request.action == "stop" {
            if let Some(id) = existing {
                if let Some(kernel) = &mut self.kernel {
                    let removed = kernel.stop(id)?;
                    self.observer.forget(&removed);
                }
                // Retain old policy versions for already queued/in-flight events.
                self.sessions.get_mut(&id).unwrap().active = false;
            }
            return Ok(());
        }
        let cwd = fs::read_link(format!("/proc/{}/cwd", request.pid))?;
        let policy = Policy::compile(&request, &cwd)?;
        self.sequence = self
            .sequence
            .checked_add(1)
            .context("session counter overflow")?;
        let generation = self.sequence;
        if let Some(id) = existing {
            let session = self.sessions.get_mut(&id).unwrap();
            ensure!(
                session.history.len() < 8192,
                "policy history limit reached; STOP then START a new session"
            );
            // The event generation selects its immutable policy snapshot even if
            // the syscall returns after a subsequent annotation update.
            session.history.insert(generation, policy);
            if let Some(kernel) = &mut self.kernel {
                if let Err(e) = kernel.update(id, generation) {
                    session.history.remove(&generation);
                    return Err(e);
                }
            }
            session.generation = generation;
        } else {
            let task_ids = tids(request.pid)?;
            self.observer.seed(request.pid, &task_ids)?;
            let id = generation;
            self.sessions.insert(
                id,
                Session {
                    pid: request.pid,
                    birth: started,
                    generation,
                    history: HashMap::from([(generation, policy)]),
                    active: true,
                },
            );
            if let Some(kernel) = &mut self.kernel {
                if let Err(e) = kernel.install(id, generation, &task_ids) {
                    let _ = kernel.stop(id);
                    self.sessions.remove(&id);
                    return Err(e);
                }
                // Catch threads that were being created during initial seeding.
                // Future forks/threads inherit directly in the kernel hook.
                let extra = tids(request.pid)?;
                kernel.install(id, generation, &extra)?;
            }
        }
        Ok(())
    }
    fn event(&mut self, event: Event) {
        let observation = self.observer.observe(&event);
        if event.kind != EVENT_SYSCALL {
            return;
        }
        if env::var_os("ANOTA_SYSCALL_TRACE").is_some() {
            eprintln!("ANOTA_SYSCALL trace: session={} generation={} pid={} tid={} syscall={} result={} {:?}",
                event.session,event.generation,event.pid,event.tid,event.syscall,event.result,observation);
        }
        for message in &observation.incomplete {
            eprintln!(
                "ANOTA_SYSCALL monitor warning: pid={} tid={} syscall={} {}",
                event.pid, event.tid, event.syscall, message
            );
        }
        if let Some(policy) = self
            .sessions
            .get(&event.session)
            .and_then(|s| s.history.get(&event.generation))
        {
            for message in policy.evaluate(&event, &observation) {
                eprintln!("{message}");
            }
        } else {
            eprintln!(
                "ANOTA_SYSCALL monitor warning: missing policy generation {}",
                event.generation
            );
        }
    }
    fn drain(&mut self) {
        // Bound batches so a busy tracee cannot starve policy updates.
        for _ in 0..4096 {
            let event = self.kernel.as_mut().and_then(Kernel::next);
            if let Some(event) = event {
                self.event(event);
            } else {
                break;
            }
        }
    }
}

struct Command {
    request: Request,
    peer: libc::ucred,
    reply: mpsc::SyncSender<String>,
}

fn connection(mut stream: UnixStream, tx: mpsc::Sender<Command>, allowed_uid: u32) -> Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(3)))?;
    stream.set_write_timeout(Some(Duration::from_secs(3)))?;
    let mut peer = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut size = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut peer as *mut libc::ucred).cast(),
            &mut size,
        )
    };
    ensure!(rc == 0, "SO_PEERCRED failed");
    ensure!(
        peer.uid == allowed_uid || peer.uid == 0,
        "unauthorized control client"
    );
    let outcome = (|| -> Result<String> {
        use std::io::Read;
        let mut line = String::new();
        BufReader::new((&stream).take(MAX_REQUEST + 1)).read_line(&mut line)?;
        ensure!(
            line.len() <= MAX_REQUEST as usize && line.ends_with('\n'),
            "invalid/oversized control message"
        );
        let request: Request = serde_json::from_str(&line).context("invalid policy JSON")?;
        let (reply, rx) = mpsc::sync_channel(1);
        tx.send(Command {
            request,
            peer,
            reply,
        })?;
        rx.recv_timeout(Duration::from_secs(10))
            .context("monitor did not acknowledge policy")
    })();
    let reply = match outcome {
        Ok(reply) => reply,
        Err(e) => format!("ERR {e:#}\n"),
    };
    stream.write_all(reply.replace('\r', " ").as_bytes())?;
    Ok(())
}

fn main() -> Result<()> {
    let mut socket = PathBuf::from(
        env::var("ANOTA_SYSCALL_SOCKET").unwrap_or_else(|_| "/tmp/anota_syscall.sock".into()),
    );
    let mut bpf = PathBuf::from("target/bpfel-unknown-none/release/syscall-tracepoint");
    let mut control_only = env::var_os("ANOTA_SYSCALL_SKIP_EBPF").is_some();
    let mut uid = env::var("SUDO_UID")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| unsafe { libc::geteuid() });
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--socket" => socket = args.next().context("--socket requires a path")?.into(),
            "--bpf" => bpf = args.next().context("--bpf requires an object path")?.into(),
            "--uid" => uid = args.next().context("--uid requires a uid")?.parse()?,
            "--control-only" => control_only = true,
            "--help" => {
                println!("syscall-tracepoint [--bpf OBJECT] [--socket PATH] [--uid UID] [--control-only]");
                return Ok(());
            }
            _ => bail!("unknown argument {arg}"),
        }
    }
    let mut monitor = Monitor::default();
    if control_only {
        eprintln!("ANOTA_SYSCALL control-only mode: NO kernel syscall capture");
    } else {
        monitor.kernel = Some(Kernel::load(&bpf)?);
    }
    let listener = UnixListener::bind(&socket).with_context(|| {
        format!(
            "bind {}; remove a stale socket only after checking no daemon owns it",
            socket.display()
        )
    })?;
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))?;
    if unsafe { libc::geteuid() } == 0 {
        use std::os::unix::ffi::OsStrExt;
        let path = std::ffi::CString::new(socket.as_os_str().as_bytes())?;
        ensure!(
            unsafe { libc::chown(path.as_ptr(), uid, u32::MAX) } == 0,
            "chown control socket failed"
        );
    }
    let inode = fs::metadata(&socket)?.ino();
    listener.set_nonblocking(true)?;
    unsafe {
        libc::signal(libc::SIGINT, stop_signal as *const () as libc::sighandler_t);
        libc::signal(
            libc::SIGTERM,
            stop_signal as *const () as libc::sighandler_t,
        );
    }
    let (tx, rx) = mpsc::channel();
    eprintln!(
        "ANOTA_SYSCALL monitor ready: {} (client uid={uid})",
        socket.display()
    );
    let mut last_report = Instant::now();
    while !STOP.load(Ordering::Relaxed) {
        monitor.drain();
        match listener.accept() {
            Ok((stream, _)) => {
                let tx = tx.clone();
                thread::spawn(move || {
                    if let Err(e) = connection(stream, tx, uid) {
                        eprintln!("ANOTA_SYSCALL control error: {e:#}");
                    }
                });
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(e.into()),
        }
        while let Ok(command) = rx.try_recv() {
            let reply = match monitor.apply(command.request, command.peer) {
                Ok(()) => "OK\n".to_string(),
                Err(e) => format!("ERR {}\n", format!("{e:#}").replace(['\n', '\r'], " ")),
            };
            let _ = command.reply.send(reply);
        }
        if last_report.elapsed() > Duration::from_secs(2) {
            if let Some(kernel) = &mut monitor.kernel {
                kernel.report_loss();
                let live = kernel.live_sessions();
                // Keep stopped sessions until shutdown: a syscall already in
                // flight at STOP can still return with its old generation.
                let ended: Vec<_> = monitor
                    .sessions
                    .iter()
                    .filter_map(|(id, s)| (s.active && !live.contains(id)).then_some(*id))
                    .collect();
                for id in ended {
                    let _ = kernel.stop(id);
                    monitor.sessions.get_mut(&id).unwrap().active = false;
                }
            }
            last_report = Instant::now();
        }
        thread::sleep(Duration::from_millis(2));
    }
    monitor.drain();
    if let Some(kernel) = &mut monitor.kernel {
        kernel.report_loss();
    }
    if fs::metadata(&socket).is_ok_and(|m| m.ino() == inode) {
        fs::remove_file(&socket)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn acknowledged_replacement_retains_old_policy_versions_and_rejects_bad_updates() {
        let pid = std::process::id();
        let peer = libc::ucred {
            pid: pid as i32,
            uid: unsafe { libc::geteuid() },
            gid: unsafe { libc::getegid() },
        };
        let mut monitor = Monitor::default();
        let request = || Request {
            version: 1,
            action: "replace".into(),
            pid,
            ..Default::default()
        };
        let mut blocked = request();
        blocked.blocked.push("getppid".into());
        monitor.apply(blocked, peer).unwrap();
        let id = *monitor.sessions.keys().next().unwrap();
        let old = monitor.sessions[&id].generation;
        let mut bad = request();
        bad.blocked.push("typo".into());
        assert!(monitor.apply(bad, peer).is_err());
        assert_eq!(monitor.sessions[&id].generation, old);
        monitor.apply(request(), peer).unwrap();
        let new = monitor.sessions[&id].generation;
        let mut event = Event::empty();
        event.syscall = 110;
        event.pid = pid;
        assert_eq!(
            monitor.sessions[&id].history[&old]
                .evaluate(&event, &Default::default())
                .len(),
            1
        );
        assert!(monitor.sessions[&id].history[&new]
            .evaluate(&event, &Default::default())
            .is_empty());
        let mut stop = request();
        stop.action = "stop".into();
        monitor.apply(stop, peer).unwrap();
        assert!(!monitor.sessions[&id].active);
        monitor.apply(request(), peer).unwrap();
        assert!(monitor
            .sessions
            .iter()
            .any(|(other, s)| *other != id && s.active));
    }
}
