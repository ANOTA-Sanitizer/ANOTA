mod file;

use std::convert::TryFrom;
use std::path::{Path, PathBuf};

use aya::{include_bytes_aligned, Bpf};
use aya::maps::Array;
use aya_log::BpfLogger;
use log::{info, warn, debug, error};
use std::env;

use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{UnixListener, UnixStream},
    signal,
    sync::mpsc,
};
use syscall_tracepoint_common::WatchConfig;

const CONTROL_SOCKET_PATH: &str = "/tmp/anota_syscall.sock";

#[derive(Debug)]
enum MonitorCommand {
    Start { pid: Option<u32> },
    Stop,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();

    bump_memlock_limit();

    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/syscall-tracepoint"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/syscall-tracepoint"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        warn!("failed to initialize eBPF logger: {}", e);
    }

    let skip_ebpf = env::var_os("ANOTA_SYSCALL_SKIP_EBPF").is_some();
    if skip_ebpf {
        info!("ANOTA_SYSCALL_SKIP_EBPF set; skipping eBPF program attachment");
    } else {
        file::load_and_attatch_enter_openat(&mut bpf)?;
        file::load_and_attatch_exit_openat(&mut bpf)?;
    }

    write_watch_config(&mut bpf, false, None)?;

    let (cmd_tx, mut cmd_rx) = mpsc::channel::<MonitorCommand>(16);
    let socket_path = PathBuf::from(CONTROL_SOCKET_PATH);
    let server_handle = tokio::spawn(run_control_server(socket_path.clone(), cmd_tx.clone()));
    info!(
        "Waiting for control commands on {} (use START [pid]/STOP)",
        CONTROL_SOCKET_PATH
    );

    loop {
        tokio::select! {
            _ = signal::ctrl_c() => {
                info!("Ctrl-C received, shutting down");
                break;
            }
            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(command) => {
                        if let Err(err) = apply_command(command, &mut bpf) {
                            error!("failed to apply command: {err:?}");
                        }
                    }
                    None => break,
                }
            }
        }
    }

    server_handle.abort();
    let _ = server_handle.await;
    if Path::new(&socket_path).exists() {
        let _ = std::fs::remove_file(&socket_path);
    }
    info!("Exiting...");

    Ok(())
}

fn bump_memlock_limit() {
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }
}

fn apply_command(command: MonitorCommand, bpf: &mut Bpf) -> anyhow::Result<()> {
    match command {
        MonitorCommand::Start { pid } => {
            write_watch_config(bpf, true, pid)?;
            if let Some(pid) = pid {
                info!("monitoring enabled for PID {}", pid);
            } else {
                info!("monitoring enabled for all processes");
            }
        }
        MonitorCommand::Stop => {
            write_watch_config(bpf, false, None)?;
            info!("monitoring disabled");
        }
    }
    Ok(())
}

fn write_watch_config(bpf: &mut Bpf, enabled: bool, pid: Option<u32>) -> anyhow::Result<()> {
    let mut array: Array<_, WatchConfig> = Array::try_from(bpf.map_mut("WATCH_CONFIG")?)?;
    let config = WatchConfig {
        enabled: if enabled { 1 } else { 0 },
        target_pid: pid.unwrap_or(0),
    };
    array.set(0, config, 0)?;
    Ok(())
}

async fn run_control_server(path: PathBuf, sender: mpsc::Sender<MonitorCommand>) -> anyhow::Result<()> {
    if Path::new(&path).exists() {
        let _ = std::fs::remove_file(&path);
    }
    let listener = UnixListener::bind(&path)?;
    loop {
        let (stream, _) = listener.accept().await?;
        let tx = sender.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_stream(stream, tx).await {
                error!("control connection error: {err:?}");
            }
        });
    }
}

async fn handle_stream(stream: UnixStream, sender: mpsc::Sender<MonitorCommand>) -> anyhow::Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();
    while let Some(line) = lines.next_line().await? {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        match parse_command(trimmed) {
            Ok(cmd) => {
                if sender.send(cmd).await.is_err() {
                    writer.write_all(b"ERR server shutting down\n").await?;
                    break;
                } else {
                    writer.write_all(b"OK\n").await?;
                }
            }
            Err(msg) => {
                let reply = format!("ERR {}\n", msg);
                writer.write_all(reply.as_bytes()).await?;
            }
        }
    }
    Ok(())
}

fn parse_command(line: &str) -> Result<MonitorCommand, String> {
    let mut parts = line.split_whitespace();
    match parts.next() {
        Some(cmd) if cmd.eq_ignore_ascii_case("START") => {
            if let Some(pid_str) = parts.next() {
                let pid: u32 = pid_str
                    .parse()
                    .map_err(|_| format!("invalid pid '{pid_str}'"))?;
                Ok(MonitorCommand::Start { pid: Some(pid) })
            } else {
                Ok(MonitorCommand::Start { pid: None })
            }
        }
        Some(cmd) if cmd.eq_ignore_ascii_case("STOP") => Ok(MonitorCommand::Stop),
        Some(other) => Err(format!("unknown command '{other}'")),
        None => Err("empty command".to_string()),
    }
}
