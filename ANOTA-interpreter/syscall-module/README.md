# syscall-tracepoint

## Prerequisites

1. Install Rust nightly (once): `rustup toolchain install nightly`
2. Install `bpf-linker`: `cargo +nightly install bpf-linker`
3. (Already done in this repo) The Aya framework is vendored under `aya-src/`, so
   building does not require network access. If you ever need to refresh it,
   clone https://github.com/aya-rs/aya into that directory manually.

## Build eBPF

```bash
cargo +nightly xtask build-ebpf
```

To perform a release build you can use the `--release` flag.
You may also change the target architecture with the `--target` flag.

## Build Userspace

```bash
cargo +nightly build
```

## Run

```bash
RUST_LOG=info cargo +nightly xtask run
```

The userspace daemon now exposes a UNIX domain control socket at `/tmp/anota_syscall.sock`.
Send textual commands to start/stop monitoring:

```
START            # enable tracing for every process
START <pid>      # enable tracing only for the specified PID
STOP             # disable tracing
```

Each command should be terminated by `\n`. The daemon replies with either `OK` or `ERR ...`.

In CPython, the helper functions `ANOTA_SYSCALL_SIGNAL_START` / `ANOTA_SYSCALL_SIGNAL_STOP` can
connect to this socket and send `START <os.getpid()>` or `STOP` to bracket the region that needs
syscall monitoring.

### Development Shortcut

When running tests or developing on a machine without eBPF permissions, export
`ANOTA_SYSCALL_SKIP_EBPF=1` before launching the daemon. In this mode the Rust
process still brings up the control socket but skips loading/attaching the
kernel programs, which avoids requiring root access. Combine this with the
nightly toolchain commands above (e.g. `ANOTA_SYSCALL_SKIP_EBPF=1 cargo +nightly xtask run`).

## Integration Test

After compiling the daemon, you can run the Python-side integration test (from
the repo root) to ensure end-to-end communication works:

```bash
./python anota_syscall_integration_test.py
```

This script automatically builds the Rust binary if needed, starts it with
`ANOTA_SYSCALL_SKIP_EBPF=1`, and invokes the `ANOTA_SYSCALL_SIGNAL_START/STOP`
helpers. Use it whenever you change the control-socket protocol.

## Collect Tracepoint Events
```
sudo cat /sys/kernel/debug/tracing/available_events |grep syscalls > syscall_event_list.txt
sudo cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_access/format
```
