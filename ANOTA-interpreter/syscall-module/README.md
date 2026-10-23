# syscall-tracepoint

Aya-based syscall monitoring for ANOTA, including native code and future child
processes/threads. Violations print to the daemon's stderr without stopping the application.

## Prerequisites

- Native Linux x86_64, kernel 5.8+, with tracefs mounted.
- Rust stable and nightly with `rust-src`:

  ```bash
  rustup toolchain install nightly --profile minimal --component rust-src
  ```

- A prebuilt `bpf-linker` from the [official releases](https://github.com/aya-rs/bpf-linker#installation):

  ```bash
  mkdir -p /tmp/anota-tools/bin
  curl -fL https://github.com/aya-rs/bpf-linker/releases/latest/download/bpf-linker-x86_64-unknown-linux-musl.tar.zst \
    -o /tmp/bpf-linker.tar.zst
  tar --zstd -xf /tmp/bpf-linker.tar.zst -C /tmp/anota-tools/bin
  export PATH="/tmp/anota-tools/bin:$PATH"
  ```

Aya is pinned to 0.14.0 and aya-ebpf to 0.2.1, with lockfiles. No vendored `aya-src` is needed.

## Build eBPF

From `ANOTA-interpreter/syscall-module/`:

```bash
cargo xtask build-ebpf --release
```

## Build Userspace

```bash
cargo build --locked --release -p syscall-tracepoint
```

## Run

Start the daemon before the annotated application:

```bash
sudo target/release/syscall-tracepoint \
  --bpf target/bpfel-unknown-none/release/syscall-tracepoint \
  --socket /tmp/anota_syscall.sock
```

Then, from `ANOTA-interpreter/`:

```bash
ANOTA_SYSCALL_BACKEND=ebpf ./python your_application.py
```

- Alternatively, call `ANOTA_SYSCALL_SIGNAL_START()` to upload existing policies; `ANOTA_SYSCALL_SIGNAL_STOP()` disables monitoring.
- `ANOTA_SYSCALL_SIGNAL_START(pid=...)` monitors that process and future descendants. Start before spawning children.
- `--uid UID` selects the control client; the default is `$SUDO_UID` or the daemon's UID.
- `ANOTA_SYSCALL_SOCKET` selects a custom socket path for the interpreter.

## Policies

```python
rule = ANOTA_SYSCALL.READ.BLOCK(PATH="/private/")
ANOTA_SYSCALL.CONNECT.BLOCK(IP="127.*")
ANOTA_SYSCALL.SOCKET.BLOCK(PROTOCOL="UDP")
CLEAR(rule)
ANOTA_SYSCALL.CLEAR()
```

- Supports syscall names and `FILE`, `NETWORK`, `OPEN`, `READ`, `WRITE` groups.
- `PATH` supports `*` and trailing-slash directory scopes. Descriptors and dirfd/cwd paths are tracked.
- `IP` accepts IPv4/IPv6 patterns; `PROTOCOL` accepts names or numbers.
- `DOMAIN` resolves exact names at installation; wildcard domains are unsupported.
- URL `SCHEME`/`HOST` checks run in the interpreter. See [URL policies](../README.md#url-policies).
- Blocks take precedence. Allow entries of the same field are alternatives.
- `CLEAR(handle)` removes one annotation; operation `.CLEAR()` removes its rules. Clearing does not stop monitoring.
- Updates wait for acknowledgement. Rejection preserves local rules; connection failure can leave the remote outcome unknown.

## Tests

From this directory:

```bash
cargo test --locked -p syscall-tracepoint
```

From `ANOTA-interpreter/`:

```bash
./python ANOTA-tests/anota_syscall_signal_test.py
python3 ANOTA-tests/anota_syscall_integration_test.py
sudo python3 ANOTA-tests/anota_syscall_integration_test.py --kernel
```

The default integration test uses `--control-only` without loading BPF.
`--kernel` checks real capture. Pass `--python /path/to/instrumented/python`
for a separate interpreter build.

## Limitations

- Monitoring is asynchronous and nonfatal; it does not prevent side effects.
- Path/descriptor reconstruction is best effort. Capture failures and dropped events are reported to stderr.
- Compat/32-bit ABIs, individual io_uring operations, SCM_RIGHTS transfers, and arbitrary ioctl payloads are not decoded.
- Pre-existing socket metadata may be incomplete; `sendmmsg` captures only its first destination.
- TOCTOU detection is not implemented. `ANOTA_SYSCALL_TRACE=1` enables event diagnostics.
