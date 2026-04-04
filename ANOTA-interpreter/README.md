# ANOTA Instrumentation Guide

This repository extends CPython 3.10 with a family of ANOTA security hooks. The goal of this document is to describe each component’s purpose, public interface, the available test scripts, and explain how to build the instrumented interpreter.

## Building the Interpreter

The project follows CPython’s normal build layout. The steps below assume a Debian/Ubuntu-style environment; adjust package names as needed for other platforms.

### 1. Install System Dependencies

```bash
sudo apt update
sudo apt install -y \
    build-essential \
    gdb \
    lcov \
    libbz2-dev \
    libffi-dev \
    libgdbm-dev \
    liblzma-dev \
    libncursesw5-dev \
    libnss3-dev \
    libreadline-dev \
    libsqlite3-dev \
    libssl-dev \
    tk-dev \
    uuid-dev \
    zlib1g-dev
```

These match the packages recommended by `Doc/README.rst` for building Python with all optional modules enabled.

### 2. Configure

From the repository root:

```bash
./configure --enable-optimizations --with-lto
```

- `--enable-optimizations` enables profile-guided optimizations (PGO).
- `--with-lto` turns on link-time optimization when supported by the toolchain.

Use `./configure --help` to inspect additional options (e.g., `--with-pydebug` for a debug build).

### 3. Build

```bash
make -j"$(nproc)"
```

### 4. Run Tests

Run the standard CPython regression suite:

```bash
make test
```

For the ANOTA features specifically, execute:

```bash
./python ANOTA-tests/anota_object_access_test.py
./python ANOTA-tests/anota_watch_con_test.py
./python ANOTA-tests/anota_taint_test.py
./python ANOTA-tests/anota_dfsan_test.py
./python ANOTA-tests/anota_syscall_test.py
```

For the ptrace-backed native watch coverage, run:

```bash
./python ANOTA-tests/anota_cext_watch_test.py
```

Notes:

- `ANOTA-tests/anota_cext_watch_test.py` requires `x86_64` Linux.
- `ANOTA-tests/anota_dfsan_test.py` requires `clang-19`. It builds a small
  DFSan-linked launcher executable before running the DFSan-instrumented
  extension regression.

### 5. Optional Installation

If you want to install the instrumented interpreter system-wide (not usually required for development):

```bash
sudo make altinstall
```

`altinstall` avoids overwriting the system’s default `python3`.

### 6. Optional Syscall Monitor Integration

The Rust daemon under `syscall-module/` requires the nightly toolchain because
its dependencies currently target `edition2024`. Install it once via

```bash
rustup toolchain install nightly
```

Then run the end-to-end integration test:

```bash
./python ANOTA-tests/anota_syscall_integration_test.py
```

The script automatically builds the daemon using `cargo +nightly` and exercises
the `ANOTA_SYSCALL_SIGNAL_START/STOP` helpers.

Note: the Aya crates required by the daemon are vendored under
`syscall-module/aya-src`, so no network access or git submodules are necessary.

### Syscall Tracepoint Overview

The Rust crate at `syscall-module/syscall-tracepoint/` provides the low-level
syscall monitors used by the daemon. It attaches to Linux syscall tracepoints,
collects per-call metadata, and forwards events through the shared types in
`syscall-tracepoint-common` to the rest of the workspace. You typically do not
need to touch it directly—building the daemon or running the integration tests
automatically compiles the tracepoint code alongside its eBPF helpers.

All ANOTA-specific tests and fixtures live under `ANOTA-tests/`.

## Table of Contents

1. ANOTA_EXECUTION (`Python/anota_execution.c`)
2. ANOTA_WATCH (`Python/anota_watch.c`)
3. ANOTA_TAINT (`Python/anota_taint.c`)
4. Native Instrumentation Helpers (`Lib/anota_native.py`)
5. ANOTA_SYSCALL (`Python/anota_syscall.c`)
6. Test Suites

---

## 1. ANOTA_EXECUTION (`Python/anota_execution.c`)

### Usage Summary

`ANOTA_EXECUTION` provides a single guard primitive:

```python
ANOTA_EXECUTION.BLOCK(condition, msg=None)
```

- If `condition` is truthy, execution continues normally.
- If it is falsy, a `RuntimeError` is raised (optionally containing `msg`), allowing you to stop unsafe flows early.

Typical use cases:

- Hardening privilege checks (`ANOTA_EXECUTION.BLOCK(user.is_admin)`).
- Preventing optional code from running when prerequisites are missing.

---

## 2. ANOTA_WATCH (`Python/anota_watch.c`)

### Usage Summary

`ANOTA_WATCH` lets you gate reads (`R`), writes (`W`), and execution (`X`) against specific objects or their members:

```python
ANOTA_WATCH.ALLOW(obj, "RW", key=None)
ANOTA_WATCH.BLOCK(obj, "X", key=None)
ANOTA_WATCH.CLEAR(obj, key=None)
ANOTA_WATCH.CLEAR_ALL()
ANOTA_WATCH.CON(callable, fixed_args, random_args,
                number_measurements=5000, threshold=4.5, kwargs=None)
```

- Use `ALLOW` when you want to specify the exact set of modes that remain permitted; everything else is implicitly denied.
- Use `BLOCK` for one-off denials.
- Provide `key` (attribute name, dict key, index, etc.) to scope policies to individual fields.
- `CLEAR`/`CLEAR_ALL` remove policies so code can proceed normally again.
- `CON(...)` runs a [Dudect-style](https://github.com/oreparaz/dudect) timing test inside the interpreter and raises if
  the measured timing difference exceeds the threshold.

### Native C-extension Enforcement
For common `PyCFunction` call paths, the interpreter now reuses the same `ALLOW`/`BLOCK` policy when a
watched Python object crosses into native code.

- Currently, automatic native enforcement is implemented for `bytearray` and
  `bytes` objects whose native storage can be mapped directly.
- The current backend traps blocked native writes by arming ptrace hardware
  watchpoints around the C call.
- This makes patterns such as `ANOTA_WATCH.ALLOW(buf, "R")` useful for
  detecting native writes to `buf` inside a C extension.

Current limitations:

- Linux `x86_64` only.
- Automatic enforcement currently targets `PyCFunction` call sites.
- Hardware watch point limitations
---

## 3. ANOTA_TAINT (`Python/anota_taint.c`)

### Usage Summary

```python
ANOTA_TAINT(obj, sanitization=[hash], Sink=[print])
```

- `obj` becomes tainted by object identity and will propagate warnings if it
  reaches listed sinks.
- Any function listed under `sanitization` clears taint on its return value.
- Any function listed under `Sink` raises `RuntimeError` when called with tainted arguments.
- Tainted callables propagate taint to their return values.
- `write` as a default sink intent.
- Current supported str-like objects for cross-interface taint track are [bytesobject]([ANOTA-interpreter/Objects/bytesobject.c:140), [bytearrayobject](ANOTA-interpreter/Objects/bytearrayobject.c:107) and [unicodeobject.c](ANOTA-interpreter/Objects/unicodeobject.c:2302).
- In example, DFSan-instrumented native code can report tainted `write()` and `printf()`
  sink hits back into the interpreter, where they surface as
  `RuntimeError("ANOTA_TAINT native sink violation")`.
---

## 4. Experimental Native Instrumentation Helpers (`Lib/anota_native.py`)

`Lib/anota_native.py` contains the interpreter-side helpers used by the native
experiments and tests.

- DFSan helper routines generate compile and link flags for extension modules.
- `Include/anota_dfsan_abilist.txt` marks CPython `Py*` / `_Py*` entry points as
  uninstrumented so DFSan helper code can call back into the interpreter.
- The ptrace-backed native `ANOTA_WATCH` enforcement is implemented in the
  interpreter core rather than exposed as a separate public Python API.

As mentioned in the paper,  cross-language taint analysis is challenging and our implementation only serves as a proof-of-concept. [PolyCruise](https://github.com/awen-li/PolyCruise) would be a more stable and comprehensive implementation.

To use the current version with LLVM data-flow sanitizer. you need to 
- Build the interpreter normally. Use the ANOTA interpreter build in ANOTA-interpreter/.
- Write your extension as a normal shared-object C extension, but compile it with DFSan. The helper for that is in [ANOTA-interpreter/Lib/anota_native.py](ANOTA-interpreter/Lib/anota_native.py)
- Run your test script under a process that already has the DFSan runtime loaded. Right now, the template for that is [ANOTA-interpreter/ANOTA-tests/anota_dfsan_test.py](ANOTA-interpreter/ANOTA-tests/anota_dfsan_test.py), which builds a DFSan-linked launcher from [ANOTA-interpreter/ANOTA-tests/anota_dfsan_runner.c](ANOTA-interpreter/ANOTA-tests/anota_dfsan_runner.c) and execves your Python script through it.
---

## 5. ANOTA_SYSCALL (`Python/anota_syscall.c`)

### Usage Summary

`ANOTA_SYSCALL` lets you monitor file, process, and network operations issued through CPython’s standard wrappers. Policies can be written globally or scoped to a particular operation:

```python
ANOTA_SYSCALL.READ.BLOCK(PATH="/etc/passwd")
ANOTA_SYSCALL.READ.ALLOW(PATH="/var/log/")
ANOTA_SYSCALL.CONNECT.BLOCK(DOMAIN="*.example.com")
ANOTA_SYSCALL.CONNECT.BLOCK(IP="10.*")
ANOTA_SYSCALL.SOCKET.BLOCK(PROTOCOL="TCP")
```

- Accepted keywords: `PATH`, `DOMAIN`, `IP`, `PROTOCOL`. Supply only one per call.
- Wildcards (`*`) are supported in all fields. Append `/` to a path to match an entire directory tree.
- Global controls: `ANOTA_SYSCALL.ALLOW("execve")`, `ANOTA_SYSCALL.BLOCK("open", "execv")`.
- Violations are logged to stderr so you can review which syscall and target triggered the policy.
- System-wide collection is driven by the Rust daemon in `syscall-module`. Use helper functions such as `ANOTA_SYSCALL_SIGNAL_START(pid=None)` / `ANOTA_SYSCALL_SIGNAL_STOP()` to send `START`/`STOP` commands to `/tmp/anota_syscall.sock` and bracket the region you want to trace.

---

## 6. Test Suites

### 6.1 `anota_object_access_test.py`

- Exercises ANOTA_WATCH and ANOTA_EXECUTION behavior.
- Run with the instrumented interpreter:

  ```
  ./python ANOTA-tests/anota_object_access_test.py
  ```

- Coverage:
  - Object-level read/execution policies and their interaction with bytecode opcodes.
  - Attribute and subscript read/write policies.
  - Mode allow-mask semantics.

### 6.2 `anota_taint_test.py`

- Validates ANOTA_TAINT hook behavior.
- Run with:

  ```
  ./python ANOTA-tests/anota_taint_test.py
  ```

- Coverage:
  - Registering tainted objects.
  - Ensuring sinks raise on tainted inputs.
  - Sanitizer propagation and clearing.
  - Helper assertions: `expect_runtime_error`, etc.

### 6.3 `anota_dfsan_test.py`

- Validates the DFSan-backed ANOTA_TAINT native path.
- Run with:

  ```
  ./python ANOTA-tests/anota_dfsan_test.py
  ```

- Coverage:
  - Taint export from Python objects into DFSan-tracked native buffers.
  - Native taint propagation across a C-level copy.
  - DFSan-backed taint import on returned `bytes`.
  - Avoiding overtaint when a tainted native call returns unrelated clean data.
  - Preserving the old ANOTA fallback behavior for uninstrumented builtin C methods.
  - Native `write()` sink rejection.
  - Native `printf()` sink rejection.

### 6.4 `anota_watch_con_test.py`

- Validates `ANOTA_WATCH.CON(...)`.
- Run with:

  ```
  ./python ANOTA-tests/anota_watch_con_test.py
  ```

- Coverage:
  - Dudect-style timing-test success path.
  - Timing leakage detection and exception behavior.

### 6.5 `anota_cext_watch_test.py`

- Validates ptrace-backed native watch support.
- Run with:

  ```
  ./python ANOTA-tests/anota_cext_watch_test.py
  ```

- Coverage:
  - Automatic `ANOTA_WATCH` enforcement when a read-only annotated
    `bytearray` is written inside a C extension.
- Platform constraints:
  - Linux `x86_64`.
  - Requires `ptrace` permission.

### 6.6 `anota_syscall_test.py`

- Smoke-tests the ANOTA_SYSCALL controller in a non-fatal way (violations log but do not stop execution).
- Run with:

  ```
  ./python ANOTA-tests/anota_syscall_test.py
  ```

- Tests include:
  - Blocking global syscalls like `open`.
  - File/directory path policies (exact, directory prefixes, wildcards).
  - Allow-list enforcement.
  - Process execution monitoring (`execv`).
  - Network policies (domain/IP allow/deny with wildcards).
- Protocol-level blocking (`SOCKET` policy).

### 6.6 `anota_syscall_signal_test.py`

- Validates the `ANOTA_SYSCALL_SIGNAL_START/STOP` helpers that talk to the Rust monitoring daemon.
- Run with:

  ```
  ./python ANOTA-tests/anota_syscall_signal_test.py
  ```

- The script spins up a dummy UNIX socket server in `/tmp/anota_syscall.sock` and ensures the helpers emit `START [pid]` and `STOP` commands without errors.

### 6.7 `anota_syscall_integration_test.py`

- Builds (if necessary) and launches the Rust daemon in `syscall-module`, then exercises the Python `ANOTA_SYSCALL_SIGNAL_START/STOP` helpers against the real control socket.
- Run with:

  ```
  ./python ANOTA-tests/anota_syscall_integration_test.py
  ```

- The script sets `ANOTA_SYSCALL_SKIP_EBPF=1` so no root privileges are required; it focuses on the control-plane integration.

### 6.8 Additional Coverage

- Interpreter bytecode tests (e.g., `ANOTA-tests/test_nested_sink.py`,
  `ANOTA-tests/test_taint_propagation.py`) integrate the taint hooks into real
  call flows.
- When modifying policies, use the dedicated tests above to validate behavior, then run the broader CPython regression suite as needed.

---

## Usage Notes

1. Always launch the custom interpreter (`./python`) so that the ANOTA singletons are available in `builtins`.
2. Policies persist within a process; call `ANOTA_* .clear()` or `CLEAR_ALL()`
   between tests or when updating configuration at runtime.
3. `ANOTA_WATCH`, `ANOTA_TAINT`, and `ANOTA_EXECUTION` raise `RuntimeError`
   when a policy violation is detected. `ANOTA_SYSCALL` currently logs without
   raising.
4. Wildcards can be used in PATH, DOMAIN, IP, and PROTOCOL values. For
   directory scopes, add a trailing slash to enforce prefix matching.