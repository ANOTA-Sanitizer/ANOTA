"""Integration test for the Rust syscall monitor + Python helpers.

Steps performed:
 1. Ensure the Rust daemon is built (runs `cargo build` if needed).
 2. Launch the daemon with ANOTA_SYSCALL_SKIP_EBPF=1 so no root privileges
    are required.
 3. Wait for `/tmp/anota_syscall.sock` to appear.
 4. Call ANOTA_SYSCALL_SIGNAL_START/STOP builtins, which send commands
    to the daemon.
 5. Shut down the daemon cleanly.

Run this with the ANOTA-enabled interpreter from the repo root:

    ./python anota_syscall_integration_test.py
"""

from __future__ import annotations

import builtins
import os
import signal
import socket
import subprocess
import time
from pathlib import Path

SOCKET_PATH = Path("/tmp/anota_syscall.sock")
REPO_ROOT = Path(__file__).resolve().parent
SYSCALL_MODULE = REPO_ROOT / "syscall-module"
DAEMON_PATH = SYSCALL_MODULE / "target" / "debug" / "syscall-tracepoint"
CARGO_TOOLCHAIN = ["cargo", "+nightly"]


def ensure_daemon_built() -> None:
    if DAEMON_PATH.exists():
        return
    try:
        subprocess.run(
            CARGO_TOOLCHAIN + ["build", "-p", "syscall-tracepoint"],
            cwd=SYSCALL_MODULE,
            check=True,
        )
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(
            "Failed to build syscall-tracepoint with nightly Cargo. "
            "Ensure `rustup toolchain install nightly` has been run."
        ) from exc
    except FileNotFoundError as exc:
        raise RuntimeError(
            "cargo (with nightly toolchain) not found. Install Rust via rustup."
        ) from exc


def wait_for_socket(timeout: float = 5.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if SOCKET_PATH.exists():
            return
        time.sleep(0.05)
    raise RuntimeError(f"{SOCKET_PATH} did not appear within {timeout} seconds")


def run_test() -> None:
    ensure_daemon_built()
    if hasattr(builtins, "ANOTA_SYSCALL_SIGNAL_START") is False:
        raise RuntimeError("ANOTA_SYSCALL_SIGNAL_START missing from builtins")
    if hasattr(builtins, "ANOTA_SYSCALL_SIGNAL_STOP") is False:
        raise RuntimeError("ANOTA_SYSCALL_SIGNAL_STOP missing from builtins")

    if SOCKET_PATH.exists():
        SOCKET_PATH.unlink()

    env = os.environ.copy()
    env.setdefault("RUST_LOG", "warn")
    env["ANOTA_SYSCALL_SKIP_EBPF"] = "1"
    env.setdefault("RUSTUP_TOOLCHAIN", "nightly")
    daemon = subprocess.Popen(
        [str(DAEMON_PATH)],
        cwd=SYSCALL_MODULE,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        wait_for_socket()
        builtins.ANOTA_SYSCALL_SIGNAL_START(pid=os.getpid())
        builtins.ANOTA_SYSCALL_SIGNAL_STOP()
        print("ANOTA_SYSCALL integration test: OK")
    finally:
        daemon.send_signal(signal.SIGINT)
        try:
            daemon.wait(timeout=5)
        except subprocess.TimeoutExpired:
            daemon.kill()
            daemon.wait()
        if SOCKET_PATH.exists():
            SOCKET_PATH.unlink()


if __name__ == "__main__":
    run_test()
