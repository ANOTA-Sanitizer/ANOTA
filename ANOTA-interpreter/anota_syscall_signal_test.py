"""Smoke tests for ANOTA_SYSCALL_SIGNAL_START / STOP helpers.

This script spins up a lightweight UNIX domain socket server that mimics the
Rust monitoring daemon. It verifies that the Python helpers emit the expected
commands and handle responses without errors.

Run with the ANOTA-enabled interpreter:

    ./python anota_syscall_signal_test.py
"""

from __future__ import annotations

import builtins
import errno
import os
import socket
import threading
import time
import sys

SOCKET_PATH = "/tmp/anota_syscall.sock"


class DummyMonitorServer:
    """Simple server that collects commands sent to the control socket."""

    def __init__(self) -> None:
        if os.path.exists(SOCKET_PATH):
            os.unlink(SOCKET_PATH)
        self._stop = threading.Event()
        self._commands: list[str] = []
        self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._sock.bind(SOCKET_PATH)
        self._sock.listen(1)
        self._thread = threading.Thread(target=self._serve, daemon=True)

    @property
    def commands(self) -> list[str]:
        return self._commands

    def start(self) -> None:
        self._thread.start()

    def close(self) -> None:
        self._stop.set()
        try:
            self._sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self._sock.close()
        if os.path.exists(SOCKET_PATH):
            os.unlink(SOCKET_PATH)
        self._thread.join(timeout=1)

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except OSError as exc:
                if exc.errno in {errno.EBADF, errno.ENOTSOCK}:
                    break
                continue
            with conn:
                data = b""
                while True:
                    chunk = conn.recv(1024)
                    if not chunk:
                        break
                    data += chunk
                    if b"\n" in data:
                        break
                try:
                    decoded = data.decode()
                except UnicodeDecodeError:
                    decoded = ""
                if decoded:
                    self._commands.append(decoded)
                try:
                    conn.sendall(b"OK\n")
                except OSError:
                    pass


def ensure_helpers_available() -> None:
    missing = [
        name
        for name in ("ANOTA_SYSCALL_SIGNAL_START", "ANOTA_SYSCALL_SIGNAL_STOP")
        if not hasattr(builtins, name)
    ]
    if missing:
        raise RuntimeError(
            "Missing builtin(s): {}. "
            "Are you running the ANOTA-enabled interpreter?".format(
                ", ".join(missing)
            )
        )


def main() -> int:
    if os.name != "posix":
        print("This test only runs on Unix platforms.")
        return 0

    ensure_helpers_available()
    server = DummyMonitorServer()
    server.start()
    try:
        builtins.ANOTA_SYSCALL_SIGNAL_START(pid=os.getpid())
        builtins.ANOTA_SYSCALL_SIGNAL_START()
        builtins.ANOTA_SYSCALL_SIGNAL_STOP()
        time.sleep(0.1)
        expected = ["START {}\n".format(os.getpid()), "START\n", "STOP\n"]
        if server.commands[:3] != expected:
            raise AssertionError(
                "Unexpected command sequence: {!r}".format(server.commands)
            )
        print("ANOTA_SYSCALL signal helpers: OK")
        return 0
    finally:
        server.close()


if __name__ == "__main__":
    sys.exit(main())
