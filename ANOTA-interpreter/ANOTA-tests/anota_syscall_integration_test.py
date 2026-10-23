"""Real Aya daemon integration; --kernel also validates privileged eBPF capture.

python3 ANOTA-tests/anota_syscall_integration_test.py --python /path/to/anota/python
sudo python3 ANOTA-tests/anota_syscall_integration_test.py --kernel --python /path/to/anota/python

Build the daemon and BPF object before invoking this test. No automatic network
access or toolchain installation occurs. All sockets/files use a private temp dir.
"""
import argparse
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "syscall-module"

CLIENT = r'''
import ctypes, os, socket, subprocess, sys, threading
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
libc.open.argtypes = [ctypes.c_char_p, ctypes.c_int]
libc.read.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t]
base = sys.argv[1]
secret = base + '/secret'
with open(secret, 'w') as f: f.write('test')
with open(base + '/safe-source', 'w') as f: f.write('rename test')
# Open before registration: the daemon must seed descriptors from /proc.
fd = libc.open(secret.encode(), 0)
assert fd >= 0
ANOTA_SYSCALL_SIGNAL_START()
ANOTA_SYSCALL.BLOCK('getppid')
libc.syscall(110)  # bypass every CPython syscall wrapper
ANOTA_SYSCALL.READ.BLOCK(PATH=secret)
buf = ctypes.create_string_buffer(16)
assert libc.read(fd, buf, 4) == 4
libc.close(fd)
ANOTA_SYSCALL.READ.CLEAR()
ANOTA_SYSCALL.FILE.BLOCK(PATH=base + '/blocked*')
# Short-lived child: inheritance must happen in the kernel before first syscall.
child = os.fork()
if child == 0:
    libc.open((base + '/blocked-child').encode(), 0)
    os._exit(0)
os.waitpid(child, 0)
# New thread, without a registration call in the thread.
def worker(): libc.open((base + '/blocked-thread').encode(), 0)
t = threading.Thread(target=worker); t.start(); t.join()
# An exec'd native child and both sides of a rename are decoded too.
subprocess.run(['/bin/cat', base + '/blocked-exec'], capture_output=True)
os.rename(base + '/safe-source', base + '/blocked-rename')
# openat's pathname is relative to the directory descriptor.
directory = os.open(base, os.O_RDONLY | os.O_DIRECTORY)
libc.openat(directory, b'blocked-dirfd', 0)
os.close(directory)
# Actual socket syscalls: numeric address and protocol, no external network.
ANOTA_SYSCALL.CONNECT.BLOCK(IP='127.0.0.1')
ANOTA_SYSCALL.SOCKET.BLOCK(PROTOCOL='UDP')
with socket.socket() as sock: sock.connect_ex(('127.0.0.1', 1))
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM): pass
# Atomic clear/replacement: this distinctive name must not be reported.
ANOTA_SYSCALL.CLEAR()
libc.open((base + '/blocked-after-clear').encode(), 0)
ANOTA_SYSCALL_SIGNAL_STOP()
print('client completed normally')
'''


def wait_ready(daemon, path, log):
    for _ in range(200):
        if daemon.poll() is not None:
            raise AssertionError("daemon exited during startup:\n" + log.read_text())
        if path.exists(): return
        time.sleep(0.025)
    raise AssertionError("daemon did not create control socket")


def exchange(path, request):
    with socket.socket(socket.AF_UNIX) as stream:
        stream.settimeout(5)
        stream.connect(str(path))
        stream.sendall((json.dumps(request) + "\n").encode())
        return stream.makefile("rb").readline().decode()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--python", type=Path, default=ROOT / "python")
    parser.add_argument("--kernel", action="store_true")
    args = parser.parse_args()
    binary = MODULE / "target/release/syscall-tracepoint"
    bpf = MODULE / "target/bpfel-unknown-none/release/syscall-tracepoint"
    assert binary.exists(), "build the release daemon first"
    assert args.python.exists(), "build the ANOTA interpreter or pass --python"
    with tempfile.TemporaryDirectory(prefix="anota-integration-") as tmp:
        tmp = Path(tmp)
        path, log = tmp / "monitor.sock", tmp / "daemon.log"
        command = [str(binary), "--socket", str(path), "--uid", str(os.getuid())]
        command += ["--bpf", str(bpf)] if args.kernel else ["--control-only"]
        with log.open("w") as output:
            daemon = subprocess.Popen(command, stdout=output, stderr=output)
        try:
            wait_ready(daemon, path, log)
            # Invalid policies must receive an error, never a successful ACK.
            request = dict(version=1, action="replace", pid=os.getpid(), blocked=["not_a_syscall"])
            assert exchange(path, request).startswith("ERR ")
            env = dict(os.environ, ANOTA_SYSCALL_SOCKET=str(path), ANOTA_SYSCALL_BACKEND="local")
            client = subprocess.run([str(args.python), "-c", CLIENT, str(tmp)], env=env,
                                    text=True, capture_output=True, timeout=30)
            assert client.returncode == 0, client.stderr
            assert "client completed normally" in client.stdout
            time.sleep(0.3)  # allow queued syscall-exit events to be drained
        finally:
            if daemon.poll() is None: daemon.send_signal(signal.SIGTERM)
            daemon.wait(timeout=5)
            diagnostic = log.read_text()
            print(diagnostic, end="")
        assert daemon.returncode == 0
        if args.kernel:
            violations = "\n".join(line for line in diagnostic.splitlines() if "violation:" in line)
            for expected in ["GETPPID", "secret", "blocked-child", "blocked-thread", "blocked-dirfd", "blocked-exec", "blocked-rename", "127.0.0.1", "SOCKET"]:
                assert expected in violations, f"missing violation for {expected}; see daemon log above"
            assert "blocked-after-clear" not in violations, "cleared policy still produced a violation"
            assert "events lost" not in diagnostic, "kernel dropped events; see daemon log above"
        else:
            assert "NO kernel syscall capture" in diagnostic
            assert "violation:" not in diagnostic
        print("ANOTA syscall integration: PASS ({} mode)".format("kernel" if args.kernel else "control-only"))


if __name__ == "__main__":
    main()
