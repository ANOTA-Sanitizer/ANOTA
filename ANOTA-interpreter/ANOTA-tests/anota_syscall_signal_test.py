"""Annotation-to-daemon protocol regressions; no eBPF/root required.

Run with ./python ANOTA-tests/anota_syscall_signal_test.py.
The mock server is a separate process because annotation synchronization holds
CPython's GIL while waiting for the acknowledgement.
"""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile


def server(path, log):
    with socket.socket(socket.AF_UNIX) as listener:
        listener.bind(path)
        listener.listen()
        print("ready", flush=True)
        for _ in range(10):
            with listener.accept()[0] as stream:
                request = json.loads(stream.makefile("rb").readline())
                with open(log, "a") as output:
                    output.write(json.dumps(request) + "\n")
                if "NO_ACK" in request["blocked"]:
                    continue
                reply = b"ERR deliberately rejected\n" if "FORCED_REJECTION" in request["blocked"] else b"OK\n"
                stream.sendall(reply)


def main():
    ctrl = ANOTA_SYSCALL
    ctrl.clear()
    old_socket = os.environ.get("ANOTA_SYSCALL_SOCKET")
    old_backend = os.environ.get("ANOTA_SYSCALL_BACKEND")
    with tempfile.TemporaryDirectory(prefix="anota-protocol-") as tmp:
        path, log = str(Path(tmp) / "monitor.sock"), str(Path(tmp) / "requests.jsonl")
        env = dict(os.environ, ANOTA_SYSCALL_BACKEND="local")
        child = subprocess.Popen([sys.executable, __file__, "--server", path, log],
                                 stdout=subprocess.PIPE, text=True, env=env)
        try:
            assert child.stdout.readline().strip() == "ready"
            os.environ["ANOTA_SYSCALL_SOCKET"] = path
            os.environ["ANOTA_SYSCALL_BACKEND"] = "local"
            ctrl.READ.BLOCK(PATH="/tmp/audit-secret")
            ANOTA_SYSCALL_SIGNAL_START()                     # 0: initial snapshot
            ctrl.WRITE.BLOCK(PATH="/tmp/quote\"\nfile")        # 1: JSON escaping
            ctrl.READ.CLEAR()                                # 2: scoped clear
            for bad in ["FORCED_REJECTION", "NO_ACK"]:       # 3,4: rollback
                try:
                    ctrl.BLOCK(bad)
                except RuntimeError:
                    pass
                else:
                    raise AssertionError("monitor rejection/EOF must raise")
            ctrl.BLOCK("getppid")                            # 5: rollback verified
            ctrl.CLEAR()                                     # 6: global clear
            ANOTA_SYSCALL_SIGNAL_STOP()                      # 7
            os.environ["ANOTA_SYSCALL_BACKEND"] = "ebpf"
            ctrl.BLOCK("getppid")                            # 8: automatic install
            ANOTA_SYSCALL_SIGNAL_STOP()                      # 9
            child.wait(timeout=10)
            assert child.returncode == 0
            requests = [json.loads(line) for line in Path(log).read_text().splitlines()]
            assert len(requests) == 10
            assert all(r["version"] == 1 and r["pid"] == os.getpid() for r in requests)
            assert requests[0]["operations"]["READ"][1] == [[1, "/tmp/audit-secret"]]
            assert requests[1]["operations"]["WRITE"][1] == [[1, '/tmp/quote"\nfile']]
            assert "READ" not in requests[2]["operations"]
            assert requests[5]["blocked"] == ["GETPPID"]
            assert requests[6]["operations"] == {} and requests[6]["blocked"] == []
            assert requests[7]["action"] == requests[9]["action"] == "stop"
            assert requests[8]["action"] == "replace"
            print("ANOTA syscall protocol: all assertions passed")
        finally:
            if child.poll() is None:
                child.terminate()
                child.wait(timeout=5)
            for key, previous in [("ANOTA_SYSCALL_SOCKET", old_socket), ("ANOTA_SYSCALL_BACKEND", old_backend)]:
                if previous is None: os.environ.pop(key, None)
                else: os.environ[key] = previous


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--server":
        server(*sys.argv[2:])
    else:
        main()
