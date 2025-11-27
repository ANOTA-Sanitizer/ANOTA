"""Readable smoke tests for the ANOTA_SYSCALL monitoring API."""

from __future__ import annotations

import builtins
import os
import socket
import sys
import tempfile
from pathlib import Path


def have_controller():
    ctrl = getattr(builtins, "ANOTA_SYSCALL", None)
    if ctrl is None:
        print("ANOTA_SYSCALL builtin not available; tests skipped.")
        return None
    return ctrl


def reset_policy(ctrl):
    ctrl.clear()


def test_block_open(ctrl):
    reset_policy(ctrl)
    ctrl.BLOCK("open")
    try:
        with open(__file__, "r", encoding="utf-8") as handle:
            handle.read(8)
    except Exception as exc:
        print("test_block_open: unexpected exception", exc)
        return False
    finally:
        reset_policy(ctrl)
    return True


def test_read_path_block(ctrl):
    reset_policy(ctrl)
    with tempfile.TemporaryDirectory() as tmpdir:
        folder = Path(tmpdir)
        secret = folder / "secret.txt"
        secret.write_text("classified", encoding="utf-8")
        ctrl.READ.BLOCK(PATH=str(secret))
        try:
            with open(secret, "r", encoding="utf-8") as handle:
                handle.read()
        except Exception as exc:
            print("test_read_path_block: unexpected exception", exc)
            reset_policy(ctrl)
            return False
    reset_policy(ctrl)
    return True


def test_write_path_block(ctrl):
    reset_policy(ctrl)
    with tempfile.TemporaryDirectory() as tmpdir:
        folder = Path(tmpdir)
        target = folder / "out.txt"
        ctrl.WRITE.BLOCK(PATH=str(folder))
        try:
            with open(target, "w", encoding="utf-8") as handle:
                handle.write("payload")
        except Exception as exc:
            print("test_write_path_block: unexpected exception", exc)
            reset_policy(ctrl)
            return False
    reset_policy(ctrl)
    return True


def test_directory_block(ctrl):
    reset_policy(ctrl)
    with tempfile.TemporaryDirectory() as tmpdir:
        folder = Path(tmpdir) / "nested"
        folder.mkdir()
        nested_file = folder / "inner.txt"
        nested_file.write_text("data", encoding="utf-8")
        ctrl.READ.BLOCK(PATH=str(folder) + os.sep)
        try:
            with open(nested_file, "r", encoding="utf-8") as handle:
                handle.read()
        except Exception as exc:
            print("test_directory_block: unexpected exception", exc)
            reset_policy(ctrl)
            return False
    reset_policy(ctrl)
    return True


def test_path_wildcard(ctrl):
    reset_policy(ctrl)
    with tempfile.TemporaryDirectory() as tmpdir:
        folder = Path(tmpdir)
        target = folder / "prefix_secret.txt"
        target.write_text("hidden", encoding="utf-8")
        ctrl.READ.BLOCK(PATH="*secret.txt")
        try:
            with open(target, "r", encoding="utf-8") as handle:
                handle.read()
        except Exception as exc:
            print("test_path_wildcard: unexpected exception", exc)
            reset_policy(ctrl)
            return False
    reset_policy(ctrl)
    return True


def test_read_allow(ctrl):
    reset_policy(ctrl)
    with tempfile.TemporaryDirectory() as tmpdir:
        folder = Path(tmpdir)
        allowed = folder / "allowed.txt"
        other = folder / "other.txt"
        allowed.write_text("safe", encoding="utf-8")
        other.write_text("unsafe", encoding="utf-8")
        ctrl.READ.ALLOW(PATH=str(allowed))
        try:
            with open(allowed, "r", encoding="utf-8") as handle:
                handle.read()
            with open(other, "r", encoding="utf-8") as handle:
                handle.read()
        except Exception as exc:
            print("test_read_allow: unexpected exception", exc)
            reset_policy(ctrl)
            return False
    reset_policy(ctrl)
    return True


def test_exec_block(ctrl):
    reset_policy(ctrl)
    ctrl.BLOCK("execv")
    try:
        os.execv("__anota_missing_exec__", ["__anota_missing_exec__"])
    except FileNotFoundError:
        pass
    except Exception as exc:
        print("test_exec_block: unexpected exception", exc)
        reset_policy(ctrl)
        return False
    reset_policy(ctrl)
    return True


def _exercise_connect(host):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.1)
    try:
        try:
            sock.connect((host, 9))
        except OSError:
            pass
    finally:
        sock.close()


def test_connect_domain_block(ctrl):
    reset_policy(ctrl)
    ctrl.CONNECT.BLOCK(DOMAIN="localhost")
    _exercise_connect("localhost")
    reset_policy(ctrl)
    return True


def test_connect_ip_block(ctrl):
    reset_policy(ctrl)
    ctrl.CONNECT.BLOCK(IP="127.0.0.1")
    _exercise_connect("127.0.0.1")
    reset_policy(ctrl)
    return True


def test_protocol_block(ctrl):
    reset_policy(ctrl)
    ctrl.SOCKET.BLOCK(PROTOCOL="TCP")
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
    except Exception as exc:
        print("test_protocol_block: unexpected exception", exc)
        reset_policy(ctrl)
        return False
    finally:
        if sock is not None:
            sock.close()
    reset_policy(ctrl)
    return True


def test_domain_wildcard(ctrl):
    reset_policy(ctrl)
    ctrl.CONNECT.BLOCK(DOMAIN="local*")
    _exercise_connect("localhost")
    reset_policy(ctrl)
    return True


def test_ip_wildcard(ctrl):
    reset_policy(ctrl)
    ctrl.CONNECT.BLOCK(IP="127.*")
    _exercise_connect("127.0.0.1")
    reset_policy(ctrl)
    return True


def test_protocol_wildcard(ctrl):
    reset_policy(ctrl)
    ctrl.SOCKET.BLOCK(PROTOCOL="*")
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
    except Exception as exc:
        print("test_protocol_wildcard: unexpected exception", exc)
        reset_policy(ctrl)
        return False
    finally:
        if sock is not None:
            sock.close()
    reset_policy(ctrl)
    return True


def main():
    ctrl = have_controller()
    if ctrl is None:
        return 1

    tests = [
        ("block open syscall", test_block_open),
        ("block read paths", test_read_path_block),
        ("block write paths", test_write_path_block),
        ("block directories", test_directory_block),
        ("wildcard paths", test_path_wildcard),
        ("read allow list", test_read_allow),
        ("exec monitoring", test_exec_block),
        ("network domain block", test_connect_domain_block),
        ("network IP block", test_connect_ip_block),
        ("protocol block", test_protocol_block),
        ("wildcard domain", test_domain_wildcard),
        ("wildcard IP", test_ip_wildcard),
        ("wildcard protocol", test_protocol_wildcard),
    ]

    failures = 0
    for label, func in tests:
        ok = func(ctrl)
        print(f"[ANOTA_SYSCALL] {label}: {'OK' if ok else 'FAILED'}")
        if not ok:
            failures += 1

    if failures:
        print(f"{failures} test(s) failed.")
        return 1

    print("All ANOTA_SYSCALL tests executed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
