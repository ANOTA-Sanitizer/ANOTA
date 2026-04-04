"""
Regression tests for integrated ANOTA_WATCH native C-extension monitoring.

Run with the instrumented interpreter:

    ./python ANOTA-tests/anota_cext_watch_test.py
"""

from __future__ import annotations

import builtins
from pathlib import Path
import platform
import subprocess
import sys
import sysconfig


AW = builtins.ANOTA_WATCH
ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / "anota_cext_watch_ext.c"
BUILD_DIR = ROOT / "build" / "anota_cext_watch"
MODULE_NAME = "anota_cext_watch_ext"


def require_linux_x86_64() -> None:
    if sys.platform != "linux":
        raise SystemExit("skipping: ptrace watchpoint test requires Linux")
    if platform.machine() != "x86_64":
        raise SystemExit("skipping: ptrace watchpoint test requires x86_64")


def build_extension() -> Path:
    include_dirs = [
        sysconfig.get_path("include"),
        sysconfig.get_path("platinclude"),
    ]
    ext_suffix = sysconfig.get_config_var("EXT_SUFFIX") or ".so"
    output = BUILD_DIR / f"{MODULE_NAME}{ext_suffix}"
    BUILD_DIR.mkdir(parents=True, exist_ok=True)

    cmd = [
        "gcc",
        "-shared",
        "-fPIC",
        "-O0",
        "-g",
        "-o",
        str(output),
        str(SOURCE),
    ]
    for include_dir in include_dirs:
        if include_dir:
            cmd.extend(["-I", include_dir])

    subprocess.run(cmd, check=True)
    return output


def run_automatic_watch_violation() -> None:
    extension = build_extension()
    sys.path.insert(0, str(extension.parent))
    try:
        mod = __import__(MODULE_NAME)
        payload = bytearray(b"abcdef")

        AW.CLEAR_ALL()
        AW.ALLOW(payload, "R")

        assert mod.read_first_byte(payload) == ord("a")

        try:
            mod.write_first_byte(payload, ord("z"))
        except RuntimeError as exc:
            print("automatic native watch violation:", exc)
        else:
            raise AssertionError("expected RuntimeError from native ANOTA_WATCH violation")

        assert payload[0] == ord("z"), "watchpoint should report after the native write executes"
    finally:
        AW.CLEAR_ALL()
        sys.path.pop(0)


def main() -> int:
    require_linux_x86_64()
    run_automatic_watch_violation()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
