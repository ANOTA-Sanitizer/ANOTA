"""
Regression tests for ANOTA_TAINT <-> DFSan integration in C extensions.

Run with the instrumented interpreter:

    ./python ANOTA-tests/anota_dfsan_test.py
"""

from __future__ import annotations

import builtins
import ctypes
import os
from pathlib import Path
import subprocess
import sys
import sysconfig

from anota_native import build_dfsan_extension


TAINT = builtins.ANOTA_TAINT
ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / "anota_dfsan_ext.c"
RUNNER_SOURCE = ROOT / "anota_dfsan_runner.c"
BUILD_DIR = ROOT / "build" / "anota_dfsan"
MODULE_NAME = "anota_dfsan_ext"
ABILIST = (ROOT.parent / "Include" / "anota_dfsan_abilist.txt").resolve()


def build_extension() -> Path:
    ext_suffix = sysconfig.get_config_var("EXT_SUFFIX") or ".so"
    return Path(
        build_dfsan_extension(
            module_name=MODULE_NAME,
            sources=[str(SOURCE)],
            output=str(BUILD_DIR / f"{MODULE_NAME}{ext_suffix}"),
            extra_compile_args=["-O0"],
        )
    )


def runtime_is_loaded() -> bool:
    process = ctypes.CDLL(None)
    try:
        getattr(process, "dfsan_set_label")
    except AttributeError:
        return False
    return True


def build_runner() -> Path:
    runner = BUILD_DIR / "anota_dfsan_runner"
    cmd = [
        "clang-19",
        str(RUNNER_SOURCE),
        "-fno-omit-frame-pointer",
        "-g",
        "-O1",
        "-fsanitize=dataflow",
        "-Xlinker",
        "-export-dynamic",
        "-o",
        str(runner),
    ]
    for include_dir in [sysconfig.get_path("include"), sysconfig.get_path("platinclude")]:
        if include_dir:
            cmd.extend(["-I", include_dir])
    cmd.extend(["-mllvm", f"-dfsan-abilist={ABILIST}"])

    cmd.append(str((ROOT.parent / "libpython3.10.a").resolve()))
    cmd.extend(["-lcrypt", "-ldl", "-lm"])

    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    subprocess.run(cmd, check=True, cwd=str(ROOT.parent))
    return runner


def ensure_dfsan_runtime_loaded() -> None:
    if runtime_is_loaded():
        os.environ["ANOTA_DFSAN_EMBEDDED_RUNTIME"] = "1"
        return
    runner = build_runner()
    env = os.environ.copy()
    pythonpath_entries = [str((ROOT.parent / "Lib").resolve())]
    pythonpath_entries.extend(
        str(path.resolve()) for path in sorted((ROOT.parent / "build").glob("lib.*"))
    )
    env["PYTHONHOME"] = str(ROOT.parent.resolve())
    env["PYTHONPATH"] = os.pathsep.join(pythonpath_entries)
    env["ANOTA_DFSAN_EMBEDDED_RUNTIME"] = "1"
    os.execve(str(runner), [str(runner), str(Path(__file__).resolve())], env)


def expect_runtime_error(callable_obj, *args) -> None:
    try:
        callable_obj(*args)
    except RuntimeError:
        return
    raise AssertionError("expected RuntimeError from ANOTA_TAINT native sink")


def expect_no_runtime_error(callable_obj, *args) -> None:
    try:
        callable_obj(*args)
    except RuntimeError as exc:
        raise AssertionError(f"unexpected RuntimeError: {exc!r}") from exc


def import_extension():
    extension = build_extension()
    sys.path.insert(0, str(extension.parent))
    try:
        return __import__(MODULE_NAME)
    except Exception:
        sys.path.pop(0)
        raise


def test_native_write_sink(module) -> None:
    secret = b"dfsan-write-secret"
    TAINT(secret)
    expect_runtime_error(module.copy_then_write, secret)


def test_native_printf_sink(module) -> None:
    secret = "dfsan-printf-secret"
    TAINT(secret)
    expect_runtime_error(module.copy_then_printf, secret)


def test_precise_native_return_is_tainted(module) -> None:
    secret = b"dfsan-return-secret"
    TAINT(secret, Sink=[print])

    returned = module.copy_then_return(secret)
    expect_runtime_error(print, returned)


def test_clean_native_return_stays_clean(module) -> None:
    secret = b"dfsan-clean-source"
    TAINT(secret, Sink=[print])

    returned = module.return_clean(secret)
    expect_no_runtime_error(print, returned)


def test_unrelated_clean_result_is_not_overtainted(module) -> None:
    secret = b"dfsan-overtaint-source"
    clean = b"public-value"
    TAINT(secret, Sink=[print])

    returned = module.return_second(secret, clean)
    expect_no_runtime_error(print, returned)


def test_builtin_c_methods_still_use_python_taint_fallback() -> None:
    secret = b"native-fallback"
    TAINT(secret, Sink=[print])

    returned = secret.upper()
    expect_runtime_error(print, returned)


def main() -> int:
    ensure_dfsan_runtime_loaded()
    module = import_extension()
    try:
        test_native_write_sink(module)
        test_native_printf_sink(module)
        test_precise_native_return_is_tainted(module)
        test_clean_native_return_stays_clean(module)
        test_unrelated_clean_result_is_not_overtainted(module)
        test_builtin_c_methods_still_use_python_taint_fallback()
    finally:
        sys.path.pop(0)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
