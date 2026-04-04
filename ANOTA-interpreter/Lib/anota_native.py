from __future__ import annotations

from pathlib import Path
import os
import shlex
import subprocess
import sysconfig


DEFAULT_DFSAN_CLANG = os.environ.get("ANOTA_DFSAN_CLANG", "clang-19")
DEFAULT_DFSAN_ABILIST = (
    Path(__file__).resolve().parent.parent / "Include" / "anota_dfsan_abilist.txt"
)


def _run(argv: list[str]) -> str:
    completed = subprocess.run(
        argv,
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def dfsan_runtime_path(clang: str = DEFAULT_DFSAN_CLANG) -> str:
    env_runtime = os.environ.get("ANOTA_DFSAN_RUNTIME")
    if env_runtime:
        return env_runtime
    shared_candidates = [
        Path("/tmp/llvm-build-dfsan-gd/lib/linux/libclang_rt.dfsan-x86_64.so"),
        Path("/tmp/llvm-build-dfsan/lib/linux/libclang_rt.dfsan-x86_64.so"),
    ]
    for shared_runtime in shared_candidates:
        if shared_runtime.exists():
            return str(shared_runtime)
    return _run([clang, "-print-file-name=libclang_rt.dfsan-x86_64.a"])


def dfsan_extension_flags(clang: str = DEFAULT_DFSAN_CLANG) -> dict[str, object]:
    repo_root = Path(__file__).resolve().parent.parent
    ext_suffix = sysconfig.get_config_var("EXT_SUFFIX") or ".so"
    include_dirs = [
        sysconfig.get_path("include"),
        sysconfig.get_path("platinclude"),
        str(repo_root / "Include"),
        str(repo_root),
    ]
    cflags = [
        "-fPIC",
        "-shared",
        "-fsanitize=dataflow",
        "-fno-sanitize-link-runtime",
        "-fno-omit-frame-pointer",
        "-g",
        "-O1",
    ]
    if DEFAULT_DFSAN_ABILIST.exists():
        cflags.extend(["-mllvm", f"-dfsan-abilist={DEFAULT_DFSAN_ABILIST}"])
    ldflags = ["-shared"]
    if os.environ.get("ANOTA_DFSAN_EMBEDDED_RUNTIME") != "1":
        runtime = dfsan_runtime_path(clang)
        if runtime.endswith(".so"):
            ldflags.extend([runtime, f"-Wl,-rpath,{Path(runtime).parent}"])
        else:
            ldflags.extend(["-fsanitize=dataflow", runtime])
    return {
        "clang": clang,
        "ext_suffix": ext_suffix,
        "include_dirs": [d for d in include_dirs if d and Path(d).exists()],
        "compile_flags": cflags,
        "link_flags": ldflags,
    }


def dfsan_extension_build_command(
    module_name: str,
    sources: list[str],
    output: str | None = None,
    clang: str = DEFAULT_DFSAN_CLANG,
    extra_compile_args: list[str] | tuple[str, ...] = (),
    extra_link_args: list[str] | tuple[str, ...] = (),
) -> list[str]:
    flags = dfsan_extension_flags(clang)
    if output is None:
        output = os.path.join("build", "anota_dfsan", module_name + flags["ext_suffix"])

    include_args: list[str] = []
    for include_dir in flags["include_dirs"]:
        include_args.extend(["-I", str(include_dir)])

    cmd = [
        str(flags["clang"]),
        *map(str, sources),
        *include_args,
        *map(str, flags["compile_flags"]),
        *map(str, extra_compile_args),
        "-o",
        output,
        *map(str, flags["link_flags"]),
        *map(str, extra_link_args),
    ]
    return cmd


def build_dfsan_extension(
    module_name: str,
    sources: list[str],
    output: str | None = None,
    clang: str = DEFAULT_DFSAN_CLANG,
    extra_compile_args: list[str] | tuple[str, ...] = (),
    extra_link_args: list[str] | tuple[str, ...] = (),
) -> str:
    cmd = dfsan_extension_build_command(
        module_name=module_name,
        sources=sources,
        output=output,
        clang=clang,
        extra_compile_args=extra_compile_args,
        extra_link_args=extra_link_args,
    )
    out_index = cmd.index("-o") + 1
    out_path = Path(cmd[out_index])
    out_path.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(cmd, check=True)
    return str(out_path)


def pretty_command(argv: list[str]) -> str:
    return " ".join(shlex.quote(part) for part in argv)


__all__ = [
    "DEFAULT_DFSAN_CLANG",
    "build_dfsan_extension",
    "dfsan_extension_build_command",
    "dfsan_extension_flags",
    "dfsan_runtime_path",
    "pretty_command",
]
