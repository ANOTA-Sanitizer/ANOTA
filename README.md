# Anota: Identifying Business Logic Vulnerabilities via Annotation-Based Sanitization

This repository contains the full artifact for the ANOTA paper. Each subdirectory ships with its own README that documents build steps, test procedures, and evaluation notes. The top-level README stays intentionally high level and simply orients you toward the right component.

---

## Directory Overview

- [`ANOTA-interpreter/`](ANOTA-interpreter/) – ANOTA’s CPython 3.10.13 fork that introduces the `ANOTA_EXECUTION`, `ANOTA_WATCH`, `ANOTA_TAINT`, and `ANOTA_SYSCALL` primitives. See `ANOTA-interpreter/README.md` for detailed build and validation instructions.
- [`ANOTA-interpreter/syscall-module/`](ANOTA-interpreter/syscall-module/) – Rust workspace that provides the eBPF tracepoints used by the syscall policies. Refer to `ANOTA-interpreter/syscall-module/README.md`.
- [`cmp-with-DBI/`](cmp-with-DBI/) – DynamoRIO and Valgrind memory-tracing baselines plus the scripts used for the performance comparison in the paper. Consult `cmp-with-DBI/readme.md`.
- [`cmp-with-DBI/perf-data/`](cmp-with-DBI/perf-data/) – Supplementary data for performance comparison with DBIs; summarized documentation lives in `cmp-with-DBI/perf-data/readme.md`.
- [`user-study/`](user-study/) – Annotation training packet and real-world developer survey materials.
- [`syscall_name.c`](syscall_name.c) – Small helper program that maps syscall numbers to symbolic names when triaging traces.
- [`README.rst`](README.rst) – Original CPython README retained for reference on the unmodified interpreter infrastructure.

---

## How to Navigate the Artifact

1. Start with `ANOTA-interpreter/README.md` to build the instrumented interpreter and run the ANOTA samples.
2. Move to `ANOTA-interpreter/syscall-module/README.md` when you need syscall tracing or you want to use it w/o ANOTA's CPython interpreter.
3. Use the documentation inside `cmp-with-DBI/` for the performance comparisons against the DBI memory trace baselines.
4. Consult `user-study/` if you are re-running the annotation study or the real-world developer study survey described in the paper.
