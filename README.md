# ANOTA: Identifying Business Logic Vulnerabilities via Annotation-Based Sanitization

This repository contains the artifact for the ANOTA paper.

The top-level README is a map of the repository. Build steps, test procedures,
and evaluation details live in the README files inside each major component.

## Start Here

- To build the instrumented CPython fork and run the ANOTA tests, read
  [`ANOTA-interpreter/README.md`](ANOTA-interpreter/README.md).
- To work with the syscall tracing backend directly, read
  [`ANOTA-interpreter/syscall-module/README.md`](ANOTA-interpreter/syscall-module/README.md).
- To reproduce the performance comparison against DBI-based baselines, start in
  [`SupplementaryMaterials/cmp-with-DBI/`](SupplementaryMaterials/cmp-with-DBI/).
- To review the user-study materials, start in
  [`SupplementaryMaterials/user-study/`](SupplementaryMaterials/user-study/).

## Repository Layout

- [`ANOTA-interpreter/`](ANOTA-interpreter/) contains ANOTA's CPython 3.10.13
  fork. It implements `ANOTA_EXECUTION`, `ANOTA_WATCH`, `ANOTA_TAINT`, and
  `ANOTA_SYSCALL`, and it documents the `WATCH.CON` timing test,
  object-identity taint tracking, and the current native instrumentation
  support.
- [`ANOTA-interpreter/syscall-module/`](ANOTA-interpreter/syscall-module/)
  contains the Rust workspace for the eBPF tracepoint components used by the
  syscall policy system.
- [`SupplementaryMaterials/annotation_study_details.md`](SupplementaryMaterials/annotation_study_details.md)
  contains participant details, feedback, and results for the annotation
  study.
- [`SupplementaryMaterials/cmp-with-DBI/`](SupplementaryMaterials/cmp-with-DBI/)
  contains the DynamoRIO and Valgrind memory-tracing baselines, plus the
  scripts used for the paper's performance comparison.
- [`SupplementaryMaterials/cmp-with-DBI/perf-data/`](SupplementaryMaterials/cmp-with-DBI/perf-data/)
  contains the supplementary performance-comparison data for the DBI baselines.
- [`SupplementaryMaterials/cwe_top_40.md`](SupplementaryMaterials/cwe_top_40.md)
  contains the analysis of ANOTA's coverage of the CWE Top 40 Security
  Weaknesses.
- [`SupplementaryMaterials/perf-benchmark.md`](SupplementaryMaterials/perf-benchmark.md)
  contains the benchmark setup and performance evaluation results.
- [`SupplementaryMaterials/skipped_applications.md`](SupplementaryMaterials/skipped_applications.md)
  contains the list of applications excluded from the evaluation, with
  reasons.
- [`SupplementaryMaterials/user-study/`](SupplementaryMaterials/user-study/)
  contains the annotation training materials and survey assets for the
  real-world developer study.

## How to Navigate the Artifact

1. Start with `ANOTA-interpreter/README.md` to build the instrumented interpreter and run the ANOTA samples.
2. Move to `ANOTA-interpreter/syscall-module/README.md` when you need syscall tracing or you want to use it w/o ANOTA's CPython interpreter.
3. Use the documentation inside `SupplementaryMaterials/cmp-with-DBI/` for the performance comparisons against the DBI memory trace baselines.
4. Consult `SupplementaryMaterials/user-study/` if you are re-running the annotation study or the real-world developer study survey described in the paper.
