"""
Regression tests for ANOTA_WATCH.CON.

Run with the instrumented interpreter:

    ./python ANOTA-tests/anota_watch_con_test.py
"""

from __future__ import annotations

import builtins


AW = builtins.ANOTA_WATCH


def leaky(data: bytes) -> int:
    loops = 500 if data[0] == 0 else 25000
    acc = 0
    for i in range(loops):
        acc ^= i
    return acc


def constant(data: bytes) -> int:
    acc = 0
    for i in range(8000):
        acc ^= i ^ data[0]
    return acc


def main() -> int:
    fixed = (b"\x00",)
    randomish = (b"\xff",)

    summary = AW.CON(constant, fixed, randomish,
                     number_measurements=200, threshold=8.0)
    print("constant summary:", summary)

    try:
        AW.CON(leaky, fixed, randomish,
               number_measurements=200, threshold=8.0)
    except RuntimeError as exc:
        print("leaky summary: RuntimeError:", exc)
        return 0

    raise AssertionError("expected ANOTA_WATCH.CON to flag leaky()")


if __name__ == "__main__":
    raise SystemExit(main())
