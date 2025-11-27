"""
anota_taint_test.py

Ad-hoc tests for the ANOTA_TAINT taint-tracking API and its integration
with the instrumented CPython interpreter.

Intended usage (from the ANOTA-instrumented build root):

    ./python anota_taint_test.py

These tests assume:

- A builtin called ANOTA_TAINT is available (implemented by _PyAnota_Taint),
  with the signature:

      ANOTA_TAINT(obj, sanitization=[hash], Sink=[print])

- Taint is enforced via _PyAnotaTaint_CheckVectorcall /
  _PyAnotaTaint_CheckTupleDictCall, which raise RuntimeError on violations.

- Sanitizers (e.g. hash) clear taint on their return values when called
  with tainted inputs, via _PyAnotaTaint_PostCall.
"""

import sys
import builtins
import traceback


def has_anota_taint() -> bool:
    """Return True if the ANOTA_TAINT builtin is present."""
    return hasattr(builtins, "ANOTA_TAINT")


def get_anota_taint():
    if not has_anota_taint():
        raise RuntimeError("ANOTA_TAINT builtin is not available")
    return builtins.ANOTA_TAINT


# ---------------------------------------------------------------------------
# Test infrastructure
# ---------------------------------------------------------------------------

def run_test(name, func):
    """Run a single test, print result, and return True/False."""
    print(f"=== {name} ===")
    try:
        func()
    except Exception:
        print(f"TEST {name}: FAIL")
        traceback.print_exc()
        print()
        return False
    else:
        print(f"TEST {name}: OK\n")
        return True


class ExpectedException(Exception):
    """Internal marker for expected failures."""


def expect_runtime_error(callable_obj, *args, **kwargs):
    """
    Call callable_obj(*args, **kwargs) and assert that it raises RuntimeError.

    If the call succeeds or raises some other exception type, this function
    raises AssertionError.
    """
    try:
        callable_obj(*args, **kwargs)
    except RuntimeError:
        # This is what the taint engine is expected to raise.
        return
    except Exception as exc:
        raise AssertionError(
            f"Expected RuntimeError, got {type(exc).__name__}: {exc!r}"
        ) from exc
    else:
        raise AssertionError("Expected RuntimeError, but call succeeded")


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_00_anota_taint_builtin_available():
    """
    Smoke-test that the ANOTA_TAINT builtin exists.

    This is a prerequisite for all other tests. If this fails, the remaining
    tests will likely error.
    """
    assert has_anota_taint(), "builtins should expose ANOTA_TAINT"
    taint = get_anota_taint()
    assert callable(taint), "ANOTA_TAINT should be callable"


def test_10_basic_taint_blocks_print_sink():
    """
    Mark a value as tainted with print as a sink; calling print on the
    tainted value should raise RuntimeError.
    """
    taint = get_anota_taint()

    secret = "super-secret"
    # Register print as a sink for this value.
    taint(secret, Sink=[print])

    # Printing the tainted value should be rejected.
    expect_runtime_error(print, secret)

    # But printing an untainted value is still fine.
    print("untainted-ok")  # should not raise


def test_20_untainted_values_can_use_sink():
    """
    Verify that registering a sink does not globally break the sink for
    untainted values.
    """
    taint = get_anota_taint()

    # Taint one specific object with print as sink.
    secret = "another-secret"
    taint(secret, Sink=[print])

    # Unrelated, untainted object should still be allowed.
    try:
        print("this should still be allowed")
    except RuntimeError as exc:
        raise AssertionError(
            f"print raised RuntimeError for untainted value: {exc!r}"
        ) from exc

    # But the tainted object should still be blocked.
    expect_runtime_error(print, secret)


def test_30_sanitizer_hash_clears_taint_for_result():
    """
    Mark a string as tainted, with hash as a sanitization function and
    print as a sink. The direct sink call on the tainted value must fail,
    but calling the sink on the hash result should succeed.

    This exercises _PyAnotaTaint_PostCall via the hash() sanitizer.
    """
    taint = get_anota_taint()

    secret = "password-123"
    # Register hash as a sanitizer, print as sink.
    taint(secret, sanitization=[hash], Sink=[print])

    # Directly printing the tainted value should be blocked.
    expect_runtime_error(print, secret)

    # Hashing the tainted value should produce an untainted result.
    h = hash(secret)

    # Printing the sanitized result should be allowed.
    print("hash-of-secret:", h)


def test_40_multiple_taints_and_sinks_independent():
    """
    Verify that taint registrations are object-specific and that sinks
    check taint on their arguments, not globally.

    We:
      - taint obj_a with print as a sink
      - taint obj_b with len as a (nonsensical) sink
    """
    taint = get_anota_taint()

    obj_a = "A"
    obj_b = "B"

    taint(obj_a, Sink=[print])
    taint(obj_b, Sink=[len])

    # obj_a: print is a sink, so this should fail.
    expect_runtime_error(print, obj_a)

    # obj_b: len is a sink here, so len(obj_b) should be rejected.
    expect_runtime_error(len, obj_b)

    # Cross-check:
    # - using len on obj_a should be fine (only print is sink for obj_a).
    len(obj_a)

    # - using print on obj_b should be fine (only len is sink for obj_b).
    print("obj_b-ok:", obj_b)


def test_50_sanitizer_idempotent_on_untainted():
    """
    Call ANOTA_TAINT with an empty sanitizer/sink config to ensure it
    doesn't explode on edge cases, and verify that sanitizers on
    already-untainted values don't break anything.
    """
    taint = get_anota_taint()

    value = "plain"
    # No sanitizers or sinks: should be a no-op from the perspective
    # of behavior, but should not crash.
    taint(value, sanitization=[], Sink=[])

    # Using sinks like print/len should still be fine.
    print("plain value:", value)
    len(value)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

TESTS = [
    ("00_anota_taint_builtin_available", test_00_anota_taint_builtin_available),
    ("10_basic_taint_blocks_print_sink", test_10_basic_taint_blocks_print_sink),
    ("20_untainted_values_can_use_sink", test_20_untainted_values_can_use_sink),
    ("30_sanitizer_hash_clears_taint_for_result", test_30_sanitizer_hash_clears_taint_for_result),
    ("40_multiple_taints_and_sinks_independent", test_40_multiple_taints_and_sinks_independent),
    ("50_sanitizer_idempotent_on_untainted", test_50_sanitizer_idempotent_on_untainted),
]


def main() -> int:
    if not has_anota_taint():
        print("ANOTA_TAINT builtin not found; marking tests as failed.")
        return 1

    ok = True
    for name, func in TESTS:
        if not run_test(name, func):
            ok = False

    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
