"""
ANOTA_WATCH object access tests for the modified CPython interpreter.

This module is intended to be run with the custom interpreter binary
that has ANOTA_WATCH support compiled in and exposed via ``builtins.ANOTA_WATCH``.

    ./python anota_object_access_test.py

The tests exercise the bytecode-level hooks added in ``ceval.c`` that call:

    _PyAnota_CheckReadObject
    _PyAnota_CheckWriteObject
    _PyAnota_CheckExecObject
    _PyAnota_CheckReadMember
    _PyAnota_CheckWriteMember

We deliberately trigger both ALLOWED and BLOCKED operations to verify:

- Object-level read control:
    - Local/global/closure variable loads (opcodes like LOAD_FAST, LOAD_NAME,
      LOAD_GLOBAL, LOAD_DEREF, LOAD_CLASSDEREF) respect read policies.
- Object-level execute control:
    - Calls through CALL_FUNCTION, CALL_METHOD, CALL_FUNCTION_KW,
      CALL_FUNCTION_EX, and their helpers respect execute policies.
- Member-level read/write control:
    - Attribute access (LOAD_ATTR / STORE_ATTR) is checked via
      _PyAnota_CheckReadMember / _PyAnota_CheckWriteMember.
    - Subscript access (BINARY_SUBSCR / STORE_SUBSCR) for dicts/lists is also
      checked via the member helpers.
- ALLOW mask semantics:
    - When an allow mask is present (e.g. ALLOW(obj, "R")), non-mentioned
      modes (e.g. "W") are implicitly blocked.

Each test prints a short description of what it is exercising and logs whether
it observed an expected RuntimeError raised by the ANOTA_WATCH engine. Any
UNEXPECTED line indicates a mismatch between expected behaviour and what the
interpreter actually did.
"""

from __future__ import annotations

import builtins
from typing import Any


try:
    AW = builtins.ANOTA_WATCH
    AE = builtins.ANOTA_EXECUTION
except AttributeError as exc:  # pragma: no cover - sanity guard
    raise RuntimeError(
        "ANOTA_WATCH or ANOTA_EXECUTION not found in builtins. "
        "Run this file with the modified ./python interpreter."
    ) from exc


def _section(title: str) -> None:
    """Print a section header for clarity in test output."""
    print("\n" + "=" * 72)
    print(title)
    print("=" * 72)


def test_object_read() -> None:
    """
    Test object-level READ control.

    This primarily exercises:

        - _PyAnota_CheckReadObject
        - Bytecodes like LOAD_FAST / LOAD_NAME / LOAD_GLOBAL corresponding
          to variable reads.

    Behaviour under test:
        1. With no policy: reading a local variable referring to an object
           should succeed.
        2. After AW.BLOCK(obj, "R"): reading that object via any variable
           should raise RuntimeError.
        3. After AW.CLEAR(obj): reads should succeed again.
    """
    _section("Object-level READ: BLOCK then CLEAR")

    x = [1, 2, 3]
    print("[baseline] read of x OK:", x)

    # Block all READ accesses to this specific object.
    AW.BLOCK(x, "R")

    try:
        # LOAD_FAST on x should now trigger a policy violation.
        y = x
        print("[UNEXPECTED] read of x succeeded, y =", y)
    except RuntimeError as e:
        print("[expected] RuntimeError on read of x:", e)

    # Clear all policies. Calling CLEAR(x) itself would perform a READ of x
    # (to evaluate the argument), which is also subject to the object-level
    # R block. Using CLEAR_ALL() avoids that and removes the rule for all
    # objects so that we can safely read x again.
    AW.CLEAR_ALL()
    try:
        y = x
        print("[after CLEAR_ALL] read of x OK:", y)
    except RuntimeError as e:
        print("[UNEXPECTED] RuntimeError on read of x after CLEAR_ALL:", e)


def test_exec_block() -> None:
    """
    Test object-level EXEC control for callables.

    This primarily exercises:

        - _PyAnota_CheckExecObject
        - CALL_FUNCTION and CALL_FUNCTION_EX paths in ceval.c.

    Behaviour under test:
        1. With no policy: calling a plain Python function should succeed.
        2. After AW.BLOCK(func, "X"): calling that function should raise
           RuntimeError.
        3. After AW.CLEAR(func): the call should succeed again.
    """
    _section("Object-level EXEC: BLOCK then CLEAR")

    def f() -> int:
        return 42

    print("[baseline] f() returns:", f())

    AW.BLOCK(f, "X")

    try:
        f()
        print("[UNEXPECTED] call to f() succeeded despite EXEC block")
    except RuntimeError as e:
        print("[expected] RuntimeError on exec of f():", e)

    AW.CLEAR(f)
    print("[after CLEAR] f() returns:", f())


def test_attr_read_write() -> None:
    """
    Test attribute READ and WRITE control on an instance attribute.

    This primarily exercises:

        - _PyAnota_CheckReadMember  via LOAD_ATTR
        - _PyAnota_CheckWriteMember via STORE_ATTR

    Behaviour under test:
        1. With no policy: reading and writing attributes should succeed.
        2. After AW.BLOCK(obj, "R", key="secret"):
              - Reading obj.secret should raise RuntimeError.
              - Reading other attributes remains allowed.
        3. After AW.BLOCK(obj, "W", key="value"):
              - Writing obj.value should raise RuntimeError.
        4. After AW.CLEAR(obj, key=...), both attributes behave normally.
    """
    _section("Attribute READ/WRITE on instance attribute")

    class C:
        def __init__(self) -> None:
            # Two attributes so that we can restrict them independently.
            self.secret = 1
            self.value = 10

    c = C()
    print("[baseline] c.secret, c.value =", c.secret, c.value)

    # Block READs of the 'secret' attribute only.
    AW.BLOCK(c, "R", key="secret")

    try:
        print("[attempt] reading c.secret (should be blocked):", c.secret)
        print("[UNEXPECTED] read of c.secret succeeded")
    except RuntimeError as e:
        print("[expected] RuntimeError when reading c.secret:", e)

    # 'value' remains readable.
    print("[expected] read of c.value still OK:", c.value)

    # Block WRITEs to 'value' only.
    AW.BLOCK(c, "W", key="value")

    try:
        c.value = 999
        print("[UNEXPECTED] write to c.value succeeded")
    except RuntimeError as e:
        print("[expected] RuntimeError when writing c.value:", e)

    # Clear both policies and confirm normal behaviour.
    AW.CLEAR(c, key="secret")
    AW.CLEAR(c, key="value")

    c.secret = 2
    c.value = 20
    print("[after CLEAR] c.secret, c.value =", c.secret, c.value)


def test_dict_subscript() -> None:
    """
    Test READ and WRITE control for dict subscripts.

    This primarily exercises:

        - _PyAnota_CheckReadMember  via BINARY_SUBSCR
        - _PyAnota_CheckWriteMember via STORE_SUBSCR

    Behaviour under test:
        1. With no policy: reads and writes of d[key] should succeed.
        2. After AW.BLOCK(d, "R", key="secret"):
              - Reading d["secret"] should raise RuntimeError.
              - Reading other keys remains allowed.
        3. After AW.BLOCK(d, "W", key="public"):
              - Writing d["public"] should raise RuntimeError.
        4. After AW.CLEAR(d, key=...), dict operations behave normally.
    """
    _section("Dict subscript READ/WRITE")

    d = {"secret": 42, "public": 1}
    print("[baseline] d['secret'], d['public'] =", d["secret"], d["public"])

    # Block READs of the "secret" key.
    AW.BLOCK(d, "R", key="secret")

    try:
        print("[attempt] d['secret'] (should be blocked):", d["secret"])
        print("[UNEXPECTED] read of d['secret'] succeeded")
    except RuntimeError as e:
        print("[expected] RuntimeError on d['secret']:", e)

    # Other keys remain readable.
    print("[expected] read of d['public'] OK:", d["public"])

    # Block WRITEs to the "public" key.
    AW.BLOCK(d, "W", key="public")

    try:
        d["public"] = 99
        print("[UNEXPECTED] write to d['public'] succeeded")
    except RuntimeError as e:
        print("[expected] RuntimeError on write to d['public']:", e)

    # Clear both policies and confirm normal behaviour.
    AW.CLEAR(d, key="secret")
    AW.CLEAR(d, key="public")

    d["secret"] = 100
    d["public"] = 200
    print("[after CLEAR] d =", d)


def test_list_subscript() -> None:
    """
    Test READ and WRITE control for list subscripts.

    This primarily exercises:

        - _PyAnota_CheckReadMember  via BINARY_SUBSCR on a list
        - _PyAnota_CheckWriteMember via STORE_SUBSCR on a list

    Behaviour under test:
        1. With no policy: reading and writing lst[i] should succeed.
        2. After AW.BLOCK(lst, "R", key=1):
              - Reading lst[1] should raise RuntimeError.
        3. After AW.BLOCK(lst, "W", key=2):
              - Writing lst[2] should raise RuntimeError.
        4. After AW.CLEAR(lst, key=...), list operations behave normally.
    """
    _section("List subscript READ/WRITE")

    lst = [10, 20, 30]
    print("[baseline] lst[1] =", lst[1])

    # Block READs of index 1.
    AW.BLOCK(lst, "R", key=1)

    try:
        print("[attempt] lst[1] (should be blocked):", lst[1])
        print("[UNEXPECTED] read of lst[1] succeeded")
    except RuntimeError as e:
        print("[expected] RuntimeError on lst[1]:", e)

    # Other indices remain readable.
    print("[expected] read of lst[0] OK:", lst[0])

    # Block WRITEs to index 2.
    AW.BLOCK(lst, "W", key=2)

    try:
        lst[2] = 999
        print("[UNEXPECTED] write to lst[2] succeeded")
    except RuntimeError as e:
        print("[expected] RuntimeError on write to lst[2]:", e)

    # Clear and confirm normal behaviour.
    AW.CLEAR(lst, key=1)
    AW.CLEAR(lst, key=2)

    lst[1] = 111
    lst[2] = 222
    print("[after CLEAR] lst =", lst)


def test_allow_only_read() -> None:
    """
    Test ALLOW-only semantics: ALLOW(obj, "R") with no W/X bits.

    This primarily validates the policy interpretation logic in
    ``_anota_check_access``:

        - If allow_mask != 0 and the requested mode bit is not present in
          allow_mask, the access is BLOCKED.

    Behaviour under test:
        1. Set ALLOW(obj, "R") for a dict.
        2. Read of the dict should succeed (mode bit R is in allow_mask).
        3. Write to the dict should FAIL (mode bit W is not in allow_mask).
        4. After AW.CLEAR(obj), write should succeed again.
    """
    _section("ALLOW('R') => reads allowed, writes implicitly blocked")

    x = {"k": 0}
    print("[baseline] x =", x)

    # allow_mask = R only; writes should be blocked, reads allowed.
    AW.ALLOW(x, "R")

    print("[expected] read of x OK:", x)

    try:
        x["k"] = 1
        print("[UNEXPECTED] write to x['k'] succeeded")
    except RuntimeError as e:
        print("[expected] RuntimeError on write to x['k']:", e)

    AW.CLEAR(x)
    x["k"] = 2
    print("[after CLEAR] write OK, x =", x)


def test_execution_block() -> None:
    """
    Test ANOTA_EXECUTION.BLOCK(cond) immediate condition checking.

    Behaviour under test:
        1. If cond is truthy: BLOCK returns normally (no exception).
        2. If cond is falsy:  BLOCK raises RuntimeError.
    """
    _section("ANOTA_EXECUTION.BLOCK(cond) immediate check")

    class User:
        def __init__(self, type_: str) -> None:
            self.type = type_

    admin = User("admin")
    non_admin = User("user")

    # Condition true -> no exception.
    AE.BLOCK(non_admin.type != "admin")
    print("[expected] BLOCK(non_admin.type != 'admin') returned normally")

    # Condition false -> RuntimeError.
    try:
        AE.BLOCK(admin.type != "admin")
        print("[UNEXPECTED] BLOCK(admin.type != 'admin') returned normally")
    except RuntimeError as e:
        print("[expected] RuntimeError from BLOCK(admin.type != 'admin'):", e)


def run_all_tests() -> None:
    """
    Run all ANOTA_WATCH / ANOTA_EXECUTION tests in a deterministic order.

    This helper is used by the main block so that the module can be imported
    without immediately executing tests (useful if you later wrap these in
    unittest or pytest).
    """
    test_object_read()
    test_exec_block()
    test_attr_read_write()
    test_dict_subscript()
    test_list_subscript()
    test_allow_only_read()
    test_execution_block()
    print("\nAll ANOTA_WATCH / ANOTA_EXECUTION tests finished.")


if __name__ == "__main__":
    run_all_tests()
