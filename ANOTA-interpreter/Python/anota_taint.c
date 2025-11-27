#include "Python.h"
#include "anota_taint.h"
#include "pycore_pystate.h"  /* PyThreadState */

/* Very simple taint-tracking engine.
 *
 * Model:
 *   - A global mapping of tainted objects:
 *         taint_objects: { obj -> True }
 *   - A global mapping of sanitizer functions:
 *         sanitizers: { func -> True }
 *   - A global mapping of sink functions:
 *         sinks: { func -> True }
 *
 * APIs:
 *   - ANOTA_TAINT(obj, sanitization=[hash], Sink=[print])
 *       * Marks 'obj' as tainted.
 *       * Registers sanitizer functions and sink functions.
 *
 *   - _PyAnotaTaint_CheckVectorcall(...) and _PyAnotaTaint_CheckTupleDictCall(...)
 *       * Called from ceval.c before calling 'func'.
 *       * If 'func' is a registered sink and any arg is tainted, raise.
 *
 *   - _PyAnotaTaint_PostCall(func, result)
 *       * Called from ceval.c after a successful call.
 *       * If 'func' is a registered sanitizer, clear taint on 'result'.
 *
 * Notes / limitations:
 *   - Taint is tracked per-object and only for objects that are hashable,
 *     since we store them as dictionary keys. Attempting to taint an
 *     unhashable object currently raises a TypeError.
 *   - We do not automatically propagate taint to derived values: only
 *     values explicitly passed to ANOTA_TAINT() are tracked as tainted.
 *   - Sanitizers clear taint on their return value only.
 */

static PyObject *taint_objects = NULL;    /* { obj -> True } */
static PyObject *taint_sanitizers = NULL; /* { func -> True } */
static PyObject *taint_sinks = NULL;      /* { func -> True } */

/* --- internal helpers -------------------------------------------------- */

static int
ensure_state(void)
{
    if (taint_objects == NULL) {
        taint_objects = PyDict_New();
        if (taint_objects == NULL) {
            return -1;
        }
    }
    if (taint_sanitizers == NULL) {
        taint_sanitizers = PyDict_New();
        if (taint_sanitizers == NULL) {
            return -1;
        }
    }
    if (taint_sinks == NULL) {
        taint_sinks = PyDict_New();
        if (taint_sinks == NULL) {
            return -1;
        }
    }
    return 0;
}

/* Return 1 if obj is tainted, 0 if not, -1 on error. */
static int
is_tainted(PyObject *obj)
{
    if (taint_objects == NULL) {
        return 0;
    }
    int contains = PyDict_Contains(taint_objects, obj);
    if (contains < 0) {
        if (PyErr_ExceptionMatches(PyExc_TypeError)) {
            PyErr_Clear();
            return 0;
        }
        return -1;
    }
    return contains;
}

/* Mark obj as tainted. Returns 0 on success, -1 on error. */
static int
mark_tainted(PyObject *obj)
{
    if (ensure_state() < 0) {
        return -1;
    }

    int res = PyDict_SetItem(taint_objects, obj, Py_True);
    if (res < 0) {
        /* Most likely: unhashable object. Give a clearer error. */
        if (PyErr_ExceptionMatches(PyExc_TypeError)) {
            PyErr_Clear();
            PyErr_SetString(PyExc_TypeError,
                            "ANOTA_TAINT only supports hashable objects "
                            "as taint sources");
        }
        return -1;
    }
    return 0;
}

/* Register all callable items in 'seq' into the given dict. */
static int
register_funcs_from_seq(PyObject *seq, PyObject *target_dict,
                        const char *role)
{
    if (seq == NULL || Py_IsNone(seq)) {
        return 0;
    }

    PyObject *fast = PySequence_Fast(seq,
        role && *role ? "ANOTA_TAINT: expected a sequence for argument" : "ANOTA_TAINT: bad sequence");
    if (fast == NULL) {
        return -1;
    }

    Py_ssize_t n = PySequence_Fast_GET_SIZE(fast);
    PyObject **items = PySequence_Fast_ITEMS(fast);
    for (Py_ssize_t i = 0; i < n; i++) {
        PyObject *f = items[i];
        if (!PyCallable_Check(f)) {
            Py_DECREF(fast);
            PyErr_Format(PyExc_TypeError,
                         "ANOTA_TAINT: %s entry at index %zd is not callable",
                         role ? role : "list", i);
            return -1;
        }
        if (PyDict_SetItem(target_dict, f, Py_True) < 0) {
            Py_DECREF(fast);
            return -1;
        }
    }

    Py_DECREF(fast);
    return 0;
}

/* --- public registration helpers -------------------------------------- */

int
_PyAnotaTaint_Register(PyObject *obj, PyObject *sanitizers, PyObject *sinks)
{
    if (ensure_state() < 0) {
        return -1;
    }

    if (mark_tainted(obj) < 0) {
        return -1;
    }

    if (sanitizers && !Py_IsNone(sanitizers)) {
        if (register_funcs_from_seq(sanitizers, taint_sanitizers,
                                    "sanitization") < 0) {
            return -1;
        }
    }

    if (sinks && !Py_IsNone(sinks)) {
        if (register_funcs_from_seq(sinks, taint_sinks,
                                    "Sink") < 0) {
            return -1;
        }
    }

    return 0;
}

/* --- Python-level ANOTA_TAINT builtin --------------------------------- */

PyObject *
_PyAnota_Taint(PyObject *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"obj", "sanitization", "Sink", NULL};
    PyObject *obj;
    PyObject *sanitization = Py_None;
    PyObject *sink = Py_None;

    if (!PyArg_ParseTupleAndKeywords(
            args, kwds, "O|OO:ANOTA_TAINT", kwlist,
            &obj, &sanitization, &sink)) {
        return NULL;
    }

    if (_PyAnotaTaint_Register(obj, sanitization, sink) < 0) {
        return NULL;
    }

    Py_RETURN_NONE;
}

/* --- sink checks for various call paths ------------------------------- */

/* --- sink checks for various call paths ------------------------------- */

static int
is_sink(PyObject *func)
{
    if (taint_sinks == NULL) {
        return 0;
    }
    int contains = PyDict_Contains(taint_sinks, func);
    if (contains < 0) {
        return -1;
    }
    return contains;
}

/* Returns 1 if any arg is tainted, 0 if none, -1 on error.
 * If func is a sink and arg is tainted, raises error and returns -1.
 */
static int
check_args_for_taint(PyObject *func, PyObject *const *stack,
                     Py_ssize_t total_args, int is_sink_func)
{
    if (taint_objects == NULL) {
        return 0;
    }

    int found_taint = 0;
    for (Py_ssize_t i = 0; i < total_args; i++) {
        PyObject *arg = stack[i];
        int ta = is_tainted(arg);
        if (ta < 0) {
            return -1;
        }
        if (ta) {
            if (is_sink_func) {
                PySys_FormatStderr(
                    "ANOTA_TAINT violation: tainted object %R passed to sink %R\n",
                    arg, func);
                PyErr_SetString(PyExc_RuntimeError,
                                "ANOTA_TAINT sink violation");
                return -1;
            }
            found_taint = 1;
        }
    }
    return found_taint;
}

static int
check_tuple_for_taint(PyObject *func, PyObject *tuple, int is_sink_func)
{
    if (taint_objects == NULL || tuple == NULL) {
        return 0;
    }

    int found_taint = 0;
    Py_ssize_t n = PyTuple_GET_SIZE(tuple);
    for (Py_ssize_t i = 0; i < n; i++) {
        PyObject *arg = PyTuple_GET_ITEM(tuple, i);
        int ta = is_tainted(arg);
        if (ta < 0) {
            return -1;
        }
        if (ta) {
            if (is_sink_func) {
                PySys_FormatStderr(
                    "ANOTA_TAINT violation: tainted object %R passed to sink %R\n",
                    arg, func);
                PyErr_SetString(PyExc_RuntimeError,
                                "ANOTA_TAINT sink violation");
                return -1;
            }
            found_taint = 1;
        }
    }
    return found_taint;
}

static int
check_dict_values_for_taint(PyObject *func, PyObject *dict, int is_sink_func)
{
    if (taint_objects == NULL || dict == NULL) {
        return 0;
    }

    PyObject *key, *value;
    Py_ssize_t pos = 0;
    int found_taint = 0;

    while (PyDict_Next(dict, &pos, &key, &value)) {
        int ta = is_tainted(value);
        if (ta < 0) {
            return -1;
        }
        if (ta) {
            if (is_sink_func) {
                PySys_FormatStderr(
                    "ANOTA_TAINT violation: tainted object %R passed to sink %R "
                    "via keyword argument %R\n",
                    value, func, key);
                PyErr_SetString(PyExc_RuntimeError,
                                "ANOTA_TAINT sink violation");
                return -1;
            }
            found_taint = 1;
        }
    }
    return found_taint;
}

/* Called from ceval.c for the vectorcall fast-path (CALL_FUNCTION, etc.) */
int
_PyAnotaTaint_CheckVectorcall(PyThreadState *tstate,
                              PyObject *func,
                              PyObject *const *stack,
                              Py_ssize_t nargs,
                              Py_ssize_t nkwargs,
                              PyObject *kwnames)
{
    (void)tstate;  /* currently unused */

    if (taint_objects == NULL) {
        return 0;
    }

    int sink = is_sink(func);
    if (sink < 0) {
        return -1;
    }

    /* Layout: first nargs positional args, followed by nkwargs keyword values. */
    Py_ssize_t total = nargs + nkwargs;
    return check_args_for_taint(func, stack, total, sink);
}

/* Called from ceval.c for CALL_FUNCTION_EX-style calls. */
int
_PyAnotaTaint_CheckTupleDictCall(PyThreadState *tstate,
                                 PyObject *func,
                                 PyObject *args_tuple,
                                 PyObject *kwargs_dict)
{
    (void)tstate;  /* currently unused */

    if (taint_objects == NULL) {
        return 0;
    }

    int sink = is_sink(func);
    if (sink < 0) {
        return -1;
    }

    int t1 = check_tuple_for_taint(func, args_tuple, sink);
    if (t1 < 0) return -1;

    int t2 = check_dict_values_for_taint(func, kwargs_dict, sink);
    if (t2 < 0) return -1;

    return (t1 || t2);
}

/* --- post-call sanitizer handling ------------------------------------- */

static int
is_sanitizer(PyObject *func)
{
    if (taint_sanitizers == NULL) {
        return 0;
    }
    int contains = PyDict_Contains(taint_sanitizers, func);
    if (contains < 0) {
        return -1;
    }
    return contains;
}

/* Called from ceval.c when a call returns successfully. */
void
_PyAnotaTaint_PostCall(PyObject *func, PyObject *result, int taint_source_found)
{
    if (result == NULL || taint_objects == NULL) {
        return;
    }

    int sani = is_sanitizer(func);
    if (sani < 0) {
        /* Error checking sanitizer status, just return to avoid crash */
        PyErr_Clear();
        return;
    }

    if (sani) {
        /* Sanitizer: remove taint from result if present */
        if (PyDict_DelItem(taint_objects, result) < 0) {
            if (PyErr_ExceptionMatches(PyExc_KeyError) ||
                PyErr_ExceptionMatches(PyExc_TypeError)) {
                PyErr_Clear();
            }
            else {
                PyErr_Clear();
            }
        }
    }
    else if (taint_source_found) {
        /* Not a sanitizer, but arguments were tainted: propagate to result */
        if (mark_tainted(result) == 0) {
             PySys_FormatStderr("ANOTA_TAINT propagation: call to %R returned %R (tainted)\n", func, result);
        }
    }
}

/* --- propagation helpers ---------------------------------------------- */

void
_PyAnotaTaint_Propagate(PyObject *source, PyObject *target)
{
    if (taint_objects == NULL || source == NULL || target == NULL) {
        return;
    }
    int ta = is_tainted(source);
    if (ta > 0) {
        if (mark_tainted(target) == 0) {
            PySys_FormatStderr("ANOTA_TAINT propagation: %R -> %R\n", source, target);
        }
    }
}

void
_PyAnotaTaint_PropagateBinary(PyObject *left, PyObject *right, PyObject *result)
{
    if (taint_objects == NULL || result == NULL) {
        return;
    }
    int t1 = (left != NULL) ? is_tainted(left) : 0;
    int t2 = (right != NULL) ? is_tainted(right) : 0;

    if (t1 > 0 || t2 > 0) {
        if (mark_tainted(result) == 0) {
            PySys_FormatStderr("ANOTA_TAINT propagation: %R, %R -> %R\n",
                               left ? left : Py_None,
                               right ? right : Py_None,
                               result);
        }
    }
}
