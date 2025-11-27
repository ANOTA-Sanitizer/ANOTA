#ifndef Py_ANOTA_TAINT_H
#define Py_ANOTA_TAINT_H
#ifdef __cplusplus
extern "C" {
#endif

#include "Python.h"
#include "pycore_pystate.h"  /* PyThreadState */

/* Python-level entry:
 *
 *   ANOTA_TAINT(obj, sanitization=[hash], Sink=[print])
 *
 * Implemented as a built-in function that:
 *   - Marks obj as tainted.
 *   - Registers sanitization functions that clear taint from their return
 *     values.
 *   - Registers sink functions that will raise when called with tainted args.
 */
PyAPI_FUNC(PyObject *) _PyAnota_Taint(PyObject *self, PyObject *args, PyObject *kwds);

/* Register taint/sanitizers/sinks from C (used by _PyAnota_Taint). */
PyAPI_FUNC(int) _PyAnotaTaint_Register(PyObject *obj,
                                       PyObject *sanitizers,
                                       PyObject *sinks);

/* Called from ceval.c before invoking a callable via vectorcall:
 *
 *   - tstate: current thread state
 *   - func:   function/callable about to be invoked
 *   - stack:  base pointer to positional + keyword values
 *   - nargs:  number of positional arguments
 *   - nkwargs: number of keyword arguments
 *   - kwnames: keyword names tuple (may be NULL)
 *
 * Returns 0 on success (call allowed), -1 on error/violation (and sets
 * a RuntimeError for taint violations).
 */
PyAPI_FUNC(int) _PyAnotaTaint_CheckVectorcall(
    PyThreadState *tstate,
    PyObject *func,
    PyObject *const *stack,
    Py_ssize_t nargs,
    Py_ssize_t nkwargs,
    PyObject *kwnames);



/* Helper for CALL_FUNCTION_EX-style calls (args tuple + kwargs dict). */
PyAPI_FUNC(int) _PyAnotaTaint_CheckTupleDictCall(
    PyThreadState *tstate,
    PyObject *func,
    PyObject *args_tuple,   /* tuple of positional args, may be empty */
    PyObject *kwargs_dict   /* dict or NULL */
);

/* Propagate taint from source to target.
 * If source is tainted, target becomes tainted.
 */
PyAPI_FUNC(void) _PyAnotaTaint_Propagate(PyObject *source, PyObject *target);

/* Propagate taint from binary operands to result.
 * If left or right is tainted, result becomes tainted.
 */
PyAPI_FUNC(void) _PyAnotaTaint_PropagateBinary(PyObject *left, PyObject *right, PyObject *result);

/* Update PostCall to accept taint_source_found flag */
PyAPI_FUNC(void) _PyAnotaTaint_PostCall(PyObject *func, PyObject *result, int taint_source_found);

#ifdef __cplusplus
}
#endif

#endif /* !Py_ANOTA_TAINT_H */
