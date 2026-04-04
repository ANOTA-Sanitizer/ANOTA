#ifndef Py_ANOTA_TAINT_H
#define Py_ANOTA_TAINT_H
#ifdef __cplusplus
extern "C" {
#endif

#include "Python.h"

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

/* Collect taint sources participating in a call and validate sink rules.
 * Returns a new reference to a tuple of taint ids on success, or NULL on
 * error/violation (with an exception set). */
PyAPI_FUNC(PyObject *) _PyAnotaTaint_CheckVectorcall(
    PyThreadState *tstate,
    PyObject *func,
    PyObject *const *stack,
    Py_ssize_t nargs,
    Py_ssize_t nkwargs,
    PyObject *kwnames);


/* Helper for CALL_FUNCTION_EX-style calls (args tuple + kwargs dict). */
PyAPI_FUNC(PyObject *) _PyAnotaTaint_CheckTupleDictCall(
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

/* Apply post-call taint propagation/sanitization based on the collected
 * taint sources returned by _PyAnotaTaint_Check*(). */
PyAPI_FUNC(void) _PyAnotaTaint_PostCall(PyObject *func, PyObject *result, PyObject *taint_sources);

PyAPI_FUNC(int) _PyAnotaTaint_IsTainted(PyObject *obj);

/* Export Python-object taint into native memory tracked by DFSan. */
PyAPI_FUNC(int) _PyAnotaTaint_ExportBuffer(PyObject *source,
                                           void *buf,
                                           Py_ssize_t size);
PyAPI_FUNC(int) _PyAnotaTaint_ImportBuffer(PyObject *target,
                                           const void *buf,
                                           Py_ssize_t size);

/* Track DFSan-backed native sink violations across a PyCFunction call. */
PyAPI_FUNC(void) _PyAnotaTaint_NativeCallBegin(void);
PyAPI_FUNC(int) _PyAnotaTaint_NativeCallEnd(PyObject *func);
PyAPI_FUNC(int) _PyAnotaTaint_RecordNativeSinkLabel(const char *sink_name,
                                                    int fd,
                                                    unsigned int label);

#ifdef __cplusplus
}
#endif

#endif /* !Py_ANOTA_TAINT_H */
