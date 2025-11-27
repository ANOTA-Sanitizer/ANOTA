#ifndef Py_ANOTA_WATCH_H
#define Py_ANOTA_WATCH_H
#ifdef __cplusplus
extern "C" {
#endif

#include "Python.h"

/* Public-ish helper used by ceval and builtins to access the singleton
   ANOTA_WATCH object that exposes the Python API:
       ANOTA_WATCH.ALLOW(obj, modes, key=None)
       ANOTA_WATCH.BLOCK(obj, modes, key=None)
       ANOTA_WATCH.CLEAR(obj, key=None)
       ANOTA_WATCH.CLEAR_ALL()
*/
PyAPI_FUNC(PyObject *) _PyAnotaWatch_GetSingleton(void);

/* Internal helpers used from the bytecode evaluator (ceval.c).
   They return 0 on success (access allowed), and -1 on policy
   violation or other error (and set an exception and print a
   diagnostic message). */

PyAPI_FUNC(int) _PyAnota_CheckReadObject(PyThreadState *tstate, PyObject *obj);
PyAPI_FUNC(int) _PyAnota_CheckWriteObject(PyThreadState *tstate, PyObject *obj);
PyAPI_FUNC(int) _PyAnota_CheckExecObject(PyThreadState *tstate, PyObject *obj);

PyAPI_FUNC(int) _PyAnota_CheckReadMember(PyThreadState *tstate,
                                         PyObject *container,
                                         PyObject *key);
PyAPI_FUNC(int) _PyAnota_CheckWriteMember(PyThreadState *tstate,
                                          PyObject *container,
                                          PyObject *key);

#ifdef __cplusplus
}
#endif

#endif /* !Py_ANOTA_WATCH_H */
