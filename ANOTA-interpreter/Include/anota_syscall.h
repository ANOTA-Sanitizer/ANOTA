#ifndef Py_ANOTA_SYSCALL_H
#define Py_ANOTA_SYSCALL_H
#ifdef __cplusplus
extern "C" {
#endif

#include "Python.h"

/* Public-ish helper used by bltinmodule.c to expose the singleton
   ANOTA_SYSCALL policy controller. */
PyAPI_FUNC(PyObject *) _PyAnotaSyscall_GetSingleton(void);

/* Internal helper used by various I/O and os.* wrappers to enforce the
   syscall policy engine. Returns 0 on success, -1 on policy violation
   or error (with an exception set and a diagnostic printed to stderr). */
/* Returns:
 *   0 -> allowed / no violation
 *   1 -> violation logged but execution should continue
 *  -1 -> internal error (exception set)
 */
PyAPI_FUNC(int) _PyAnotaSyscall_Check(const char *syscall_name,
                                      PyObject *target,
                                      const char *operation,
                                      const char *target_kind);

PyAPI_FUNC(PyObject *) _PyAnotaSyscall_SignalStart(PyObject *self,
                                                   PyObject *args,
                                                   PyObject *kwds);
PyAPI_FUNC(PyObject *) _PyAnotaSyscall_SignalStop(PyObject *self,
                                                  PyObject *args);

#ifdef __cplusplus
}
#endif

#endif /* !Py_ANOTA_SYSCALL_H */
