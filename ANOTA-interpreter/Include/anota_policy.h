#ifndef Py_ANOTA_POLICY_H
#define Py_ANOTA_POLICY_H
#include "Python.h"
#ifdef __cplusplus
extern "C" {
#endif

/* Tokens are private lists with an active flag at index zero. Policies remain
 * installed when a handle is discarded; removal is explicit or via `with`. */
typedef int (*AnotaPolicyRemove)(PyObject *token);
PyAPI_FUNC(PyObject *) _PyAnotaPolicy_New(PyObject *token, AnotaPolicyRemove remove);
PyAPI_FUNC(void) _PyAnotaPolicy_Invalidate(PyObject *token);
PyAPI_FUNC(int) _PyAnotaPolicy_IsControl(PyObject *callable);
PyAPI_FUNC(PyObject *) _PyAnota_Clear(PyObject *self, PyObject *args);
#ifdef __cplusplus
}
#endif
#endif
