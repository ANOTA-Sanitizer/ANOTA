#ifndef Py_ANOTA_EXECUTION_H
#define Py_ANOTA_EXECUTION_H
#ifdef __cplusplus
extern "C" {
#endif

#include "Python.h"

/* Public helper used by builtins to access the singleton
   ANOTA_EXECUTION object that exposes the Python API:

       ANOTA_EXECUTION.BLOCK(cond, msg=None)

   Semantics:
       - cond is any Python object; it is interpreted via PyObject_IsTrue().
       - If cond is truthy, BLOCK() returns None.
       - If cond is falsy, BLOCK() raises a RuntimeError (or a provided msg). */
PyAPI_FUNC(PyObject *) _PyAnotaExecution_GetSingleton(void);

#ifdef __cplusplus
}
#endif

#endif /* !Py_ANOTA_EXECUTION_H */
