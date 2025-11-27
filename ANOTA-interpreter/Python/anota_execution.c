#include "Python.h"
#include "anota_execution.h"

/* Simple immediate condition checker used by ANOTA_EXECUTION.BLOCK.
 *
 * Python API:
 *
 *   ANOTA_EXECUTION.BLOCK(cond, msg=None)
 *
 * Semantics:
 *   - cond is any Python object; it is interpreted via PyObject_IsTrue().
 *   - If cond is truthy, BLOCK() returns None.
 *   - If cond is falsy, BLOCK() raises a RuntimeError (or a provided msg).
 */

typedef struct {
    PyObject_HEAD
} AnotaExecutionObject;

static PyTypeObject AnotaExecution_Type;
static PyObject *anota_exec_singleton = NULL;


/* --- ANOTA_EXECUTION.BLOCK implementation ------------------------------ */

static PyObject *
anota_exec_block(AnotaExecutionObject *self, PyObject *args, PyObject *kwargs)
{
    static char *kwlist[] = {"cond", "msg", NULL};
    PyObject *cond;
    PyObject *msg = NULL;

    if (!PyArg_ParseTupleAndKeywords(args, kwargs,
                                     "O|O:BLOCK", kwlist,
                                     &cond, &msg)) {
        return NULL;
    }

    int truth = PyObject_IsTrue(cond);
    if (truth < 0) {
        /* Propagate error from PyObject_IsTrue (e.g. __bool__ raised). */
        return NULL;
    }

    if (truth) {
        Py_RETURN_NONE;
    }

    /* Condition is false: raise. Use custom msg if provided. */
    if (msg && !Py_IsNone(msg)) {
        PyErr_SetObject(PyExc_RuntimeError, msg);
    }
    else {
        PyErr_SetString(PyExc_RuntimeError,
                        "ANOTA_EXECUTION.BLOCK condition failed");
    }
    return NULL;
}

static PyMethodDef anota_exec_methods[] = {
    {"BLOCK", (PyCFunction)anota_exec_block, METH_VARARGS | METH_KEYWORDS,
     PyDoc_STR("BLOCK(cond, msg=None)\n"
               "Raise RuntimeError if cond is falsey; return None otherwise.\n"
               "\n"
               "Example:\n"
               "    ANOTA_EXECUTION.BLOCK(user.type != 'admin')\n")},
    {NULL, NULL}
};

static PyTypeObject AnotaExecution_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "ANOTA_EXECUTION",                  /* tp_name */
    sizeof(AnotaExecutionObject),       /* tp_basicsize */
    0,                                  /* tp_itemsize */
    (destructor)PyObject_Del,           /* tp_dealloc */
    0,                                  /* tp_vectorcall_offset */
    0,                                  /* tp_getattr */
    0,                                  /* tp_setattr */
    0,                                  /* tp_as_async */
    0,                                  /* tp_repr */
    0,                                  /* tp_as_number */
    0,                                  /* tp_as_sequence */
    0,                                  /* tp_as_mapping */
    0,                                  /* tp_hash */
    0,                                  /* tp_call */
    0,                                  /* tp_str */
    PyObject_GenericGetAttr,            /* tp_getattro */
    0,                                  /* tp_setattro */
    0,                                  /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT,                 /* tp_flags */
    "ANOTA_EXECUTION condition checker",/* tp_doc   */
    0,                                  /* tp_traverse */
    0,                                  /* tp_clear */
    0,                                  /* tp_richcompare */
    0,                                  /* tp_weaklistoffset */
    0,                                  /* tp_iter  */
    0,                                  /* tp_iternext */
    anota_exec_methods,                 /* tp_methods */
    0,                                  /* tp_members */
    0,                                  /* tp_getset */
    0,                                  /* tp_base  */
    0,                                  /* tp_dict  */
    0,                                  /* tp_descr_get */
    0,                                  /* tp_descr_set */
    0,                                  /* tp_dictoffset */
    0,                                  /* tp_init  */
    PyType_GenericAlloc,                /* tp_alloc */
    PyType_GenericNew,                  /* tp_new   */
};


/* Public entry: get or create the singleton object. */

PyObject *
_PyAnotaExecution_GetSingleton(void)
{
    if (anota_exec_singleton != NULL) {
        Py_INCREF(anota_exec_singleton);
        return anota_exec_singleton;
    }

    if (PyType_Ready(&AnotaExecution_Type) < 0) {
        return NULL;
    }

    AnotaExecutionObject *self =
        PyObject_New(AnotaExecutionObject, &AnotaExecution_Type);
    if (self == NULL) {
        return NULL;
    }

    anota_exec_singleton = (PyObject *)self;
    Py_INCREF(anota_exec_singleton);
    return anota_exec_singleton;
}
