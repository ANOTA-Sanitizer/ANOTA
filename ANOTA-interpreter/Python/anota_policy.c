#include "Python.h"
#include "anota_policy.h"
#include "anota_watch.h"
#include "anota_taint.h"
#include "anota_syscall.h"

typedef struct {
    PyObject_HEAD
    PyObject *token;
    AnotaPolicyRemove remove;
} PolicyHandle;

void
_PyAnotaPolicy_Invalidate(PyObject *token)
{
    Py_INCREF(Py_False);
    PyList_SetItem(token, 0, Py_False);
}

static PyObject *
handle_clear(PolicyHandle *self, PyObject *unused)
{
    if (PyList_GET_ITEM(self->token, 0) == Py_True) {
        if (self->remove(self->token) < 0) return NULL;
        _PyAnotaPolicy_Invalidate(self->token);
    }
    Py_RETURN_NONE;
}

static PyObject *
handle_enter(PolicyHandle *self, PyObject *unused)
{
    Py_INCREF(self);
    return (PyObject *)self;
}

static PyObject *
handle_exit(PolicyHandle *self, PyObject *args)
{
    if (PyTuple_GET_SIZE(args) != 3) {
        PyErr_SetString(PyExc_TypeError, "__exit__ expects three arguments");
        return NULL;
    }
    return handle_clear(self, NULL);
}

static PyObject *
handle_active(PolicyHandle *self, void *closure)
{
    PyObject *active = PyList_GET_ITEM(self->token, 0);
    Py_INCREF(active);
    return active;
}

static int handle_traverse(PolicyHandle *self, visitproc visit, void *arg)
{
    Py_VISIT(self->token);
    return 0;
}
static int handle_gc_clear(PolicyHandle *self)
{
    Py_CLEAR(self->token);
    return 0;
}
static void handle_dealloc(PolicyHandle *self)
{
    PyObject_GC_UnTrack(self);
    handle_gc_clear(self);
    PyObject_GC_Del(self);
}

static PyMethodDef handle_methods[] = {
    {"clear", (PyCFunction)handle_clear, METH_NOARGS, "Remove this annotation only; idempotent."},
    {"__enter__", (PyCFunction)handle_enter, METH_NOARGS, NULL},
    {"__exit__", (PyCFunction)handle_exit, METH_VARARGS, NULL},
    {NULL, NULL}
};
static PyGetSetDef handle_getset[] = {
    {"active", (getter)handle_active, NULL, "Whether this annotation is installed.", NULL},
    {NULL}
};
static PyTypeObject PolicyHandle_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = "ANOTA_POLICY_HANDLE",
    .tp_basicsize = sizeof(PolicyHandle),
    .tp_dealloc = (destructor)handle_dealloc,
    .tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HAVE_GC,
    .tp_traverse = (traverseproc)handle_traverse,
    .tp_clear = (inquiry)handle_gc_clear,
    .tp_methods = handle_methods,
    .tp_getset = handle_getset,
};

PyObject *
_PyAnotaPolicy_New(PyObject *token, AnotaPolicyRemove remove)
{
    if (PyType_Ready(&PolicyHandle_Type) < 0) return NULL;
    PolicyHandle *self = PyObject_GC_New(PolicyHandle, &PolicyHandle_Type);
    if (self == NULL) return NULL;
    Py_INCREF(token);
    self->token = token;
    self->remove = remove;
    PyObject_GC_Track(self);
    return (PyObject *)self;
}

static int
is_controller(PyObject *obj)
{
    return Py_TYPE(obj) == &PolicyHandle_Type || _PyAnotaWatch_IsController(obj) ||
           _PyAnotaTaint_IsController(obj) || _PyAnotaSyscall_IsController(obj);
}

int
_PyAnotaPolicy_IsControl(PyObject *func)
{
    if (is_controller(func)) return 1;
    if (PyCFunction_Check(func)) {
        PyObject *owner = PyCFunction_GET_SELF(func);
        if (owner && is_controller(owner)) return 1;
        PyCFunction f = PyCFunction_GET_FUNCTION(func);
        if (f == (PyCFunction)_PyAnota_Clear || f == (PyCFunction)(void(*)(void))_PyAnota_Taint) return 1;
    }
    return 0;
}

PyObject *
_PyAnota_Clear(PyObject *self, PyObject *args)
{
    PyObject *handle = NULL;
    if (!PyArg_UnpackTuple(args, "CLEAR", 0, 1, &handle)) return NULL;
    if (handle != NULL) {
        if (!PyObject_TypeCheck(handle, &PolicyHandle_Type)) {
            PyErr_SetString(PyExc_TypeError, "CLEAR expects an ANOTA policy handle");
            return NULL;
        }
        return handle_clear((PolicyHandle *)handle, NULL);
    }
    /* A rejected monitor update leaves the local policy families installed. */
    if (_PyAnotaSyscall_ClearAll() < 0) return NULL;
    _PyAnotaWatch_ClearAll();
    _PyAnotaTaint_ClearAll();
    Py_RETURN_NONE;
}
