#include "Python.h"

static PyObject *
read_first_byte(PyObject *self, PyObject *arg)
{
    unsigned char *buf;

    (void)self;
    if (!PyByteArray_Check(arg)) {
        PyErr_SetString(PyExc_TypeError, "expected bytearray");
        return NULL;
    }
    if (PyByteArray_GET_SIZE(arg) <= 0) {
        PyErr_SetString(PyExc_ValueError, "bytearray must not be empty");
        return NULL;
    }
    buf = (unsigned char *)PyByteArray_AS_STRING(arg);
    return PyLong_FromUnsignedLong((unsigned long)buf[0]);
}

static PyObject *
write_first_byte(PyObject *self, PyObject *args)
{
    PyObject *obj;
    unsigned int value;
    unsigned char *buf;

    (void)self;
    if (!PyArg_ParseTuple(args, "OI:write_first_byte", &obj, &value)) {
        return NULL;
    }
    if (!PyByteArray_Check(obj)) {
        PyErr_SetString(PyExc_TypeError, "expected bytearray");
        return NULL;
    }
    if (PyByteArray_GET_SIZE(obj) <= 0) {
        PyErr_SetString(PyExc_ValueError, "bytearray must not be empty");
        return NULL;
    }
    buf = (unsigned char *)PyByteArray_AS_STRING(obj);
    buf[0] = (unsigned char)(value & 0xFFu);
    Py_RETURN_NONE;
}

static PyMethodDef module_methods[] = {
    {"read_first_byte", (PyCFunction)read_first_byte, METH_O, NULL},
    {"write_first_byte", (PyCFunction)write_first_byte, METH_VARARGS, NULL},
    {NULL, NULL}
};

static struct PyModuleDef module_def = {
    PyModuleDef_HEAD_INIT,
    "anota_cext_watch_ext",
    NULL,
    -1,
    module_methods,
};

PyMODINIT_FUNC
PyInit_anota_cext_watch_ext(void)
{
    return PyModule_Create(&module_def);
}
