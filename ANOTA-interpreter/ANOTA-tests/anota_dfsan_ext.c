#define PY_SSIZE_T_CLEAN
#include "Python.h"
#include "anota_taint.h"

#include <sanitizer/dfsan_interface.h>

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int write_callback_installed = 0;

static void
anota_dfsan_on_write(int fd, const void *buf, size_t count)
{
    dfsan_label label;

    if (buf == NULL || count == 0) {
        return;
    }
    label = dfsan_read_label(buf, count);
    if (label != 0) {
        (void)_PyAnotaTaint_RecordNativeSinkLabel("write", fd, (unsigned int)label);
    }
}

static int
anota_dfsan_enable_callbacks(void)
{
    if (!write_callback_installed) {
        dfsan_set_write_callback(anota_dfsan_on_write);
        write_callback_installed = 1;
    }
    return 0;
}

static void
anota_dfsan_report_printf_arg(const char *text)
{
    dfsan_label label;
    size_t size;

    if (text == NULL) {
        return;
    }

    size = strlen(text);
    if (size == 0) {
        return;
    }

    label = dfsan_read_label(text, size);
    if (label != 0) {
        (void)_PyAnotaTaint_RecordNativeSinkLabel("printf", 1, (unsigned int)label);
    }
}

static int
anota_dfsan_printf(const char *format, ...)
{
    va_list ap;
    int rc;

    if (format != NULL &&
        (strcmp(format, "%s") == 0 || strcmp(format, "%s\n") == 0)) {
        const char *text;

        va_start(ap, format);
        text = va_arg(ap, const char *);
        va_end(ap);
        anota_dfsan_report_printf_arg(text);
    }

    va_start(ap, format);
    rc = vprintf(format, ap);
    va_end(ap);
    return rc;
}

static PyObject *
copy_then_write(PyObject *self, PyObject *arg)
{
    char *source;
    Py_ssize_t size;
    char *copy;

    (void)self;
    if (anota_dfsan_enable_callbacks() < 0) {
        return NULL;
    }
    if (PyBytes_AsStringAndSize(arg, &source, &size) < 0) {
        return NULL;
    }
    if (size <= 0) {
        Py_RETURN_NONE;
    }

    copy = PyMem_Malloc((size_t)size);
    if (copy == NULL) {
        return PyErr_NoMemory();
    }
    memcpy(copy, source, (size_t)size);
    (void)write(1, copy, (size_t)size);
    (void)write(1, "\n", 1);
    PyMem_Free(copy);
    Py_RETURN_NONE;
}

static PyObject *
copy_then_printf(PyObject *self, PyObject *arg)
{
    const char *source;
    Py_ssize_t size;
    char *copy;

    (void)self;
    if (anota_dfsan_enable_callbacks() < 0) {
        return NULL;
    }
    source = PyUnicode_AsUTF8AndSize(arg, &size);
    if (source == NULL) {
        return NULL;
    }

    copy = PyMem_Malloc((size_t)size + 1u);
    if (copy == NULL) {
        return PyErr_NoMemory();
    }
    memcpy(copy, source, (size_t)size);
    copy[size] = '\0';
    (void)anota_dfsan_printf("%s\n", copy);
    PyMem_Free(copy);
    Py_RETURN_NONE;
}

static PyObject *
copy_then_return(PyObject *self, PyObject *arg)
{
    char *source;
    Py_ssize_t size;
    char *copy;
    PyObject *result;

    (void)self;
    if (PyBytes_AsStringAndSize(arg, &source, &size) < 0) {
        return NULL;
    }
    if (size <= 0) {
        return PyBytes_FromStringAndSize("", 0);
    }

    copy = PyMem_Malloc((size_t)size);
    if (copy == NULL) {
        return PyErr_NoMemory();
    }
    memcpy(copy, source, (size_t)size);
    result = PyBytes_FromStringAndSize(copy, size);
    PyMem_Free(copy);
    return result;
}

static PyObject *
return_clean(PyObject *self, PyObject *arg)
{
    (void)self;
    (void)arg;
    return PyBytes_FromString("clean-native-result");
}

static PyObject *
return_second(PyObject *self, PyObject *args)
{
    PyObject *first;
    PyObject *second;

    (void)self;
    if (!PyArg_ParseTuple(args, "OO:return_second", &first, &second)) {
        return NULL;
    }
    Py_INCREF(second);
    return second;
}

static PyMethodDef module_methods[] = {
    {"copy_then_write", (PyCFunction)copy_then_write, METH_O, NULL},
    {"copy_then_printf", (PyCFunction)copy_then_printf, METH_O, NULL},
    {"copy_then_return", (PyCFunction)copy_then_return, METH_O, NULL},
    {"return_clean", (PyCFunction)return_clean, METH_O, NULL},
    {"return_second", (PyCFunction)return_second, METH_VARARGS, NULL},
    {NULL, NULL}
};

static struct PyModuleDef module_def = {
    PyModuleDef_HEAD_INIT,
    "anota_dfsan_ext",
    NULL,
    -1,
    module_methods,
};

PyMODINIT_FUNC
PyInit_anota_dfsan_ext(void)
{
    if (anota_dfsan_enable_callbacks() < 0) {
        return NULL;
    }
    return PyModule_Create(&module_def);
}
