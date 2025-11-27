#include "Python.h"
#include "anota_watch.h"
#include "pycore_pystate.h"   // _PyThreadState_GET()
#include "pycore_pyerrors.h"  // _PyErr_SetString

/* Simple object access policy engine used by ANOTA_WATCH and ceval.c.
 *
 * Policy model:
 *   - Policies are stored in a dict on the singleton ANOTA_WATCH object.
 *   - Key: (obj, key)
 *       * key is None   -> policy for the whole object
 *       * key is not None -> policy for a specific attribute/element
 *         (e.g. attribute name, list index, dict key, ...)
 *   - Value: a single PyLong encoding:
 *         high byte: allow_mask (bits for R/W/X)
 *         low  byte: block_mask (bits for R/W/X)
 *
 *   Modes:
 *       R -> 0x01
 *       W -> 0x02
 *       X -> 0x04
 *
 *   Semantics for a given (allow_mask, block_mask) and mode bit m:
 *
 *       if (block_mask & m):                 BLOCK
 *       else if (allow_mask != 0 && !(allow_mask & m)):
 *                                            BLOCK
 *       else if (allow_mask & m):            ALLOW
 *       else                                (allow_mask == 0 and not blocked)
 *                                            ALLOW (no policy -> default allow)
 *
 *   Object-level vs member-level:
 *       - For member operations (attributes, subscripts), we check:
 *           1) (obj, key)   specific rule, then
 *           2) (obj, None)  general rule for the object
 *         The first rule that causes a BLOCK blocks the access.
 *       - For plain object operations (variable read/write, call),
 *         we only check (obj, None).
 */

#define ANOTA_MODE_R 0x01
#define ANOTA_MODE_W 0x02
#define ANOTA_MODE_X 0x04

typedef struct {
    PyObject_HEAD
    PyObject *policies;  /* dict: (obj, key) -> PyLong( (allow<<8)|block ) */
} AnotaWatchObject;

static PyTypeObject AnotaWatch_Type;
static PyObject *anota_singleton = NULL;


/* --- helpers ---------------------------------------------------------- */

static inline AnotaWatchObject *
get_singleton_struct(void)
{
    return (AnotaWatchObject *)anota_singleton;
}

/* Build internal key (id(obj), key_or_None) so that obj itself need not be hashable. */
static PyObject *
make_policy_key(PyObject *obj, PyObject *key)
{
    PyObject *id_obj = PyLong_FromVoidPtr(obj);
    PyObject *tkey;

    if (id_obj == NULL) {
        return NULL;
    }
    if (key == NULL) {
        key = Py_None;
    }
    tkey = PyTuple_Pack(2, id_obj, key);
    Py_DECREF(id_obj);
    return tkey;
}

/* Parse "R", "W", "X" combination into bitmask. */
static int
parse_modes(PyObject *modes, unsigned char *out_bits)
{
    const char *s;
    Py_ssize_t len, i;
    unsigned char bits = 0;

    if (!PyUnicode_Check(modes)) {
        PyErr_SetString(PyExc_TypeError, "modes must be a string like 'R', 'RW', or 'RWX'");
        return -1;
    }
    s = PyUnicode_AsUTF8AndSize(modes, &len);
    if (s == NULL) {
        return -1;
    }
    for (i = 0; i < len; i++) {
        switch (s[i]) {
        case 'R':
            bits |= ANOTA_MODE_R;
            break;
        case 'W':
            bits |= ANOTA_MODE_W;
            break;
        case 'X':
            bits |= ANOTA_MODE_X;
            break;
        default:
            PyErr_Format(PyExc_ValueError,
                         "unknown mode character %c (expected 'R', 'W' or 'X')",
                         s[i]);
            return -1;
        }
    }
    if (bits == 0) {
        PyErr_SetString(PyExc_ValueError, "empty modes string");
        return -1;
    }
    *out_bits = bits;
    return 0;
}

/* Update or create entry for (obj, key).
   is_allow != 0 -> set bits in allow_mask
   is_allow == 0 -> set bits in block_mask */
static int
update_entry(PyObject *policies,
             PyObject *obj, PyObject *key,
             unsigned char bits, int is_allow)
{
    PyObject *tkey = NULL;
    PyObject *entry = NULL;
    PyObject *new_entry = NULL;
    unsigned long value = 0;
    unsigned char allow = 0;
    unsigned char block = 0;

    tkey = make_policy_key(obj, key);
    if (tkey == NULL) {
        return -1;
    }

    entry = PyDict_GetItemWithError(policies, tkey);  /* borrowed */
    if (entry != NULL) {
        value = PyLong_AsUnsignedLongMask(entry);
        allow = (unsigned char)((value >> 8) & 0xFFu);
        block = (unsigned char)(value & 0xFFu);
    }
    else if (PyErr_Occurred()) {
        Py_DECREF(tkey);
        return -1;
    }

    if (is_allow) {
        allow |= bits;
    }
    else {
        block |= bits;
    }

    value = ((unsigned long)allow << 8) | (unsigned long)block;
    new_entry = PyLong_FromUnsignedLong(value);
    if (new_entry == NULL) {
        Py_DECREF(tkey);
        return -1;
    }

    if (PyDict_SetItem(policies, tkey, new_entry) < 0) {
        Py_DECREF(tkey);
        Py_DECREF(new_entry);
        return -1;
    }

    Py_DECREF(tkey);
    Py_DECREF(new_entry);
    return 0;
}

/* Decide access for a single (obj, key) entry.
   Return:
     -1 -> BLOCK
      0 -> no decision / default allow
      1 -> explicit ALLOW
     -2 -> error
*/
static int
decide_for_entry(PyObject *policies,
                 PyObject *obj, PyObject *key,
                 unsigned char mode_bit)
{
    PyObject *tkey, *entry;
    unsigned long value;
    unsigned char allow, block;

    if (policies == NULL) {
        return 0;
    }

    tkey = make_policy_key(obj, key);
    if (tkey == NULL) {
        return -2;
    }

    entry = PyDict_GetItemWithError(policies, tkey);  /* borrowed */
    Py_DECREF(tkey);
    if (entry == NULL) {
        if (PyErr_Occurred()) {
            return -2;
        }
        return 0;  /* no rule */
    }

    value = PyLong_AsUnsignedLongMask(entry);
    allow = (unsigned char)((value >> 8) & 0xFFu);
    block = (unsigned char)(value & 0xFFu);

    if (block & mode_bit) {
        return -1;
    }
    if (allow != 0 && !(allow & mode_bit)) {
        return -1;
    }
    if (allow & mode_bit) {
        return 1;
    }
    return 0;
}

/* Common implementation for all access checks. */
static int
_anota_check_access(PyThreadState *tstate,
                    PyObject *obj, PyObject *key,
                    unsigned char mode_bit,
                    const char *mode_str,
                    const char *kind_str)
{
    AnotaWatchObject *aw;
    PyObject *policies;
    int r;

    if (anota_singleton == NULL) {
        return 0;  /* fast path: no policies installed */
    }

    aw = get_singleton_struct();
    if (aw == NULL || aw->policies == NULL) {
        return 0;
    }
    policies = aw->policies;

    /* Fast path: no policies configured yet -> no checks, no hashing of obj. */
    if (PyDict_CheckExact(policies) && PyDict_GET_SIZE(policies) == 0) {
        return 0;
    }

    /* First: specific (obj, key) rule, if any. */
    if (key != NULL) {
        r = decide_for_entry(policies, obj, key, mode_bit);
        if (r == -2) {
            return -1;
        }
        if (r == -1) {
            /* blocked */
            PySys_FormatStderr(
                "ANOTA_WATCH violation: blocked %s %s access "
                "on object %R with key %R\n",
                kind_str, mode_str, obj, key);
            _PyErr_SetString(tstate, PyExc_RuntimeError,
                             "ANOTA_WATCH policy violation");
            return -1;
        }
        if (r == 1) {
            return 0;  /* explicitly allowed */
        }
    }

    /* Second: generic object-level rule (obj, None). */
    r = decide_for_entry(policies, obj, NULL, mode_bit);
    if (r == -2) {
        return -1;
    }
    if (r == -1) {
        PySys_FormatStderr(
            "ANOTA_WATCH violation: blocked %s %s access on object %R\n",
            kind_str, mode_str, obj);
        _PyErr_SetString(tstate, PyExc_RuntimeError,
                         "ANOTA_WATCH policy violation");
        return -1;
    }

    /* r == 0 or r == 1 (explicit allow) is both fine:
       default is to allow if nothing blocks this operation. */
    return 0;
}


/* --- public C helpers used from ceval.c ------------------------------- */

int
_PyAnota_CheckReadObject(PyThreadState *tstate, PyObject *obj)
{
    return _anota_check_access(tstate, obj, NULL, ANOTA_MODE_R,
                               "R", "object");
}

int
_PyAnota_CheckWriteObject(PyThreadState *tstate, PyObject *obj)
{
    return _anota_check_access(tstate, obj, NULL, ANOTA_MODE_W,
                               "W", "object");
}

int
_PyAnota_CheckExecObject(PyThreadState *tstate, PyObject *obj)
{
    return _anota_check_access(tstate, obj, NULL, ANOTA_MODE_X,
                               "X", "object");
}

int
_PyAnota_CheckReadMember(PyThreadState *tstate,
                         PyObject *container, PyObject *key)
{
    return _anota_check_access(tstate, container, key, ANOTA_MODE_R,
                               "R", "member");
}

int
_PyAnota_CheckWriteMember(PyThreadState *tstate,
                          PyObject *container, PyObject *key)
{
    return _anota_check_access(tstate, container, key, ANOTA_MODE_W,
                               "W", "member");
}


/* --- ANOTA_WATCH Python object ---------------------------------------- */

static PyObject *
anota_allow(AnotaWatchObject *self, PyObject *args, PyObject *kwargs)
{
    static char *kwlist[] = {"obj", "modes", "key", NULL};
    PyObject *obj;
    PyObject *modes;
    PyObject *key = Py_None;
    unsigned char bits;

    if (!PyArg_ParseTupleAndKeywords(args, kwargs,
                                     "OO|O:ALLOW", kwlist,
                                     &obj, &modes, &key)) {
        return NULL;
    }
    if (parse_modes(modes, &bits) < 0) {
        return NULL;
    }
    if (self->policies == NULL) {
        self->policies = PyDict_New();
        if (self->policies == NULL) {
            return NULL;
        }
    }
    if (update_entry(self->policies, obj, key, bits, 1) < 0) {
        return NULL;
    }
    Py_RETURN_NONE;
}

static PyObject *
anota_block(AnotaWatchObject *self, PyObject *args, PyObject *kwargs)
{
    static char *kwlist[] = {"obj", "modes", "key", NULL};
    PyObject *obj;
    PyObject *modes;
    PyObject *key = Py_None;
    unsigned char bits;

    if (!PyArg_ParseTupleAndKeywords(args, kwargs,
                                     "OO|O:BLOCK", kwlist,
                                     &obj, &modes, &key)) {
        return NULL;
    }
    if (parse_modes(modes, &bits) < 0) {
        return NULL;
    }
    if (self->policies == NULL) {
        self->policies = PyDict_New();
        if (self->policies == NULL) {
            return NULL;
        }
    }
    if (update_entry(self->policies, obj, key, bits, 0) < 0) {
        return NULL;
    }
    Py_RETURN_NONE;
}

static PyObject *
anota_clear(AnotaWatchObject *self, PyObject *args, PyObject *kwargs)
{
    static char *kwlist[] = {"obj", "key", NULL};
    PyObject *obj;
    PyObject *key = Py_None;
    PyObject *tkey;

    if (!PyArg_ParseTupleAndKeywords(args, kwargs,
                                     "O|O:CLEAR", kwlist,
                                     &obj, &key)) {
        return NULL;
    }
    if (self->policies == NULL) {
        Py_RETURN_NONE;
    }
    tkey = make_policy_key(obj,
                           key == NULL ? (PyObject *)Py_None : key);
    if (tkey == NULL) {
        return NULL;
    }
    if (PyDict_DelItem(self->policies, tkey) < 0) {
        /* Ignore missing keys */
        if (PyErr_ExceptionMatches(PyExc_KeyError)) {
            PyErr_Clear();
        }
    }
    Py_DECREF(tkey);
    Py_RETURN_NONE;
}

static PyObject *
anota_clear_all(AnotaWatchObject *self, PyObject *Py_UNUSED(ignored))
{
    if (self->policies != NULL) {
        PyDict_Clear(self->policies);
    }
    Py_RETURN_NONE;
}

static void
anota_dealloc(AnotaWatchObject *self)
{
    Py_XDECREF(self->policies);
    Py_TYPE(self)->tp_free((PyObject *)self);
}

static PyMethodDef anota_methods[] = {
    {"ALLOW", (PyCFunction)anota_allow, METH_VARARGS | METH_KEYWORDS,
     PyDoc_STR("ALLOW(obj, modes, key=None)\n"
               "Set allowed access modes for an object (and optional key).\n"
               "modes is a combination of 'R', 'W', 'X'.")},
    {"BLOCK", (PyCFunction)anota_block, METH_VARARGS | METH_KEYWORDS,
     PyDoc_STR("BLOCK(obj, modes, key=None)\n"
               "Block selected access modes for an object (and optional key).")},
    {"CLEAR", (PyCFunction)anota_clear, METH_VARARGS | METH_KEYWORDS,
     PyDoc_STR("CLEAR(obj, key=None)\n"
               "Remove any policy for the given object/key.")},
    {"CLEAR_ALL", (PyCFunction)anota_clear_all, METH_NOARGS,
     PyDoc_STR("CLEAR_ALL()\n"
               "Remove all ANOTA_WATCH policies.")},
    {NULL, NULL}
};

static PyTypeObject AnotaWatch_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "ANOTA_WATCH",                      /* tp_name */
    sizeof(AnotaWatchObject),           /* tp_basicsize */
    0,                                  /* tp_itemsize */
    (destructor)anota_dealloc,          /* tp_dealloc */
    0,                                  /* tp_vectorcall_offset */
    0,                                  /* tp_getattr */
    0,                                  /* tp_setattr */
    0,                                  /* tp_as_async */
    0,                                  /* tp_repr */
    0,                                  /* tp_as_number */
    0,                                  /* tp_as_sequence */
    0,                                  /* tp_as_mapping */
    0,                                  /* tp_hash  */
    0,                                  /* tp_call  */
    0,                                  /* tp_str   */
    PyObject_GenericGetAttr,            /* tp_getattro */
    0,                                  /* tp_setattro */
    0,                                  /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT,                 /* tp_flags */
    "ANOTA_WATCH policy controller",    /* tp_doc   */
    0,                                  /* tp_traverse */
    0,                                  /* tp_clear */
    0,                                  /* tp_richcompare */
    0,                                  /* tp_weaklistoffset */
    0,                                  /* tp_iter  */
    0,                                  /* tp_iternext */
    anota_methods,                      /* tp_methods */
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
_PyAnotaWatch_GetSingleton(void)
{
    if (anota_singleton != NULL) {
        Py_INCREF(anota_singleton);
        return anota_singleton;
    }

    if (PyType_Ready(&AnotaWatch_Type) < 0) {
        return NULL;
    }

    AnotaWatchObject *self = PyObject_New(AnotaWatchObject, &AnotaWatch_Type);
    if (self == NULL) {
        return NULL;
    }
    self->policies = PyDict_New();
    if (self->policies == NULL) {
        Py_DECREF(self);
        return NULL;
    }

    anota_singleton = (PyObject *)self;
    Py_INCREF(anota_singleton);
    return anota_singleton;
}
