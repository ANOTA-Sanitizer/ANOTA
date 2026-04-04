#include "Python.h"
#include "anota_taint.h"
#include "pycore_pystate.h"  /* PyThreadState */
#include <stdio.h>
#include <string.h>

#ifdef HAVE_DLOPEN
#  include <dlfcn.h>
#endif

/* Taint is tracked by object identity, not by Python value equality.
 *
 * Each PyObject carries an ANOTA taint id in ob_anota_taint_id. That id
 * points to policy bundles stored in global dicts:
 *
 *   taint_sanitizers: { taint_id -> { callable -> True } }
 *   taint_sinks:      { taint_id -> { callable -> True } }
 *   taint_default_write_sinks: { taint_id -> True }
 *
 * When tainted values flow together, ANOTA creates a derived taint id whose
 * policy bundle is the union of the source bundles. This keeps the runtime
 * object-centric while still supporting per-source sink/sanitizer policies.
 */

static PyObject *taint_sanitizers = NULL;          /* { id -> { func -> True } } */
static PyObject *taint_sinks = NULL;               /* { id -> { func -> True } } */
static PyObject *taint_default_write_sinks = NULL; /* { id -> True } */
static Py_ssize_t next_taint_id = 1;

#define ANOTA_DFSAN_NATIVE_LABEL_SLOTS 8

typedef unsigned char anota_dfsan_label;
typedef void (*anota_dfsan_set_label_fn)(anota_dfsan_label, void *, size_t);
typedef anota_dfsan_label (*anota_dfsan_read_label_fn)(const void *, size_t);

static anota_dfsan_set_label_fn dfsan_set_label_fn = NULL;
static anota_dfsan_read_label_fn dfsan_read_label_fn = NULL;
static int dfsan_symbols_initialized = 0;
static Py_ssize_t native_label_taint_ids[ANOTA_DFSAN_NATIVE_LABEL_SLOTS] = {0};
static int native_label_slots_exhausted = 0;
static int native_sink_violation_pending = 0;
static char native_sink_violation_message[256];

static int has_default_write_sink(Py_ssize_t taint_id);
static int add_taint_id_to_set(PyObject *taint_ids, Py_ssize_t taint_id);

/* --- internal helpers -------------------------------------------------- */

static int
ensure_state(void)
{
    if (taint_sanitizers == NULL) {
        taint_sanitizers = PyDict_New();
        if (taint_sanitizers == NULL) {
            return -1;
        }
    }
    if (taint_sinks == NULL) {
        taint_sinks = PyDict_New();
        if (taint_sinks == NULL) {
            return -1;
        }
    }
    if (taint_default_write_sinks == NULL) {
        taint_default_write_sinks = PyDict_New();
        if (taint_default_write_sinks == NULL) {
            return -1;
        }
    }
    return 0;
}

static int
ensure_dfsan_symbols(void)
{
#ifdef HAVE_DLOPEN
    if (!dfsan_symbols_initialized) {
        dfsan_set_label_fn = (anota_dfsan_set_label_fn)dlsym(RTLD_DEFAULT, "dfsan_set_label");
        dfsan_read_label_fn = (anota_dfsan_read_label_fn)dlsym(RTLD_DEFAULT, "dfsan_read_label");
        dfsan_symbols_initialized = 1;
    }
    return dfsan_set_label_fn != NULL && dfsan_read_label_fn != NULL;
#else
    return 0;
#endif
}

static unsigned int
native_label_for_taint_id(Py_ssize_t taint_id)
{
    for (int i = 0; i < ANOTA_DFSAN_NATIVE_LABEL_SLOTS; i++) {
        if (native_label_taint_ids[i] == taint_id) {
            return 1u << i;
        }
    }
    for (int i = 0; i < ANOTA_DFSAN_NATIVE_LABEL_SLOTS; i++) {
        if (native_label_taint_ids[i] == 0) {
            native_label_taint_ids[i] = taint_id;
            return 1u << i;
        }
    }

    if (!native_label_slots_exhausted) {
        PySys_WriteStderr(
            "ANOTA_TAINT native export warning: DFSan label slots exhausted; "
            "native taint propagation disabled for additional sources\n");
        native_label_slots_exhausted = 1;
    }
    return 0;
}

static int
native_label_has_default_write_sink(unsigned int label)
{
    for (int i = 0; i < ANOTA_DFSAN_NATIVE_LABEL_SLOTS; i++) {
        Py_ssize_t taint_id;
        int rc;

        if ((label & (1u << i)) == 0) {
            continue;
        }
        taint_id = native_label_taint_ids[i];
        if (taint_id <= 0) {
            continue;
        }
        rc = has_default_write_sink(taint_id);
        if (rc < 0) {
            return -1;
        }
        if (rc > 0) {
            return 1;
        }
    }
    return 0;
}

static int
add_native_label_ids_to_set(PyObject *taint_ids, unsigned int label)
{
    for (int i = 0; i < ANOTA_DFSAN_NATIVE_LABEL_SLOTS; i++) {
        Py_ssize_t taint_id;

        if ((label & (1u << i)) == 0) {
            continue;
        }
        taint_id = native_label_taint_ids[i];
        if (taint_id <= 0) {
            continue;
        }
        if (add_taint_id_to_set(taint_ids, taint_id) < 0) {
            return -1;
        }
    }
    return 0;
}

static Py_ssize_t
get_taint_id(PyObject *obj)
{
    if (obj == NULL) {
        return 0;
    }
    return obj->ob_anota_taint_id;
}

static int
ensure_taint_id(PyObject *obj, Py_ssize_t *out_taint_id)
{
    if (obj == NULL) {
        PyErr_SetString(PyExc_TypeError, "ANOTA_TAINT requires a Python object");
        return -1;
    }
    if (ensure_state() < 0) {
        return -1;
    }

    if (obj->ob_anota_taint_id == 0) {
        if (next_taint_id <= 0) {
            PyErr_SetString(PyExc_OverflowError, "ANOTA taint id space exhausted");
            return -1;
        }
        obj->ob_anota_taint_id = next_taint_id++;
    }

    *out_taint_id = obj->ob_anota_taint_id;
    return 0;
}

static PyObject *
taint_id_to_key(Py_ssize_t taint_id)
{
    return PyLong_FromSsize_t(taint_id);
}

static PyObject *
get_policy_dict(PyObject *policy_map, Py_ssize_t taint_id)
{
    PyObject *key;
    PyObject *policy_dict;

    key = taint_id_to_key(taint_id);
    if (key == NULL) {
        return NULL;
    }
    policy_dict = PyDict_GetItemWithError(policy_map, key);  /* borrowed */
    Py_DECREF(key);
    if (policy_dict == NULL && PyErr_Occurred()) {
        return NULL;
    }
    return policy_dict;
}

static PyObject *
ensure_policy_dict(PyObject *policy_map, Py_ssize_t taint_id)
{
    PyObject *key;
    PyObject *policy_dict;

    key = taint_id_to_key(taint_id);
    if (key == NULL) {
        return NULL;
    }
    policy_dict = PyDict_GetItemWithError(policy_map, key);  /* borrowed */
    if (policy_dict == NULL) {
        if (PyErr_Occurred()) {
            Py_DECREF(key);
            return NULL;
        }
        policy_dict = PyDict_New();
        if (policy_dict == NULL) {
            Py_DECREF(key);
            return NULL;
        }
        if (PyDict_SetItem(policy_map, key, policy_dict) < 0) {
            Py_DECREF(policy_dict);
            Py_DECREF(key);
            return NULL;
        }
        Py_DECREF(policy_dict);
        policy_dict = PyDict_GetItemWithError(policy_map, key);  /* borrowed */
    }
    Py_DECREF(key);
    return policy_dict;
}

static int
mark_default_write_sink(Py_ssize_t taint_id)
{
    PyObject *key;
    int rc;

    key = taint_id_to_key(taint_id);
    if (key == NULL) {
        return -1;
    }
    rc = PyDict_SetItem(taint_default_write_sinks, key, Py_True);
    Py_DECREF(key);
    return rc;
}

static int
has_default_write_sink(Py_ssize_t taint_id)
{
    PyObject *key;
    int rc;

    if (taint_default_write_sinks == NULL) {
        return 0;
    }

    key = taint_id_to_key(taint_id);
    if (key == NULL) {
        return -1;
    }
    rc = PyDict_Contains(taint_default_write_sinks, key);
    Py_DECREF(key);
    return rc;
}

static int
register_funcs_from_seq(PyObject *seq, PyObject *policy_map,
                        Py_ssize_t taint_id, const char *role)
{
    PyObject *fast;
    PyObject *policy_dict;
    Py_ssize_t n;
    PyObject **items;

    if (seq == NULL || Py_IsNone(seq)) {
        return 0;
    }

    fast = PySequence_Fast(
        seq,
        role && *role ? "ANOTA_TAINT: expected a sequence for argument"
                      : "ANOTA_TAINT: bad sequence");
    if (fast == NULL) {
        return -1;
    }

    policy_dict = ensure_policy_dict(policy_map, taint_id);
    if (policy_dict == NULL) {
        Py_DECREF(fast);
        return -1;
    }

    n = PySequence_Fast_GET_SIZE(fast);
    items = PySequence_Fast_ITEMS(fast);
    for (Py_ssize_t i = 0; i < n; i++) {
        PyObject *func = items[i];
        if (!PyCallable_Check(func)) {
            Py_DECREF(fast);
            PyErr_Format(PyExc_TypeError,
                         "ANOTA_TAINT: %s entry at index %zd is not callable",
                         role ? role : "list", i);
            return -1;
        }
        if (PyDict_SetItem(policy_dict, func, Py_True) < 0) {
            Py_DECREF(fast);
            return -1;
        }
    }

    Py_DECREF(fast);
    return 0;
}

static int
copy_policy_entries(PyObject *policy_map, Py_ssize_t source_id,
                    Py_ssize_t target_id)
{
    PyObject *source_dict;
    PyObject *target_dict;
    PyObject *func;
    PyObject *value;
    Py_ssize_t pos = 0;

    source_dict = get_policy_dict(policy_map, source_id);
    if (source_dict == NULL) {
        if (PyErr_Occurred()) {
            return -1;
        }
        return 0;
    }

    target_dict = ensure_policy_dict(policy_map, target_id);
    if (target_dict == NULL) {
        return -1;
    }

    while (PyDict_Next(source_dict, &pos, &func, &value)) {
        if (PyDict_SetItem(target_dict, func, value) < 0) {
            return -1;
        }
    }
    return 0;
}

static int
function_name_matches(PyObject *func, const char *name)
{
    PyObject *name_obj;
    int rc;

    name_obj = PyObject_GetAttrString(func, "__name__");
    if (name_obj == NULL) {
        PyErr_Clear();
        return 0;
    }
    rc = PyUnicode_Check(name_obj) && PyUnicode_CompareWithASCIIString(name_obj, name) == 0;
    Py_DECREF(name_obj);
    return rc;
}

static int
is_explicit_policy_match(PyObject *policy_map, Py_ssize_t taint_id, PyObject *func)
{
    PyObject *policy_dict;
    int rc;

    policy_dict = get_policy_dict(policy_map, taint_id);
    if (policy_dict == NULL) {
        if (PyErr_Occurred()) {
            return -1;
        }
        return 0;
    }
    rc = PyDict_Contains(policy_dict, func);
    return rc;
}

static int
is_sink_for_taint_id(Py_ssize_t taint_id, PyObject *func)
{
    int rc = is_explicit_policy_match(taint_sinks, taint_id, func);
    if (rc != 0) {
        return rc;
    }

    rc = has_default_write_sink(taint_id);
    if (rc <= 0) {
        return rc;
    }
    return function_name_matches(func, "write");
}

static int
is_sanitizer_for_taint_id(Py_ssize_t taint_id, PyObject *func)
{
    return is_explicit_policy_match(taint_sanitizers, taint_id, func);
}

static int
add_taint_id_to_set(PyObject *taint_ids, Py_ssize_t taint_id)
{
    PyObject *id_obj;
    int rc;

    if (taint_id <= 0) {
        return 0;
    }

    id_obj = taint_id_to_key(taint_id);
    if (id_obj == NULL) {
        return -1;
    }
    rc = PySet_Add(taint_ids, id_obj);
    Py_DECREF(id_obj);
    return rc;
}

static int
tuple_contains_taint_id(PyObject *taint_ids, Py_ssize_t taint_id)
{
    PyObject *id_obj;
    int rc;

    if (taint_id <= 0) {
        return 0;
    }

    id_obj = taint_id_to_key(taint_id);
    if (id_obj == NULL) {
        return -1;
    }
    rc = PySequence_Contains(taint_ids, id_obj);
    Py_DECREF(id_obj);
    return rc;
}

static int
add_object_taint_to_set(PyObject *taint_ids, PyObject *obj)
{
    return add_taint_id_to_set(taint_ids, get_taint_id(obj));
}

static int
report_sink_violation(PyObject *func, PyObject *arg, PyObject *key)
{
    if (key != NULL) {
        PySys_FormatStderr(
            "ANOTA_TAINT violation: tainted object %R passed to sink %R "
            "via keyword argument %R\n",
            arg, func, key);
    }
    else {
        PySys_FormatStderr(
            "ANOTA_TAINT violation: tainted object %R passed to sink %R\n",
            arg, func);
    }
    PyErr_SetString(PyExc_RuntimeError, "ANOTA_TAINT sink violation");
    return -1;
}

static int
check_arg_taint(PyObject *func, PyObject *arg, PyObject *key, PyObject *taint_ids)
{
    Py_ssize_t taint_id = get_taint_id(arg);
    int sink;

    if (taint_id <= 0) {
        return 0;
    }

    sink = is_sink_for_taint_id(taint_id, func);
    if (sink < 0) {
        return -1;
    }
    if (sink) {
        return report_sink_violation(func, arg, key);
    }
    return add_taint_id_to_set(taint_ids, taint_id);
}

static int
append_callable_taint(PyObject *func, PyObject *taint_ids)
{
    return add_object_taint_to_set(taint_ids, func);
}

static int
merge_policies_from_ids(Py_ssize_t target_id, PyObject *source_ids)
{
    Py_ssize_t n = PyTuple_GET_SIZE(source_ids);

    for (Py_ssize_t i = 0; i < n; i++) {
        PyObject *id_obj = PyTuple_GET_ITEM(source_ids, i);
        Py_ssize_t source_id = PyLong_AsSsize_t(id_obj);
        int default_write;

        if (source_id == -1 && PyErr_Occurred()) {
            return -1;
        }
        if (copy_policy_entries(taint_sanitizers, source_id, target_id) < 0) {
            return -1;
        }
        if (copy_policy_entries(taint_sinks, source_id, target_id) < 0) {
            return -1;
        }
        default_write = has_default_write_sink(source_id);
        if (default_write < 0) {
            return -1;
        }
        if (default_write > 0 && mark_default_write_sink(target_id) < 0) {
            return -1;
        }
    }
    return 0;
}

static int
apply_sources_to_target(PyObject *target, PyObject *source_ids)
{
    Py_ssize_t n;
    Py_ssize_t target_id;

    if (target == NULL || source_ids == NULL) {
        return 0;
    }
    if (ensure_state() < 0) {
        return -1;
    }

    n = PyTuple_GET_SIZE(source_ids);
    if (n == 0) {
        target->ob_anota_taint_id = 0;
        return 0;
    }
    if (n == 1) {
        PyObject *id_obj = PyTuple_GET_ITEM(source_ids, 0);
        target_id = PyLong_AsSsize_t(id_obj);
        if (target_id == -1 && PyErr_Occurred()) {
            return -1;
        }
        target->ob_anota_taint_id = target_id;
        return 0;
    }

    if (next_taint_id <= 0) {
        PyErr_SetString(PyExc_OverflowError, "ANOTA taint id space exhausted");
        return -1;
    }
    target_id = next_taint_id++;

    if (merge_policies_from_ids(target_id, source_ids) < 0) {
        return -1;
    }
    target->ob_anota_taint_id = target_id;
    return 0;
}

static PyObject *
build_source_tuple(PyObject *taint_ids)
{
    PyObject *tuple;

    tuple = PySequence_Tuple(taint_ids);
    Py_DECREF(taint_ids);
    return tuple;
}

static PyObject *
collect_vectorcall_sources(PyObject *func,
                           PyObject *const *stack,
                           Py_ssize_t total_args)
{
    PyObject *taint_ids;

    taint_ids = PySet_New(NULL);
    if (taint_ids == NULL) {
        return NULL;
    }

    if (append_callable_taint(func, taint_ids) < 0) {
        Py_DECREF(taint_ids);
        return NULL;
    }

    for (Py_ssize_t i = 0; i < total_args; i++) {
        if (check_arg_taint(func, stack[i], NULL, taint_ids) < 0) {
            Py_DECREF(taint_ids);
            return NULL;
        }
    }

    return build_source_tuple(taint_ids);
}

static PyObject *
collect_tupledict_sources(PyObject *func,
                          PyObject *args_tuple,
                          PyObject *kwargs_dict)
{
    PyObject *taint_ids;
    Py_ssize_t nargs;

    taint_ids = PySet_New(NULL);
    if (taint_ids == NULL) {
        return NULL;
    }

    if (append_callable_taint(func, taint_ids) < 0) {
        Py_DECREF(taint_ids);
        return NULL;
    }

    if (args_tuple != NULL) {
        nargs = PyTuple_GET_SIZE(args_tuple);
        for (Py_ssize_t i = 0; i < nargs; i++) {
            if (check_arg_taint(func, PyTuple_GET_ITEM(args_tuple, i), NULL, taint_ids) < 0) {
                Py_DECREF(taint_ids);
                return NULL;
            }
        }
    }

    if (kwargs_dict != NULL) {
        PyObject *key;
        PyObject *value;
        Py_ssize_t pos = 0;
        while (PyDict_Next(kwargs_dict, &pos, &key, &value)) {
            if (check_arg_taint(func, value, key, taint_ids) < 0) {
                Py_DECREF(taint_ids);
                return NULL;
            }
        }
    }

    return build_source_tuple(taint_ids);
}

static PyObject *
filter_sanitized_sources(PyObject *func, PyObject *taint_sources)
{
    PyObject *survivors;
    Py_ssize_t n;

    survivors = PySet_New(NULL);
    if (survivors == NULL) {
        return NULL;
    }

    n = PyTuple_GET_SIZE(taint_sources);
    for (Py_ssize_t i = 0; i < n; i++) {
        PyObject *id_obj = PyTuple_GET_ITEM(taint_sources, i);
        Py_ssize_t taint_id = PyLong_AsSsize_t(id_obj);
        int sanitized;

        if (taint_id == -1 && PyErr_Occurred()) {
            Py_DECREF(survivors);
            return NULL;
        }
        sanitized = is_sanitizer_for_taint_id(taint_id, func);
        if (sanitized < 0) {
            Py_DECREF(survivors);
            return NULL;
        }
        if (!sanitized && PySet_Add(survivors, id_obj) < 0) {
            Py_DECREF(survivors);
            return NULL;
        }
    }

    return build_source_tuple(survivors);
}

/* --- public registration helpers -------------------------------------- */

int
_PyAnotaTaint_Register(PyObject *obj, PyObject *sanitizers, PyObject *sinks)
{
    Py_ssize_t taint_id;

    if (ensure_taint_id(obj, &taint_id) < 0) {
        return -1;
    }

    /* write() as the default sink. */
    if (mark_default_write_sink(taint_id) < 0) {
        return -1;
    }

    if (register_funcs_from_seq(sanitizers, taint_sanitizers,
                                taint_id, "sanitization") < 0) {
        return -1;
    }
    if (register_funcs_from_seq(sinks, taint_sinks,
                                taint_id, "Sink") < 0) {
        return -1;
    }
    return 0;
}

int
_PyAnotaTaint_IsTainted(PyObject *obj)
{
    return get_taint_id(obj) > 0;
}

int
_PyAnotaTaint_ExportBuffer(PyObject *source, void *buf, Py_ssize_t size)
{
    Py_ssize_t taint_id;
    unsigned int native_label;

    if (source == NULL || buf == NULL || size <= 0) {
        return 0;
    }
    if (!ensure_dfsan_symbols()) {
        return 0;
    }

    taint_id = get_taint_id(source);
    if (taint_id <= 0) {
        dfsan_set_label_fn(0, buf, (size_t)size);
        return 0;
    }

    native_label = native_label_for_taint_id(taint_id);
    if (native_label == 0) {
        return 0;
    }

    dfsan_set_label_fn((anota_dfsan_label)native_label, buf, (size_t)size);
    return 0;
}

int
_PyAnotaTaint_ImportBuffer(PyObject *target, const void *buf, Py_ssize_t size)
{
    PyObject *taint_ids;
    PyObject *sources;
    unsigned int native_label;

    if (target == NULL || buf == NULL || size <= 0) {
        return 0;
    }
    if (!ensure_dfsan_symbols()) {
        return 0;
    }

    native_label = (unsigned int)dfsan_read_label_fn(buf, (size_t)size);
    if (native_label == 0) {
        return 0;
    }

    taint_ids = PySet_New(NULL);
    if (taint_ids == NULL) {
        return -1;
    }

    if (add_object_taint_to_set(taint_ids, target) < 0 ||
        add_native_label_ids_to_set(taint_ids, native_label) < 0) {
        Py_DECREF(taint_ids);
        return -1;
    }

    sources = build_source_tuple(taint_ids);
    if (sources == NULL) {
        return -1;
    }

    if (apply_sources_to_target(target, sources) < 0) {
        Py_DECREF(sources);
        return -1;
    }

    Py_DECREF(sources);
    return 0;
}

void
_PyAnotaTaint_NativeCallBegin(void)
{
    native_sink_violation_pending = 0;
    native_sink_violation_message[0] = '\0';
}

int
_PyAnotaTaint_RecordNativeSinkLabel(const char *sink_name, int fd, unsigned int label)
{
    int sink_match;

    if (label == 0) {
        return 0;
    }

    sink_match = native_label_has_default_write_sink(label);
    if (sink_match < 0) {
        return -1;
    }
    if (!sink_match) {
        return 0;
    }

    native_sink_violation_pending = 1;
    PyOS_snprintf(
        native_sink_violation_message,
        sizeof(native_sink_violation_message),
        "ANOTA_TAINT native sink violation: tainted data reached %s(fd=%d)",
        sink_name ? sink_name : "native-sink",
        fd);
    return -1;
}

int
_PyAnotaTaint_NativeCallEnd(PyObject *func)
{
    if (!native_sink_violation_pending) {
        return 0;
    }

    PySys_FormatStderr(
        "%s via %R\n",
        native_sink_violation_message,
        func ? func : Py_None);
    PyErr_SetString(PyExc_RuntimeError, "ANOTA_TAINT native sink violation");
    native_sink_violation_pending = 0;
    native_sink_violation_message[0] = '\0';
    return -1;
}

static int
func_is_external_c_extension(PyObject *func)
{
#ifdef HAVE_DLOPEN
    Dl_info info;
    const char *filename;
    const char *suffix;

    if (!PyCFunction_Check(func) && !PyCMethod_Check(func)) {
        return 0;
    }
    if (dladdr((void *)PyCFunction_GET_FUNCTION(func), &info) == 0) {
        return 0;
    }
    filename = info.dli_fname;
    if (filename == NULL) {
        return 0;
    }
    suffix = strrchr(filename, '.');
    if (suffix == NULL) {
        return 0;
    }
    if (strcmp(suffix, ".so") == 0) {
        return 1;
    }
    return strstr(filename, ".so.") != NULL;
#else
    return 0;
#endif
}

static int
result_supports_precise_native_taint(PyObject *result)
{
    if (result == NULL) {
        return 0;
    }
    return PyBytes_Check(result) ||
           PyByteArray_Check(result) ||
           PyUnicode_Check(result);
}

static int
apply_precise_native_postcall(PyObject *func,
                              PyObject *result,
                              PyObject *survivors)
{
    PyObject *taint_ids;
    PyObject *sources;
    Py_ssize_t callable_taint_id;
    int rc;

    if (!func_is_external_c_extension(func) ||
        !result_supports_precise_native_taint(result) ||
        !ensure_dfsan_symbols()) {
        return 0;
    }

    taint_ids = PySet_New(NULL);
    if (taint_ids == NULL) {
        return -1;
    }

    if (add_object_taint_to_set(taint_ids, result) < 0) {
        Py_DECREF(taint_ids);
        return -1;
    }

    callable_taint_id = get_taint_id(func);
    rc = tuple_contains_taint_id(survivors, callable_taint_id);
    if (rc < 0) {
        Py_DECREF(taint_ids);
        return -1;
    }
    if (rc > 0 && add_taint_id_to_set(taint_ids, callable_taint_id) < 0) {
        Py_DECREF(taint_ids);
        return -1;
    }

    sources = build_source_tuple(taint_ids);
    if (sources == NULL) {
        return -1;
    }

    if (apply_sources_to_target(result, sources) < 0) {
        Py_DECREF(sources);
        return -1;
    }

    if (PyTuple_GET_SIZE(sources) > 0) {
        PySys_FormatStderr(
            "ANOTA_TAINT native propagation: call to %R returned %R (tainted)\n",
            func, result);
    }

    Py_DECREF(sources);
    return 1;
}

/* --- Python-level ANOTA_TAINT builtin --------------------------------- */

PyObject *
_PyAnota_Taint(PyObject *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"obj", "sanitization", "Sink", NULL};
    PyObject *obj;
    PyObject *sanitization = Py_None;
    PyObject *sink = Py_None;

    if (!PyArg_ParseTupleAndKeywords(
            args, kwds, "O|OO:ANOTA_TAINT", kwlist,
            &obj, &sanitization, &sink)) {
        return NULL;
    }

    if (_PyAnotaTaint_Register(obj, sanitization, sink) < 0) {
        return NULL;
    }

    Py_RETURN_NONE;
}

/* --- sink checks for various call paths ------------------------------- */

PyObject *
_PyAnotaTaint_CheckVectorcall(PyThreadState *tstate,
                              PyObject *func,
                              PyObject *const *stack,
                              Py_ssize_t nargs,
                              Py_ssize_t nkwargs,
                              PyObject *kwnames)
{
    (void)tstate;
    (void)kwnames;
    return collect_vectorcall_sources(func, stack, nargs + nkwargs);
}

PyObject *
_PyAnotaTaint_CheckTupleDictCall(PyThreadState *tstate,
                                 PyObject *func,
                                 PyObject *args_tuple,
                                 PyObject *kwargs_dict)
{
    (void)tstate;
    return collect_tupledict_sources(func, args_tuple, kwargs_dict);
}

/* --- post-call sanitizer handling ------------------------------------- */

void
_PyAnotaTaint_PostCall(PyObject *func, PyObject *result, PyObject *taint_sources)
{
    PyObject *survivors;
    int precise_native;

    if (result == NULL || taint_sources == NULL) {
        return;
    }

    survivors = filter_sanitized_sources(func, taint_sources);
    if (survivors == NULL) {
        PyErr_Clear();
        return;
    }

    precise_native = apply_precise_native_postcall(func, result, survivors);
    if (precise_native < 0) {
        Py_DECREF(survivors);
        PyErr_Clear();
        return;
    }
    if (precise_native > 0) {
        Py_DECREF(survivors);
        return;
    }

    if (apply_sources_to_target(result, survivors) == 0 &&
        PyTuple_GET_SIZE(survivors) > 0) {
        PySys_FormatStderr(
            "ANOTA_TAINT propagation: call to %R returned %R (tainted)\n",
            func, result);
    }
    else if (PyErr_Occurred()) {
        PyErr_Clear();
    }

    Py_DECREF(survivors);
}

/* --- propagation helpers ---------------------------------------------- */

void
_PyAnotaTaint_Propagate(PyObject *source, PyObject *target)
{
    PyObject *taint_ids;

    if (source == NULL || target == NULL || !_PyAnotaTaint_IsTainted(source)) {
        return;
    }

    taint_ids = PyTuple_New(1);
    if (taint_ids == NULL) {
        PyErr_Clear();
        return;
    }
    {
        PyObject *id_obj = taint_id_to_key(get_taint_id(source));
        if (id_obj == NULL) {
            Py_DECREF(taint_ids);
            PyErr_Clear();
            return;
        }
        PyTuple_SET_ITEM(taint_ids, 0, id_obj);
    }

    if (apply_sources_to_target(target, taint_ids) == 0) {
        PySys_FormatStderr("ANOTA_TAINT propagation: %R -> %R\n", source, target);
    }
    else {
        PyErr_Clear();
    }
    Py_DECREF(taint_ids);
}

void
_PyAnotaTaint_PropagateBinary(PyObject *left, PyObject *right, PyObject *result)
{
    PyObject *taint_ids;

    if (result == NULL) {
        return;
    }

    taint_ids = PySet_New(NULL);
    if (taint_ids == NULL) {
        PyErr_Clear();
        return;
    }

    if (add_object_taint_to_set(taint_ids, left) < 0 ||
        add_object_taint_to_set(taint_ids, right) < 0 ||
        add_object_taint_to_set(taint_ids, result) < 0) {
        Py_DECREF(taint_ids);
        PyErr_Clear();
        return;
    }

    {
        PyObject *sources = build_source_tuple(taint_ids);
        if (sources == NULL) {
            PyErr_Clear();
            return;
        }

        if (apply_sources_to_target(result, sources) == 0 &&
            PyTuple_GET_SIZE(sources) > 0) {
            PySys_FormatStderr(
                "ANOTA_TAINT propagation: %R, %R -> %R\n",
                left ? left : Py_None,
                right ? right : Py_None,
                result);
        }
        else if (PyErr_Occurred()) {
            PyErr_Clear();
        }

        Py_DECREF(sources);
    }
}
