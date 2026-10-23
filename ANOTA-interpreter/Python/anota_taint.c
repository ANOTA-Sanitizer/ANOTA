#include "Python.h"
#include "anota_taint.h"
#include "anota_policy.h"
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
 * A label refers to a set of original sources. Derived labels never merge
 * sanitizer permissions: a sanitizer removes only sources that registered it.
 * Revoking a source invalidates its contribution to all derived labels.
 */

static PyObject *taint_sanitizers = NULL;          /* { id -> { func -> True } } */
static PyObject *taint_sinks = NULL;               /* { id -> { func -> True } } */
static PyObject *taint_default_write_sinks = NULL; /* { id -> True } */
/* Labels retain original sources; sanitizers remove only their own sources. */
static PyObject *source_sets = NULL;    /* label -> frozenset(origin ids) */
static PyObject *union_labels = NULL;   /* frozenset(origin ids) -> label */
static PyObject *taint_records = NULL;  /* origin -> policy handle token */
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
    if (source_sets == NULL) source_sets = PyDict_New();
    if (union_labels == NULL) union_labels = PyDict_New();
    if (taint_records == NULL) taint_records = PyDict_New();
    if (!source_sets || !union_labels || !taint_records) return -1;
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
    PyObject *ids = PySet_New(NULL);
    if (!ids) return -1;
    for (int i = 0; i < ANOTA_DFSAN_NATIVE_LABEL_SLOTS; i++) {
        if ((label & (1u << i)) && add_taint_id_to_set(ids, native_label_taint_ids[i]) < 0) {
            Py_DECREF(ids); return -1;
        }
    }
    Py_ssize_t pos = 0;
    PyObject *id;
    Py_hash_t hash;
    int rc = 0;
    while (_PySet_NextEntry(ids, &pos, &id, &hash)) {
        rc = has_default_write_sink(PyLong_AsSsize_t(id));
        if (rc != 0) break;
    }
    Py_DECREF(ids);
    return rc;
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
    return function_name_matches(func, "write") || function_name_matches(func, "writelines") ||
           (PyCFunction_Check(func) && function_name_matches(func, "print"));
}

static int
is_sanitizer_for_taint_id(Py_ssize_t taint_id, PyObject *func)
{
    return is_explicit_policy_match(taint_sanitizers, taint_id, func);
}

static int
add_taint_id_to_set(PyObject *ids, Py_ssize_t id)
{
    if (id <= 0 || source_sets == NULL) return 0;
    PyObject *key = PyLong_FromSsize_t(id);
    if (!key) return -1;
    PyObject *origins = PyDict_GetItemWithError(source_sets, key);
    Py_DECREF(key);
    if (!origins) return PyErr_Occurred() ? -1 : 0;
    Py_ssize_t pos = 0;
    PyObject *origin;
    Py_hash_t hash;
    while (_PySet_NextEntry(origins, &pos, &origin, &hash)) {
        int active = PyDict_Contains(taint_records, origin);
        if (active < 0 || (active && PySet_Add(ids, origin) < 0)) return -1;
    }
    return 0;
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

/* Inspect builtin containers without calling user iterators or descriptors.
 * A visited identity set handles cycles, aliases, and recursive containers. */
static int
collect_object(PyObject *obj, PyObject *ids, PyObject *seen)
{
    if (obj == NULL) return 0;
    PyObject *key = PyLong_FromVoidPtr(obj);
    if (!key) return -1;
    int visited = PySet_Contains(seen, key);
    if (visited || PySet_Add(seen, key) < 0) {
        Py_DECREF(key);
        return visited > 0 ? 0 : -1;
    }
    Py_DECREF(key);
    if (add_object_taint_to_set(ids, obj) < 0) return -1;
    if (Py_EnterRecursiveCall(" while inspecting ANOTA taint")) return -1;
    int rc = 0;
    if (PyList_Check(obj) || PyTuple_Check(obj)) {
        Py_ssize_t n = PyList_Check(obj) ? PyList_GET_SIZE(obj) : PyTuple_GET_SIZE(obj);
        for (Py_ssize_t i = 0; i < n && rc == 0; i++) {
            PyObject *item = PyList_Check(obj) ? PyList_GET_ITEM(obj, i) : PyTuple_GET_ITEM(obj, i);
            rc = collect_object(item, ids, seen);
        }
    } else if (PyDict_Check(obj)) {
        Py_ssize_t pos = 0;
        PyObject *k, *v;
        while (rc == 0 && PyDict_Next(obj, &pos, &k, &v)) {
            rc = collect_object(k, ids, seen);
            if (rc == 0) rc = collect_object(v, ids, seen);
        }
    } else if (PyAnySet_Check(obj)) {
        Py_ssize_t pos = 0;
        PyObject *item;
        Py_hash_t hash;
        while (rc == 0 && _PySet_NextEntry(obj, &pos, &item, &hash))
            rc = collect_object(item, ids, seen);
    }
    Py_LeaveRecursiveCall();
    return rc;
}

static int
collect_deep(PyObject *ids, PyObject *obj)
{
    PyObject *seen = PySet_New(NULL);
    if (!seen) return -1;
    int rc = collect_object(obj, ids, seen);
    Py_DECREF(seen);
    return rc;
}

static int
check_arg_taint(PyObject *func, PyObject *arg, PyObject *key, PyObject *ids)
{
    PyObject *sources = PySet_New(NULL);
    if (!sources) return -1;
    int rc = collect_deep(sources, arg);
    Py_ssize_t pos = 0;
    PyObject *origin;
    Py_hash_t hash;
    while (rc == 0 && _PySet_NextEntry(sources, &pos, &origin, &hash)) {
        int sink = is_sink_for_taint_id(PyLong_AsSsize_t(origin), func);
        if (sink < 0) rc = -1;
        else if (sink) rc = report_sink_violation(func, arg, key);
        else rc = PySet_Add(ids, origin);
    }
    Py_DECREF(sources);
    return rc;
}

static int
append_callable_taint(PyObject *func, PyObject *ids)
{
    if (add_object_taint_to_set(ids, func) < 0) return -1;
    /* Bound C/Python methods can consume their receiver without an explicit
       positional argument (e.g. secret.upper(), list.copy()). */
    PyObject *owner = PyCFunction_Check(func) ? PyCFunction_GET_SELF(func) :
                      PyMethod_Check(func) ? PyMethod_GET_SELF(func) : NULL;
    if (owner && !PyModule_Check(owner)) return check_arg_taint(func, owner, NULL, ids);
    return 0;
}

static int
apply_sources_to_target(PyObject *target, PyObject *sources)
{
    if (!target || !sources) return 0;
    /* Never poison process-wide singleton return values such as print's None. */
    if (target == Py_None || PyBool_Check(target) || target == Py_Ellipsis || target == Py_NotImplemented)
        return 0;
    if (ensure_state() < 0) return -1;
    PyObject *ids = PySet_New(NULL);
    if (!ids) return -1;
    for (Py_ssize_t i = 0; i < PyTuple_GET_SIZE(sources); i++) {
        if (add_taint_id_to_set(ids, PyLong_AsSsize_t(PyTuple_GET_ITEM(sources, i))) < 0) {
            Py_DECREF(ids); return -1;
        }
    }
    if (PySet_GET_SIZE(ids) == 0) {
        target->ob_anota_taint_id = 0;
        Py_DECREF(ids); return 0;
    }
    PyObject *frozen = PyFrozenSet_New(ids);
    Py_DECREF(ids);
    if (!frozen) return -1;
    PyObject *label = PyDict_GetItemWithError(union_labels, frozen);
    if (label) {
        target->ob_anota_taint_id = PyLong_AsSsize_t(label);
        Py_DECREF(frozen); return 0;
    }
    if (PyErr_Occurred() || next_taint_id == PY_SSIZE_T_MAX) {
        Py_DECREF(frozen);
        if (!PyErr_Occurred()) PyErr_SetString(PyExc_OverflowError, "ANOTA taint id space exhausted");
        return -1;
    }
    label = PyLong_FromSsize_t(next_taint_id++);
    if (!label) { Py_DECREF(frozen); return -1; }
    int rc = PyDict_SetItem(source_sets, label, frozen);
    if (rc == 0) rc = PyDict_SetItem(union_labels, frozen, label);
    if (rc == 0) target->ob_anota_taint_id = PyLong_AsSsize_t(label);
    Py_DECREF(label); Py_DECREF(frozen);
    return rc;
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

static int
remove_source(PyObject *token)
{
    PyObject *id = PyList_GET_ITEM(token, 1);
    PyObject *maps[] = {taint_sanitizers, taint_sinks, taint_default_write_sinks, taint_records};
    for (int i = 0; i < 4; i++) {
        if (PyDict_DelItem(maps[i], id) < 0) {
            if (PyErr_ExceptionMatches(PyExc_KeyError)) PyErr_Clear();
            else return -1;
        }
    }
    return 0;
}

static PyObject *
register_source(PyObject *obj, PyObject *sanitizers, PyObject *sinks)
{
    if (ensure_state() < 0) return NULL;
    if (next_taint_id == PY_SSIZE_T_MAX) {
        PyErr_SetString(PyExc_OverflowError, "ANOTA taint id space exhausted"); return NULL;
    }
    Py_ssize_t id = next_taint_id++;
    PyObject *token = Py_BuildValue("[OnO]", Py_True, id, obj);
    if (!token) return NULL;
    PyObject *id_obj = PyList_GET_ITEM(token, 1);
    PyObject *singleton = PyTuple_Pack(1, id_obj);
    PyObject *origins = singleton ? PyFrozenSet_New(singleton) : NULL;
    Py_XDECREF(singleton);
    PyObject *handle = NULL;
    if (!origins) goto fail;
    if (register_funcs_from_seq(sanitizers, taint_sanitizers, id, "sanitization") < 0 ||
        register_funcs_from_seq(sinks, taint_sinks, id, "Sink") < 0 ||
        ((sinks == NULL || sinks == Py_None) && mark_default_write_sink(id) < 0) ||
        PyDict_SetItem(source_sets, id_obj, origins) < 0 ||
        PyDict_SetItem(union_labels, origins, id_obj) < 0 ||
        PyDict_SetItem(taint_records, id_obj, token) < 0) goto fail;
    handle = _PyAnotaPolicy_New(token, remove_source);
    if (!handle) goto fail;
    PyObject *sources = Py_BuildValue("(nn)", get_taint_id(obj), id);
    if (!sources) goto fail;
    int rc = apply_sources_to_target(obj, sources);
    Py_DECREF(sources);
    if (rc < 0) goto fail;
    Py_DECREF(origins); Py_DECREF(token);
    return handle;
 fail: {
    PyObject *type, *value, *tb;
    PyErr_Fetch(&type, &value, &tb);
    remove_source(token);
    PyErr_Clear();
    PyErr_Restore(type, value, tb);
    Py_XDECREF(handle); Py_XDECREF(origins); Py_DECREF(token);
    return NULL;
 }
}

int
_PyAnotaTaint_Register(PyObject *obj, PyObject *sanitizers, PyObject *sinks)
{
    PyObject *handle = register_source(obj, sanitizers, sinks);
    if (!handle) return -1;
    Py_DECREF(handle);
    return 0;
}

int
_PyAnotaTaint_IsTainted(PyObject *obj)
{
    if (!source_sets || !taint_records || PyDict_GET_SIZE(taint_records) == 0) return 0;
    PyObject *ids = PySet_New(NULL);
    if (!ids) { PyErr_Clear(); return 0; }
    int rc = collect_deep(ids, obj);
    int tainted = rc == 0 && PySet_GET_SIZE(ids) > 0;
    Py_DECREF(ids);
    if (rc < 0) PyErr_Clear();
    return tainted;
}

void
_PyAnotaTaint_ClearAll(void)
{
    if (!taint_records) return;
    Py_ssize_t pos = 0;
    PyObject *id, *token;
    while (PyDict_Next(taint_records, &pos, &id, &token)) _PyAnotaPolicy_Invalidate(token);
    PyDict_Clear(taint_records);
    PyDict_Clear(taint_sanitizers);
    PyDict_Clear(taint_sinks);
    PyDict_Clear(taint_default_write_sinks);
    PyDict_Clear(source_sets);
    PyDict_Clear(union_labels);
    /* Never recycle source ids or native bits: stale object/shadow labels must
       not acquire the policies of a subsequent request. */
    native_sink_violation_pending = 0;
}

static PyObject *
taint_clear(PyObject *self, PyObject *obj)
{
    PyObject *ids = PySet_New(NULL);
    if (!ids) return NULL;
    if (collect_deep(ids, obj) < 0) { Py_DECREF(ids); return NULL; }
    Py_ssize_t pos = 0;
    PyObject *id;
    Py_hash_t hash;
    while (_PySet_NextEntry(ids, &pos, &id, &hash)) {
        PyObject *token = PyDict_GetItemWithError(taint_records, id);
        if (!token) continue;
        Py_INCREF(token);
        if (remove_source(token) < 0) { Py_DECREF(token); Py_DECREF(ids); return NULL; }
        _PyAnotaPolicy_Invalidate(token);
        Py_DECREF(token);
    }
    Py_DECREF(ids);
    Py_RETURN_NONE;
}

static PyObject *
taint_clear_all(PyObject *self, PyObject *unused)
{
    _PyAnotaTaint_ClearAll();
    Py_RETURN_NONE;
}

static PyObject *
taint_is_tainted(PyObject *self, PyObject *obj)
{
    return PyBool_FromLong(_PyAnotaTaint_IsTainted(obj));
}

static PyMethodDef taint_methods[] = {
    {"CLEAR", taint_clear, METH_O, "Revoke the sources reaching this object, including container members."},
    {"CLEAR_ALL", taint_clear_all, METH_NOARGS, "Revoke all taint sources, including derived labels."},
    {"IS_TAINTED", taint_is_tainted, METH_O, "Inspect active taint, including builtin container members."},
    {NULL, NULL}
};
static PyTypeObject Taint_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = "ANOTA_TAINT",
    .tp_basicsize = sizeof(PyObject),
    .tp_flags = Py_TPFLAGS_DEFAULT,
    .tp_call = _PyAnota_Taint,
    .tp_methods = taint_methods,
};
PyObject *
_PyAnotaTaint_GetSingleton(void)
{
    if (PyType_Ready(&Taint_Type) < 0) return NULL;
    return PyObject_New(PyObject, &Taint_Type);
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
                              PyObject *Py_UNUSED(survivors))
{
    PyObject *taint_ids;
    PyObject *sources;

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

    if (add_object_taint_to_set(taint_ids, func) < 0) {
        Py_DECREF(taint_ids);
        return -1;
    }

    sources = build_source_tuple(taint_ids);
    if (sources == NULL) {
        return -1;
    }

    PyObject *filtered = filter_sanitized_sources(func, sources);
    Py_DECREF(sources);
    sources = filtered;
    if (sources == NULL) return -1;
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

    return register_source(obj, sanitization, sink);
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
    if (_PyAnotaPolicy_IsControl(func) || !taint_records || PyDict_GET_SIZE(taint_records) == 0)
        return PyTuple_New(0);
    return collect_vectorcall_sources(func, stack, nargs + nkwargs);
}

PyObject *
_PyAnotaTaint_CheckTupleDictCall(PyThreadState *tstate,
                                 PyObject *func,
                                 PyObject *args_tuple,
                                 PyObject *kwargs_dict)
{
    (void)tstate;
    if (_PyAnotaPolicy_IsControl(func) || !taint_records || PyDict_GET_SIZE(taint_records) == 0)
        return PyTuple_New(0);
    return collect_tupledict_sources(func, args_tuple, kwargs_dict);
}

/* --- post-call sanitizer handling ------------------------------------- */

void
_PyAnotaTaint_PostCall(PyObject *func, PyObject *result, PyObject *taint_sources)
{
    PyObject *survivors;
    int precise_native;

    if (result == NULL || taint_sources == NULL || _PyAnotaPolicy_IsControl(func) ||
        !taint_records || PyDict_GET_SIZE(taint_records) == 0) {
        return;
    }

    PyObject *all = PySet_New(taint_sources);
    if (!all) { PyErr_Clear(); return; }
    if (collect_deep(all, result) < 0) { Py_DECREF(all); PyErr_Clear(); return; }
    PyObject *combined = build_source_tuple(all);
    if (!combined) { PyErr_Clear(); return; }
    survivors = filter_sanitized_sources(func, combined);
    Py_DECREF(combined);
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
    _PyAnotaTaint_PropagateBinary(source, NULL, target);
}

void
_PyAnotaTaint_PropagateBinary(PyObject *left, PyObject *right, PyObject *result)
{
    PyObject *taint_ids;

    if (result == NULL || !taint_records || PyDict_GET_SIZE(taint_records) == 0) return;

    taint_ids = PySet_New(NULL);
    if (taint_ids == NULL) {
        PyErr_Clear();
        return;
    }

    if (collect_deep(taint_ids, left) < 0 ||
        collect_deep(taint_ids, right) < 0 ||
        collect_deep(taint_ids, result) < 0) {
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

int
_PyAnotaTaint_IsController(PyObject *obj)
{ return Py_TYPE(obj) == &Taint_Type; }
