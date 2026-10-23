#include "Python.h"
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include "anota_syscall.h"
#include "anota_policy.h"

#ifndef MS_WINDOWS
#  include <sys/types.h>
#  include <sys/socket.h>
#  include <sys/un.h>
#  include <sys/time.h>
#  include <unistd.h>
#endif
#include <errno.h>

#define POLICY_ALLOW_INDEX 0
#define POLICY_BLOCK_INDEX 1

typedef enum {
    POLICY_ENTRY_INVALID = 0,
    POLICY_ENTRY_PATH = 1,
    POLICY_ENTRY_PATH_PREFIX = 2,
    POLICY_ENTRY_DOMAIN = 3,
    POLICY_ENTRY_IP = 4,
    POLICY_ENTRY_PROTOCOL = 5,
    POLICY_ENTRY_SCHEME = 6,
    POLICY_ENTRY_HOST = 7,
} PolicyEntryKind;

#define POLICY_ENTRY_BASE_MASK 0xFF
#define POLICY_ENTRY_FLAG_WILDCARD 0x100

#ifndef ANOTA_SYSCALL_SOCKET_PATH
#  define ANOTA_SYSCALL_SOCKET_PATH "/tmp/anota_syscall.sock"
#endif

/* Acknowledged, bounded requests. Policy violations only log; transport
 * failures raise so callers cannot mistake an inactive monitor for success. */
static int monitor_enabled = 0;
static long monitor_target_pid = 0;
static long monitor_origin_pid = 0;
static int monitor_syncing = 0;

static int
send_monitor_command(const char *command, Py_ssize_t length)
{
#ifndef MS_WINDOWS
    const char *path = getenv("ANOTA_SYSCALL_SOCKET");
    if (path == NULL || *path == '\0') path = ANOTA_SYSCALL_SOCKET_PATH;
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (strlen(path) >= sizeof(addr.sun_path)) {
        PyErr_SetString(PyExc_ValueError, "ANOTA_SYSCALL socket path is too long");
        return -1;
    }
    memcpy(addr.sun_path, path, strlen(path) + 1);
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return PyErr_SetFromErrno(PyExc_OSError), -1;
    struct timeval timeout = {5, 0};
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0 ||
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) < 0 ||
        connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) goto io_error;
    while (length > 0) {
#ifdef MSG_NOSIGNAL
        ssize_t n = send(fd, command, (size_t)length, MSG_NOSIGNAL);
#else
        ssize_t n = send(fd, command, (size_t)length, 0);
#endif
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { if (n == 0) errno = EPIPE; goto io_error; }
        command += n; length -= n;
    }
    char response[4096];
    size_t used = 0;
    while (used < sizeof(response) - 1) {
        ssize_t n = recv(fd, response + used, 1, 0);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) goto io_error;
        if (n == 0) break;
        if (response[used++] == '\n') break;
    }
    close(fd);
    response[used] = '\0';
    if (strcmp(response, "OK\n") != 0) {
        PyErr_Format(PyExc_RuntimeError, "ANOTA_SYSCALL monitor rejected policy: %s",
                     used ? response : "connection closed without acknowledgement");
        return -1;
    }
    return 0;
io_error: {
    int saved = errno;
    close(fd); errno = saved;
    PyErr_SetFromErrnoWithFilename(PyExc_OSError, path);
    return -1;
}
#else
    PyErr_SetString(PyExc_NotImplementedError, "Aya syscall monitoring requires Linux");
    return -1;
#endif
}

typedef struct {
    PyObject_HEAD
    PyObject *blocked_syscalls;   /* set of uppercase syscall names */
    PyObject *allowed_syscalls;   /* set of uppercase syscall names */
    PyObject *path_policies;      /* dict: op_name -> (allow_list, block_list) */
    PyObject *records;           /* independent annotation tokens */
    PyObject *operation_cache;    /* dict: attr name -> AnotaSyscallOperationObject */
} AnotaSyscallObject;

typedef struct {
    PyObject_HEAD
    AnotaSyscallObject *owner;    /* borrowed from singleton */
    PyObject *op_name;            /* uppercase Unicode object */
} AnotaSyscallOperationObject;

static PyTypeObject AnotaSyscall_Type;
static PyTypeObject AnotaSyscallOperation_Type;
static PyObject *anota_syscall_singleton = NULL;

static int
monitor_requested(void)
{
    const char *backend = getenv("ANOTA_SYSCALL_BACKEND");
    return monitor_enabled || (backend && strcmp(backend, "ebpf") == 0);
}

static PyObject *
kernel_operations(AnotaSyscallObject *self)
{
    PyObject *result = PyDict_New();
    if (!result) return NULL;
    Py_ssize_t pos = 0;
    PyObject *name, *rules;
    while (PyDict_Next(self->path_policies, &pos, &name, &rules)) {
        PyObject *pair = Py_BuildValue("([],[])");
        if (!pair) { Py_DECREF(result); return NULL; }
        for (int side = 0; side < 2; side++) {
            PyObject *entries = PyTuple_GET_ITEM(rules, side);
            for (Py_ssize_t i = 0; i < PyList_GET_SIZE(entries); i++) {
                PyObject *entry = PyList_GET_ITEM(entries, i);
                int kind = PyLong_AsLong(PyTuple_GET_ITEM(entry, 0)) & POLICY_ENTRY_BASE_MASK;
                if (kind <= POLICY_ENTRY_PROTOCOL && PyList_Append(PyTuple_GET_ITEM(pair, side), entry) < 0) {
                    Py_DECREF(pair); Py_DECREF(result); return NULL;
                }
            }
        }
        if (PyList_GET_SIZE(PyTuple_GET_ITEM(pair, 0)) || PyList_GET_SIZE(PyTuple_GET_ITEM(pair, 1))) {
            if (PyDict_SetItem(result, name, pair) < 0) { Py_DECREF(pair); Py_DECREF(result); return NULL; }
        }
        Py_DECREF(pair);
    }
    return result;
}

static int
sync_policy(AnotaSyscallObject *self, long pid, const char *action)
{
    PyObject *blocked = NULL, *allowed = NULL, *message = NULL;
    PyObject *json = NULL, *encoded = NULL, *line = NULL, *operations = NULL;
    int result = -1;
    monitor_syncing = 1;
    blocked = PySequence_List(self->blocked_syscalls);
    allowed = PySequence_List(self->allowed_syscalls);
    operations = kernel_operations(self);
    if (blocked == NULL || allowed == NULL || operations == NULL) goto done;
    message = Py_BuildValue("{s:i,s:s,s:l,s:O,s:O,s:O}",
        "version", 1, "action", action, "pid", pid,
        "blocked", blocked, "allowed", allowed, "operations", operations);
    if (message == NULL) goto done;
    json = PyImport_ImportModule("json");
    if (json == NULL) goto done;
    encoded = PyObject_CallMethod(json, "dumps", "O", message);
    if (encoded == NULL) goto done;
    line = PyUnicode_FromFormat("%U\n", encoded);
    if (line == NULL) goto done;
    Py_ssize_t size;
    const char *bytes = PyUnicode_AsUTF8AndSize(line, &size);
    if (bytes == NULL) goto done;
    if (size > 1024 * 1024) {
        PyErr_SetString(PyExc_ValueError, "ANOTA_SYSCALL policy exceeds 1 MiB");
        goto done;
    }
    result = send_monitor_command(bytes, size);
    if (result == 0) {
        monitor_enabled = strcmp(action, "stop") != 0;
        monitor_target_pid = pid;
#ifndef MS_WINDOWS
        monitor_origin_pid = (long)getpid();
#endif
    }
 done:
    Py_XDECREF(operations);
    Py_XDECREF(line); Py_XDECREF(encoded); Py_XDECREF(json);
    Py_XDECREF(message); Py_XDECREF(allowed); Py_XDECREF(blocked);
    monitor_syncing = 0;
    return result;
}

typedef struct {
    PyObject *blocked, *allowed, *paths;
} PolicyBackup;

static void
backup_free(PolicyBackup *backup)
{
    Py_XDECREF(backup->blocked); Py_XDECREF(backup->allowed); Py_XDECREF(backup->paths);
}

static int
backup_policy(AnotaSyscallObject *self, PolicyBackup *backup)
{
    memset(backup, 0, sizeof(*backup));
    backup->blocked = PySet_New(self->blocked_syscalls);
    backup->allowed = PySet_New(self->allowed_syscalls);
    backup->paths = PyDict_New();
    if (!backup->blocked || !backup->allowed || !backup->paths) goto error;
    PyObject *key, *value;
    Py_ssize_t pos = 0;
    while (PyDict_Next(self->path_policies, &pos, &key, &value)) {
        PyObject *allow = PySequence_List(PyTuple_GET_ITEM(value, 0));
        PyObject *block = PySequence_List(PyTuple_GET_ITEM(value, 1));
        PyObject *pair = (allow && block) ? PyTuple_Pack(2, allow, block) : NULL;
        Py_XDECREF(allow); Py_XDECREF(block);
        if (!pair) goto error;
        int rc = PyDict_SetItem(backup->paths, key, pair);
        Py_DECREF(pair);
        if (rc < 0) goto error;
    }
    return 0;
 error:
    backup_free(backup);
    return -1;
}

static PyObject *
finish_policy_change(AnotaSyscallObject *self, PolicyBackup *backup, PyObject *result)
{
#ifndef MS_WINDOWS
    if (result != NULL && monitor_requested() &&
        sync_policy(self, (monitor_enabled && monitor_origin_pid == (long)getpid())
            ? monitor_target_pid : (long)getpid(), "replace") < 0) {
        Py_CLEAR(result);
    }
#endif
    if (result == NULL) {
        Py_SETREF(self->blocked_syscalls, backup->blocked);
        Py_SETREF(self->allowed_syscalls, backup->allowed);
        Py_SETREF(self->path_policies, backup->paths);
        memset(backup, 0, sizeof(*backup));
    }
    backup_free(backup);
    return result;
}



/* ------------------------------------------------------------------------- */
/* Helpers                                                                   */

static inline AnotaSyscallObject *
get_singleton_struct(void)
{
    return (AnotaSyscallObject *)anota_syscall_singleton;
}

static PyObject *
normalize_syscall_name(PyObject *name_obj)
{
    if (!PyUnicode_Check(name_obj)) {
        PyErr_Format(PyExc_TypeError,
                     "syscall names must be str, got %.50s",
                     Py_TYPE(name_obj)->tp_name);
        return NULL;
    }
    return PyObject_CallMethod(name_obj, "upper", NULL);
}

static PyObject *
normalize_c_name(const char *name)
{
    if (name == NULL) {
        return NULL;
    }
    PyObject *value = PyUnicode_FromString(name);
    if (value == NULL) {
        return NULL;
    }
    PyObject *upper = PyObject_CallMethod(value, "upper", NULL);
    Py_DECREF(value);
    return upper;
}

static int
update_name_set(PyObject *set_obj, PyObject *arg)
{
    PyObject *normalized = normalize_syscall_name(arg);
    if (normalized == NULL) {
        return -1;
    }
    int rc = PySet_Add(set_obj, normalized);
    Py_DECREF(normalized);
    return rc;
}

static int
unicode_contains_wildcard(PyObject *text)
{
    if (PyUnicode_READY(text) < 0) {
        return -1;
    }
    Py_ssize_t len = PyUnicode_GET_LENGTH(text);
    int kind = PyUnicode_KIND(text);
    void *data = PyUnicode_DATA(text);
    for (Py_ssize_t i = 0; i < len; i++) {
        if (PyUnicode_READ(kind, data, i) == '*') {
            return 1;
        }
    }
    return 0;
}

static int
unicode_match_wildcard_impl(int pkind, void *pdata, Py_ssize_t plen,
                            int vkind, void *vdata, Py_ssize_t vlen,
                            Py_ssize_t pi, Py_ssize_t vi)
{
    while (pi < plen) {
        Py_UCS4 pc = PyUnicode_READ(pkind, pdata, pi);
        if (pc == '*') {
            pi++;
            if (pi == plen) {
                return 1;
            }
            for (Py_ssize_t skip = vi; skip <= vlen; skip++) {
                int match = unicode_match_wildcard_impl(
                    pkind, pdata, plen, vkind, vdata, vlen, pi, skip);
                if (match != 0) {
                    return match;
                }
            }
            return 0;
        }
        if (vi >= vlen) {
            return 0;
        }
        Py_UCS4 vc = PyUnicode_READ(vkind, vdata, vi);
        if (pc != vc) {
            return 0;
        }
        pi++;
        vi++;
    }
    return vi == vlen;
}

static int
unicode_match_wildcard(PyObject *pattern, PyObject *value)
{
    if (PyUnicode_READY(pattern) < 0) {
        return -1;
    }
    if (PyUnicode_READY(value) < 0) {
        return -1;
    }
    return unicode_match_wildcard_impl(
        PyUnicode_KIND(pattern), PyUnicode_DATA(pattern),
        PyUnicode_GET_LENGTH(pattern),
        PyUnicode_KIND(value), PyUnicode_DATA(value),
        PyUnicode_GET_LENGTH(value),
        0, 0);
}

static int
mark_wildcard_if_needed(PyObject *text, int *kind_io)
{
    int wildcard = unicode_contains_wildcard(text);
    if (wildcard < 0) {
        return -1;
    }
    if (wildcard) {
        *kind_io |= POLICY_ENTRY_FLAG_WILDCARD;
    }
    return 0;
}

static PyObject *
make_policy_entry(int kind, PyObject *value)
{
    PyObject *kind_obj = PyLong_FromLong(kind);
    PyObject *entry = NULL;
    if (kind_obj == NULL) {
        Py_DECREF(value);
        return NULL;
    }
    entry = PyTuple_Pack(2, kind_obj, value);
    Py_DECREF(kind_obj);
    Py_DECREF(value);
    return entry;
}

static PyObject *
normalize_path_value(PyObject *value, int *kind_io)
{
    PyObject *path = NULL;
    if (!PyUnicode_FSDecoder(value, &path)) {
        return NULL;
    }
    Py_ssize_t len = PyUnicode_GetLength(path);
    if (len > 0) {
        Py_UCS4 ch = PyUnicode_ReadChar(path, len - 1);
        if (ch == '/' || ch == '\\') {
            *kind_io = POLICY_ENTRY_PATH_PREFIX;
        }
    }
    if (mark_wildcard_if_needed(path, kind_io) < 0) {
        Py_DECREF(path);
        return NULL;
    }
    return path;
}

static PyObject *
normalize_domain_value(PyObject *value)
{
    PyObject *text = PyUnicode_FromObject(value);
    PyObject *lower = NULL;
    if (text == NULL) {
        return NULL;
    }
    lower = PyObject_CallMethod(text, "casefold", NULL);
    Py_DECREF(text);
    return lower;
}

static PyObject *
normalize_url_value(PyObject *value, int kind)
{
    if (!PyUnicode_Check(value) || PyUnicode_GET_LENGTH(value) == 0 ||
        PyUnicode_FindChar(value, 0, 0, PyUnicode_GET_LENGTH(value), 1) >= 0) {
        PyErr_SetString(PyExc_ValueError, "URL policy values must be nonempty strings without NUL");
        return NULL;
    }
    PyObject *module = PyImport_ImportModule("anota_url");
    if (!module) return NULL;
    PyObject *result = PyObject_CallMethod(module,
        kind == POLICY_ENTRY_HOST ? "normalize_host" : "normalize_scheme", "O", value);
    Py_DECREF(module);
    return result;
}

static PyObject *
normalize_ip_value(PyObject *value)
{
    PyObject *text = PyUnicode_FromObject(value);
    PyObject *lower = NULL;
    if (text == NULL) {
        return NULL;
    }
    lower = PyObject_CallMethod(text, "casefold", NULL);
    Py_DECREF(text);
    return lower;
}

typedef struct {
    const char *name;
    int number;
} ProtocolNameMap;

static const ProtocolNameMap protocol_name_map[] = {
    {"ICMP", 1},
    {"TCP", 6},
    {"UDP", 17},
    {"ICMPV6", 58},
    {"RAW", 255},
    {"SCTP", 132},
    {"IPPROTO_TCP", 6},
    {"IPPROTO_UDP", 17},
    {"IPPROTO_ICMP", 1},
    {"IPPROTO_ICMPV6", 58},
    {"IPPROTO_RAW", 255},
    {"IPPROTO_SCTP", 132},
    {NULL, 0}
};

static int
protocol_name_to_number(const char *name, int *out_number)
{
    for (const ProtocolNameMap *entry = protocol_name_map;
         entry->name != NULL;
         entry++) {
        if (strcmp(entry->name, name) == 0) {
            *out_number = entry->number;
            return 0;
        }
    }
    return -1;
}

static PyObject *
normalize_protocol_value(PyObject *value)
{
    long proto_num;
    if (PyLong_Check(value)) {
        proto_num = PyLong_AsLong(value);
        if (proto_num == -1 && PyErr_Occurred()) {
            return NULL;
        }
        return PyUnicode_FromFormat("%ld", proto_num);
    }
    PyObject *text = PyUnicode_FromObject(value);
    if (text == NULL) {
        return NULL;
    }
    PyObject *upper = PyObject_CallMethod(text, "upper", NULL);
    Py_DECREF(text);
    if (upper == NULL) {
        return NULL;
    }
    Py_ssize_t size;
    const char *raw = PyUnicode_AsUTF8AndSize(upper, &size);
    if (raw == NULL) {
        Py_DECREF(upper);
        return NULL;
    }
    int all_digits = 1;
    for (Py_ssize_t i = 0; i < size; i++) {
        if (raw[i] < '0' || raw[i] > '9') {
            all_digits = 0;
            break;
        }
    }
    if (size == 1 && raw[0] == '*') {
        return upper;
    }
    if (all_digits && size > 0) {
        PyObject *num = PyLong_FromUnicodeObject(upper, 10);
        if (num == NULL) {
            Py_DECREF(upper);
            return NULL;
        }
        proto_num = PyLong_AsLong(num);
        Py_DECREF(num);
        if (proto_num == -1 && PyErr_Occurred()) {
            Py_DECREF(upper);
            return NULL;
        }
        Py_DECREF(upper);
        return PyUnicode_FromFormat("%ld", proto_num);
    }
    int numeric_proto = 0;
    if (protocol_name_to_number(raw, &numeric_proto) == 0) {
        Py_DECREF(upper);
        return PyUnicode_FromFormat("%d", numeric_proto);
    }
    PyErr_Format(PyExc_ValueError,
                 "unknown protocol name '%s' (use a number like 6 for TCP)",
                 raw);
    Py_DECREF(upper);
    return NULL;
}

static PyObject *
normalize_target_path(PyObject *value)
{
    PyObject *path = NULL;
    if (!PyUnicode_FSDecoder(value, &path)) {
        return NULL;
    }
    return path;
}

static int
equals_ignore_case(const char *a, const char *b)
{
    unsigned char ca, cb;
    while (*a && *b) {
        ca = (unsigned char)*a;
        cb = (unsigned char)*b;
        if (tolower(ca) != tolower(cb)) {
            return 0;
        }
        a++;
        b++;
    }
    return *a == *b;
}

static int
parse_target_kind_name(const char *name)
{
    if (name == NULL) {
        return POLICY_ENTRY_INVALID;
    }
    if (equals_ignore_case(name, "PATH")) {
        return POLICY_ENTRY_PATH;
    }
    if (equals_ignore_case(name, "DOMAIN")) {
        return POLICY_ENTRY_DOMAIN;
    }
    if (equals_ignore_case(name, "IP")) {
        return POLICY_ENTRY_IP;
    }
    if (equals_ignore_case(name, "PROTOCOL")) {
        return POLICY_ENTRY_PROTOCOL;
    }
    return POLICY_ENTRY_INVALID;
}

static PyObject *
normalize_target_value(PyObject *value, int target_kind)
{
    if (value == NULL) {
        return NULL;
    }
    switch (target_kind) {
    case POLICY_ENTRY_PATH:
        return normalize_target_path(value);
    case POLICY_ENTRY_DOMAIN:
        return normalize_domain_value(value);
    case POLICY_ENTRY_IP:
        return normalize_ip_value(value);
    case POLICY_ENTRY_PROTOCOL:
        return normalize_protocol_value(value);
    default:
        return PyUnicode_FromObject(value);
    }
}

static int append_policy_value(PyObject *list_obj, int base_kind, PyObject *value);

static int
append_policy_value_list(PyObject *list_obj, int base_kind, PyObject *sequence)
{
    PyObject *fast = PySequence_Fast(sequence, "expected a sequence");
    if (fast == NULL) {
        return -1;
    }
    Py_ssize_t len = PySequence_Fast_GET_SIZE(fast);
    PyObject **items = PySequence_Fast_ITEMS(fast);
    for (Py_ssize_t i = 0; i < len; i++) {
        if (append_policy_value(list_obj, base_kind, items[i]) < 0) {
            Py_DECREF(fast);
            return -1;
        }
    }
    Py_DECREF(fast);
    return 0;
}

static int
append_policy_value(PyObject *list_obj, int base_kind, PyObject *value)
{
    if (PyList_Check(value) || PyTuple_Check(value)) {
        return append_policy_value_list(list_obj, base_kind, value);
    }

    int kind = base_kind;
    PyObject *normalized = NULL;
    PyObject *entry = NULL;

    switch (base_kind) {
    case POLICY_ENTRY_PATH:
        normalized = normalize_path_value(value, &kind);
        break;
    case POLICY_ENTRY_DOMAIN:
        normalized = normalize_domain_value(value);
        break;
    case POLICY_ENTRY_IP:
        normalized = normalize_ip_value(value);
        break;
    case POLICY_ENTRY_PROTOCOL:
        normalized = normalize_protocol_value(value);
        break;
    case POLICY_ENTRY_SCHEME:
    case POLICY_ENTRY_HOST:
        normalized = normalize_url_value(value, base_kind);
        break;
    default:
        PyErr_SetString(PyExc_ValueError, "unsupported policy kind");
        return -1;
    }
    if (normalized == NULL) {
        return -1;
    }
    if (base_kind != POLICY_ENTRY_PATH &&
        base_kind != POLICY_ENTRY_PATH_PREFIX) {
        if (mark_wildcard_if_needed(normalized, &kind) < 0) {
            Py_DECREF(normalized);
            return -1;
        }
    }
    entry = make_policy_entry(kind, normalized);
    if (entry == NULL) {
        return -1;
    }
    if (PyList_Append(list_obj, entry) < 0) {
        Py_DECREF(entry);
        return -1;
    }
    Py_DECREF(entry);
    return 0;
}

static PyObject *
ensure_policy_tuple(AnotaSyscallObject *self, PyObject *op_name, int create)
{
    PyObject *policy = PyDict_GetItemWithError(self->path_policies, op_name);
    if (policy != NULL || PyErr_Occurred()) {
        return policy;
    }
    if (!create) {
        return NULL;
    }
    PyObject *allow_list = PyList_New(0);
    PyObject *block_list = NULL;
    PyObject *tuple = NULL;

    if (allow_list == NULL) {
        return NULL;
    }
    block_list = PyList_New(0);
    if (block_list == NULL) {
        Py_DECREF(allow_list);
        return NULL;
    }
    tuple = PyTuple_New(2);
    if (tuple == NULL) {
        Py_DECREF(allow_list);
        Py_DECREF(block_list);
        return NULL;
    }
    PyTuple_SET_ITEM(tuple, POLICY_ALLOW_INDEX, allow_list);
    PyTuple_SET_ITEM(tuple, POLICY_BLOCK_INDEX, block_list);
    if (PyDict_SetItem(self->path_policies, op_name, tuple) < 0) {
        Py_DECREF(tuple);
        return NULL;
    }
    Py_DECREF(tuple);
    return PyDict_GetItemWithError(self->path_policies, op_name);
}

static PyObject *
operation_get_policy(AnotaSyscallOperationObject *op)
{
    return ensure_policy_tuple(op->owner, op->op_name, 1);
}

static PyObject *
get_policy_if_exists(AnotaSyscallObject *self, PyObject *op_name)
{
    PyObject *policy = PyDict_GetItemWithError(self->path_policies, op_name);
    if (policy == NULL && PyErr_Occurred()) {
        return NULL;
    }
    return policy;
}

static int
policy_list_matches(PyObject *patterns,
                    int target_kind,
                    PyObject *target_value)
{
    if (target_value == NULL) {
        return 0;
    }
    Py_ssize_t size = PyList_GET_SIZE(patterns);
    for (Py_ssize_t i = 0; i < size; i++) {
        PyObject *entry = PyList_GET_ITEM(patterns, i);
        if (!PyTuple_Check(entry) || PyTuple_GET_SIZE(entry) != 2) {
            continue;
        }
        PyObject *kind_obj = PyTuple_GET_ITEM(entry, 0);
        PyObject *value_obj = PyTuple_GET_ITEM(entry, 1);
        int entry_kind_raw = (int)PyLong_AsLong(kind_obj);
        if (entry_kind_raw == -1 && PyErr_Occurred()) {
            return -1;
        }
        int wildcard = (entry_kind_raw & POLICY_ENTRY_FLAG_WILDCARD) != 0;
        int entry_kind = entry_kind_raw & POLICY_ENTRY_BASE_MASK;
        if (entry_kind == POLICY_ENTRY_PATH && target_kind == POLICY_ENTRY_PATH) {
            if (wildcard) {
                int match = unicode_match_wildcard(value_obj, target_value);
                if (match < 0) {
                    return -1;
                }
                if (match) {
                    return 1;
                }
            }
            else {
                Py_ssize_t match = PyUnicode_Tailmatch(
                    target_value, value_obj, 0, PY_SSIZE_T_MAX, +1);
                if (match < 0) {
                    return -1;
                }
                if (match) {
                    return 1;
                }
            }
        }
        else if (entry_kind == POLICY_ENTRY_PATH_PREFIX &&
                 target_kind == POLICY_ENTRY_PATH) {
            if (wildcard) {
                int match = unicode_match_wildcard(value_obj, target_value);
                if (match < 0) {
                    return -1;
                }
                if (match) {
                    return 1;
                }
            }
            else {
                Py_ssize_t match = PyUnicode_Tailmatch(
                    target_value, value_obj, 0,
                    PyUnicode_GetLength(target_value), -1);
                if (match < 0) {
                    return -1;
                }
                if (match) {
                    return 1;
                }
            }
        }
        else if (entry_kind == POLICY_ENTRY_DOMAIN &&
                 target_kind == POLICY_ENTRY_DOMAIN) {
            int match;
            if (wildcard) {
                match = unicode_match_wildcard(value_obj, target_value);
            }
            else {
                Py_ssize_t len = PyUnicode_GetLength(value_obj);
                if (len > 0 && PyUnicode_ReadChar(value_obj, 0) == '.') {
                    match = PyUnicode_Tailmatch(
                        target_value, value_obj, 0, PY_SSIZE_T_MAX, +1);
                }
                else {
                    match = PyObject_RichCompareBool(value_obj, target_value, Py_EQ);
                }
            }
            if (match < 0) {
                return -1;
            }
            if (match) {
                return 1;
            }
        }
        else if (entry_kind == POLICY_ENTRY_IP &&
                 target_kind == POLICY_ENTRY_IP) {
            int match;
            if (wildcard) {
                match = unicode_match_wildcard(value_obj, target_value);
            }
            else {
                match = PyObject_RichCompareBool(value_obj, target_value, Py_EQ);
            }
            if (match < 0) {
                return -1;
            }
            if (match) {
                return 1;
            }
        }
        else if (entry_kind == POLICY_ENTRY_PROTOCOL &&
                 target_kind == POLICY_ENTRY_PROTOCOL) {
            int match;
            if (wildcard) {
                match = unicode_match_wildcard(value_obj, target_value);
            }
            else {
                match = PyObject_RichCompareBool(value_obj, target_value, Py_EQ);
            }
            if (match < 0) {
                return -1;
            }
            if (match) {
                return 1;
            }
        }
    }
    return 0;
}

static int
report_violation(const char *syscall_name,
                 const char *operation,
                 const char *target_kind,
                 PyObject *target_text,
                 const char *detail)
{
    if (detail == NULL) {
        detail = "policy violation";
    }
    const char *kind_label = target_kind ? target_kind : "target";
    if (target_text != NULL) {
        if (operation != NULL) {
            PySys_FormatStderr(
                "ANOTA_SYSCALL violation: %s %s %s %U (%s)\n",
                operation,
                syscall_name ? syscall_name : "<unknown>",
                kind_label,
                target_text,
                detail);
        }
        else {
            PySys_FormatStderr(
                "ANOTA_SYSCALL violation: %s %s %U (%s)\n",
                syscall_name ? syscall_name : "<unknown>",
                kind_label,
                target_text,
                detail);
        }
    }
    else {
        if (operation != NULL) {
            PySys_WriteStderr(
                "ANOTA_SYSCALL violation: %s %s (%s)\n",
                operation,
                syscall_name ? syscall_name : "<unknown>",
                detail);
        }
        else {
            PySys_WriteStderr(
                "ANOTA_SYSCALL violation: %s (%s)\n",
                syscall_name ? syscall_name : "<unknown>",
                detail);
        }
    }
    return 1;
}


/* ------------------------------------------------------------------------- */
/* Operation object                                                          */

static PyObject *
operation_add_paths_impl(AnotaSyscallOperationObject *op,
                    PyObject *args,
                    PyObject *kwargs,
                    int is_allow)
{
    PyObject *policy = operation_get_policy(op);
    if (policy == NULL) {
        return NULL;
    }
    PyObject *target = PyTuple_GET_ITEM(
        policy, is_allow ? POLICY_ALLOW_INDEX : POLICY_BLOCK_INDEX);

    Py_ssize_t positional = PyTuple_GET_SIZE(args);
    PyObject *value = NULL;
    int base_kind = POLICY_ENTRY_PATH;
    if (positional > 1 || positional + (kwargs ? PyDict_GET_SIZE(kwargs) : 0) != 1) {
        PyErr_SetString(PyExc_TypeError, "provide exactly one of PATH, DOMAIN, IP, PROTOCOL, SCHEME, HOST");
        return NULL;
    }
    if (positional) value = PyTuple_GET_ITEM(args, 0);
    else {
        Py_ssize_t pos = 0;
        PyObject *name;
        PyDict_Next(kwargs, &pos, &name, &value);
        const char *key = PyUnicode_AsUTF8(name);
        if (!key) return NULL;
        if (equals_ignore_case(key, "PATH")) base_kind = POLICY_ENTRY_PATH;
        else if (equals_ignore_case(key, "DOMAIN")) base_kind = POLICY_ENTRY_DOMAIN;
        else if (equals_ignore_case(key, "IP")) base_kind = POLICY_ENTRY_IP;
        else if (equals_ignore_case(key, "PROTOCOL")) base_kind = POLICY_ENTRY_PROTOCOL;
        else if (equals_ignore_case(key, "SCHEME")) base_kind = POLICY_ENTRY_SCHEME;
        else if (equals_ignore_case(key, "HOST")) base_kind = POLICY_ENTRY_HOST;
        else { PyErr_SetString(PyExc_TypeError, "unexpected keyword argument"); return NULL; }
    }
    if (base_kind >= POLICY_ENTRY_SCHEME &&
        PyUnicode_CompareWithASCIIString(op->op_name, "NETWORK") != 0 &&
        PyUnicode_CompareWithASCIIString(op->op_name, "URL") != 0) {
        PyErr_SetString(PyExc_ValueError, "SCHEME/HOST policies require NETWORK or URL scope");
        return NULL;
    }

    if (append_policy_value(target, base_kind, value) < 0) {
        return NULL;
    }

    Py_RETURN_NONE;
}

static int
syscall_rebuild(AnotaSyscallObject *self, PyObject *skip)
{
    if (PySet_Clear(self->blocked_syscalls) < 0 || PySet_Clear(self->allowed_syscalls) < 0) return -1;
    PyDict_Clear(self->path_policies);
    for (Py_ssize_t i = 0; i < PyList_GET_SIZE(self->records); i++) {
        PyObject *r = PyList_GET_ITEM(self->records, i);
        if (r == skip || PyList_GET_ITEM(r, 0) != Py_True) continue;
        PyObject *scope = PyList_GET_ITEM(r, 1), *entries = PyList_GET_ITEM(r, 3);
        int allow = PyList_GET_ITEM(r, 2) == Py_True;
        PyObject *target = allow ? self->allowed_syscalls : self->blocked_syscalls;
        if (scope != Py_None) {
            PyObject *pair = ensure_policy_tuple(self, scope, 1);
            if (!pair) return -1;
            target = PyTuple_GET_ITEM(pair, allow ? POLICY_ALLOW_INDEX : POLICY_BLOCK_INDEX);
        }
        for (Py_ssize_t j = 0; j < PyList_GET_SIZE(entries); j++) {
            PyObject *entry = PyList_GET_ITEM(entries, j);
            int rc = scope == Py_None ? PySet_Add(target, entry) : PyList_Append(target, entry);
            if (rc < 0) return -1;
        }
    }
    return 0;
}

static int
syscall_remove(PyObject *token)
{
    AnotaSyscallObject *self = get_singleton_struct();
    PolicyBackup backup;
    if (backup_policy(self, &backup) < 0) return -1;
    PyObject *result = NULL;
    if (syscall_rebuild(self, token) == 0) { Py_INCREF(Py_None); result = Py_None; }
    result = finish_policy_change(self, &backup, result);
    if (!result) return -1;
    Py_DECREF(result);
    for (Py_ssize_t i = 0; i < PyList_GET_SIZE(self->records); i++)
        if (PyList_GET_ITEM(self->records, i) == token) return PySequence_DelItem(self->records, i);
    return 0;
}

static PyObject *
record_change(AnotaSyscallObject *self, PolicyBackup *backup,
              PyObject *scope, int allow, PyObject *entries)
{
    PyObject *token = entries ? Py_BuildValue("[OOOO]", Py_True, scope,
                                allow ? Py_True : Py_False, entries) : NULL;
    PyObject *handle = token ? _PyAnotaPolicy_New(token, syscall_remove) : NULL;
    int added = handle && PyList_Append(self->records, token) == 0;
    if (!added) Py_CLEAR(handle);
    PyObject *result = finish_policy_change(self, backup, handle);
    if (!result && added) PySequence_DelItem(self->records, PyList_GET_SIZE(self->records) - 1);
    Py_XDECREF(token);
    return result;
}

static void
invalidate_records(AnotaSyscallObject *self, PyObject *scope)
{
    for (Py_ssize_t i = PyList_GET_SIZE(self->records); i-- > 0;) {
        PyObject *r = PyList_GET_ITEM(self->records, i);
        if (scope == NULL || PyObject_RichCompareBool(scope, PyList_GET_ITEM(r, 1), Py_EQ) == 1) {
            _PyAnotaPolicy_Invalidate(r);
            PySequence_DelItem(self->records, i);
        }
    }
}

static PyObject *
operation_add_paths(AnotaSyscallOperationObject *op, PyObject *args,
                    PyObject *kwargs, int is_allow)
{
    PolicyBackup backup;
    if (backup_policy(op->owner, &backup) < 0) return NULL;
    PyObject *old = PyDict_GetItemWithError(backup.paths, op->op_name);
    int side = is_allow ? POLICY_ALLOW_INDEX : POLICY_BLOCK_INDEX;
    Py_ssize_t start = old ? PyList_GET_SIZE(PyTuple_GET_ITEM(old, side)) : 0;
    PyObject *result = operation_add_paths_impl(op, args, kwargs, is_allow);
    if (!result) return finish_policy_change(op->owner, &backup, NULL);
    Py_DECREF(result);
    PyObject *all = PyTuple_GET_ITEM(operation_get_policy(op), side);
    PyObject *entries = PyList_GetSlice(all, start, PyList_GET_SIZE(all));
    result = record_change(op->owner, &backup, op->op_name, is_allow, entries);
    Py_XDECREF(entries);
    return result;
}

static PyObject *
operation_clear(AnotaSyscallOperationObject *op, PyObject *Py_UNUSED(ignored))
{
    PolicyBackup backup;
    if (backup_policy(op->owner, &backup) < 0) return NULL;
    if (PyDict_DelItem(op->owner->path_policies, op->op_name) < 0) {
        if (PyErr_ExceptionMatches(PyExc_KeyError)) PyErr_Clear();
        else return finish_policy_change(op->owner, &backup, NULL);
    }
    Py_INCREF(Py_None);
    PyObject *result = finish_policy_change(op->owner, &backup, Py_None);
    if (result) invalidate_records(op->owner, op->op_name);
    return result;
}

static PyObject *
operation_block(AnotaSyscallOperationObject *op,
                PyObject *args,
                PyObject *kwargs)
{
    return operation_add_paths(op, args, kwargs, 0);
}

static PyObject *
operation_allow(AnotaSyscallOperationObject *op,
                PyObject *args,
                PyObject *kwargs)
{
    return operation_add_paths(op, args, kwargs, 1);
}

static PyMethodDef AnotaSyscallOperation_methods[] = {
    {"CLEAR", (PyCFunction)operation_clear, METH_NOARGS,
     PyDoc_STR("Clear policies for this operation and synchronize the monitor.")},
    {"BLOCK", (PyCFunction)(void(*)(void))operation_block,
     METH_VARARGS | METH_KEYWORDS,
     PyDoc_STR("BLOCK(PATH=..., DOMAIN=..., IP=..., PROTOCOL=...)\n"
               "Add entries to the block list for this syscall class.\n"
               "Each field accepts '*' wildcards for pattern matching.")},
    {"ALLOW", (PyCFunction)(void(*)(void))operation_allow,
     METH_VARARGS | METH_KEYWORDS,
     PyDoc_STR("ALLOW(PATH=..., DOMAIN=..., IP=..., PROTOCOL=...)\n"
               "Restrict this syscall class to the provided allow list.\n"
               "Each field accepts '*' wildcards for pattern matching.")},
    {NULL, NULL}
};

static void
operation_dealloc(AnotaSyscallOperationObject *op)
{
    Py_XDECREF(op->owner);
    Py_XDECREF(op->op_name);
    PyObject_Del(op);
}

static PyTypeObject AnotaSyscallOperation_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "ANOTA_SYSCALL_OPERATION",      /* tp_name */
    sizeof(AnotaSyscallOperationObject), /* tp_basicsize */
    0,                              /* tp_itemsize */
    (destructor)operation_dealloc,  /* tp_dealloc */
    0,                              /* tp_vectorcall_offset */
    0,                              /* tp_getattr */
    0,                              /* tp_setattr */
    0,                              /* tp_as_async */
    0,                              /* tp_repr */
    0,                              /* tp_as_number */
    0,                              /* tp_as_sequence */
    0,                              /* tp_as_mapping */
    0,                              /* tp_hash */
    0,                              /* tp_call */
    0,                              /* tp_str */
    PyObject_GenericGetAttr,        /* tp_getattro */
    0,                              /* tp_setattro */
    0,                              /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT,             /* tp_flags */
    "Per-operation policy controller used by ANOTA_SYSCALL", /* tp_doc */
    0,                              /* tp_traverse */
    0,                              /* tp_clear */
    0,                              /* tp_richcompare */
    0,                              /* tp_weaklistoffset */
    0,                              /* tp_iter */
    0,                              /* tp_iternext */
    AnotaSyscallOperation_methods,  /* tp_methods */
};


/* ------------------------------------------------------------------------- */
/* Policy object                                                             */

static PyObject *
anota_syscall_block_impl(AnotaSyscallObject *self, PyObject *args)
{
    Py_ssize_t nargs = PyTuple_GET_SIZE(args);
    if (nargs == 0) {
        PyErr_SetString(PyExc_TypeError,
                        "BLOCK() requires at least one syscall name");
        return NULL;
    }
    for (Py_ssize_t i = 0; i < nargs; i++) {
        PyObject *item = PyTuple_GET_ITEM(args, i);
        if (update_name_set(self->blocked_syscalls, item) < 0) {
            return NULL;
        }
    }
    Py_RETURN_NONE;
}

static PyObject *
anota_syscall_allow_impl(AnotaSyscallObject *self, PyObject *args)
{
    Py_ssize_t nargs = PyTuple_GET_SIZE(args);
    if (nargs == 0) {
        PyErr_SetString(PyExc_TypeError,
                        "ALLOW() requires at least one syscall name");
        return NULL;
    }
    for (Py_ssize_t i = 0; i < nargs; i++) {
        PyObject *item = PyTuple_GET_ITEM(args, i);
        if (update_name_set(self->allowed_syscalls, item) < 0) {
            return NULL;
        }
    }
    Py_RETURN_NONE;
}

static PyObject *
anota_syscall_clear_impl(AnotaSyscallObject *self, PyObject *Py_UNUSED(ignored))
{
    if (PySet_Clear(self->blocked_syscalls) < 0) {
        return NULL;
    }
    if (PySet_Clear(self->allowed_syscalls) < 0) {
        return NULL;
    }
    PyDict_Clear(self->path_policies);
    Py_RETURN_NONE;
}

static PyObject *
add_global(AnotaSyscallObject *self, PyObject *args, int allow)
{
    PolicyBackup backup;
    if (backup_policy(self, &backup) < 0) return NULL;
    PyObject *result = allow ? anota_syscall_allow_impl(self, args) : anota_syscall_block_impl(self, args);
    if (!result) return finish_policy_change(self, &backup, NULL);
    Py_DECREF(result);
    PyObject *entries = PyList_New(0);
    if (entries) {
        for (Py_ssize_t i = 0; i < PyTuple_GET_SIZE(args); i++) {
            PyObject *name = normalize_syscall_name(PyTuple_GET_ITEM(args, i));
            if (!name || PyList_Append(entries, name) < 0) {
                Py_XDECREF(name); Py_CLEAR(entries); break;
            }
            Py_DECREF(name);
        }
    }
    result = record_change(self, &backup, Py_None, allow, entries);
    Py_XDECREF(entries);
    return result;
}
static PyObject *anota_syscall_block(AnotaSyscallObject *self, PyObject *args)
{ return add_global(self, args, 0); }
static PyObject *anota_syscall_allow(AnotaSyscallObject *self, PyObject *args)
{ return add_global(self, args, 1); }

static PyObject *
anota_syscall_clear(AnotaSyscallObject *self, PyObject *args)
{
    PolicyBackup backup;
    if (backup_policy(self, &backup) < 0) return NULL;
    PyObject *result = finish_policy_change(self, &backup, anota_syscall_clear_impl(self, args));
    if (result) invalidate_records(self, NULL);
    return result;
}

static PyMethodDef AnotaSyscall_methods[] = {
    {"CLEAR", (PyCFunction)anota_syscall_clear, METH_NOARGS,
     PyDoc_STR("Clear all syscall policies and synchronize the monitor.")},
    {"BLOCK", (PyCFunction)anota_syscall_block, METH_VARARGS,
     PyDoc_STR("BLOCK(name, ...)\n"
               "Block the named syscalls regardless of arguments.")},
    {"ALLOW", (PyCFunction)anota_syscall_allow, METH_VARARGS,
     PyDoc_STR("ALLOW(name, ...)\n"
               "Whitelist the named syscalls (others will be denied).")},
    {"clear", (PyCFunction)anota_syscall_clear, METH_NOARGS,
     PyDoc_STR("Clear all syscall policies.")},
    {NULL, NULL}
};

static void
anota_syscall_dealloc(AnotaSyscallObject *self)
{
    Py_XDECREF(self->records);
    Py_XDECREF(self->blocked_syscalls);
    Py_XDECREF(self->allowed_syscalls);
    Py_XDECREF(self->path_policies);
    Py_XDECREF(self->operation_cache);
    PyObject_Del(self);
}

static PyObject *
create_operation_object(AnotaSyscallObject *self, PyObject *attr)
{
    AnotaSyscallOperationObject *op =
        PyObject_New(AnotaSyscallOperationObject, &AnotaSyscallOperation_Type);
    if (op == NULL) {
        return NULL;
    }
    PyObject *upper = PyObject_CallMethod(attr, "upper", NULL);
    if (upper == NULL) {
        PyObject_Del(op);
        return NULL;
    }
    Py_INCREF(self);
    op->owner = self;
    op->op_name = upper;
    return (PyObject *)op;
}

static PyObject *
anota_syscall_getattro(PyObject *self_obj, PyObject *attr)
{
    PyObject *result = PyObject_GenericGetAttr(self_obj, attr);
    if (result != NULL || !PyErr_ExceptionMatches(PyExc_AttributeError)) {
        return result;
    }
    PyErr_Clear();
    if (!PyUnicode_Check(attr)) {
        PyErr_SetObject(PyExc_AttributeError, attr);
        return NULL;
    }
    AnotaSyscallObject *self = (AnotaSyscallObject *)self_obj;
    PyObject *cached = PyDict_GetItemWithError(self->operation_cache, attr);
    if (cached != NULL) {
        Py_INCREF(cached);
        return cached;
    }
    if (PyErr_Occurred()) {
        return NULL;
    }
    PyObject *op = create_operation_object(self, attr);
    if (op == NULL) {
        return NULL;
    }
    if (PyDict_SetItem(self->operation_cache, attr, op) < 0) {
        Py_DECREF(op);
        return NULL;
    }
    return op;
}

static PyTypeObject AnotaSyscall_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "ANOTA_SYSCALL",                /* tp_name */
    sizeof(AnotaSyscallObject),     /* tp_basicsize */
    0,                              /* tp_itemsize */
    (destructor)anota_syscall_dealloc, /* tp_dealloc */
    0,                              /* tp_vectorcall_offset */
    0,                              /* tp_getattr */
    0,                              /* tp_setattr */
    0,                              /* tp_as_async */
    0,                              /* tp_repr */
    0,                              /* tp_as_number */
    0,                              /* tp_as_sequence */
    0,                              /* tp_as_mapping */
    0,                              /* tp_hash */
    0,                              /* tp_call */
    0,                              /* tp_str */
    anota_syscall_getattro,         /* tp_getattro */
    0,                              /* tp_setattro */
    0,                              /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT,             /* tp_flags */
    "ANOTA_SYSCALL policy controller", /* tp_doc */
    0,                              /* tp_traverse */
    0,                              /* tp_clear */
    0,                              /* tp_richcompare */
    0,                              /* tp_weaklistoffset */
    0,                              /* tp_iter */
    0,                              /* tp_iternext */
    AnotaSyscall_methods,           /* tp_methods */
};


/* ------------------------------------------------------------------------- */
/* Public entry points                                                       */

PyObject *
_PyAnotaSyscall_GetSingleton(void)
{
    if (anota_syscall_singleton != NULL) {
        Py_INCREF(anota_syscall_singleton);
        return anota_syscall_singleton;
    }

    if (PyType_Ready(&AnotaSyscallOperation_Type) < 0) {
        return NULL;
    }
    if (PyType_Ready(&AnotaSyscall_Type) < 0) {
        return NULL;
    }

    AnotaSyscallObject *self =
        PyObject_New(AnotaSyscallObject, &AnotaSyscall_Type);
    if (self == NULL) {
        return NULL;
    }

    self->blocked_syscalls = PySet_New(NULL);
    if (self->blocked_syscalls == NULL) {
        PyObject_Del(self);
        return NULL;
    }
    self->allowed_syscalls = PySet_New(NULL);
    if (self->allowed_syscalls == NULL) {
        Py_DECREF(self->blocked_syscalls);
        PyObject_Del(self);
        return NULL;
    }
    self->path_policies = PyDict_New();
    if (self->path_policies == NULL) {
        Py_DECREF(self->blocked_syscalls);
        Py_DECREF(self->allowed_syscalls);
        PyObject_Del(self);
        return NULL;
    }
    self->operation_cache = PyDict_New();
    if (self->operation_cache == NULL) {
        Py_DECREF(self->blocked_syscalls);
        Py_DECREF(self->allowed_syscalls);
        Py_DECREF(self->path_policies);
        PyObject_Del(self);
        return NULL;
    }

    self->records = PyList_New(0);
    if (!self->records) { Py_DECREF(self); return NULL; }
    anota_syscall_singleton = (PyObject *)self;
    Py_INCREF(anota_syscall_singleton);
    return anota_syscall_singleton;
}

int
_PyAnotaSyscall_Check(const char *syscall_name,
                      PyObject *target_obj,
                      const char *operation,
                      const char *target_kind_name)
{
    /* Kernel events are authoritative in eBPF mode. Avoid duplicate wrapper
       diagnostics and recursion while serializing control messages. */
    if (monitor_enabled || monitor_syncing) return 0;

    AnotaSyscallObject *self = get_singleton_struct();
    if (self == NULL) {
        return 0;
    }

    PyObject *target_text = NULL;
    PyObject *syscall_key = NULL;
    PyObject *operation_key = NULL;
    PyObject *policy = NULL;
    PyObject *allow_list = NULL;
    PyObject *block_list = NULL;
    const char *reason = NULL;
    int status = 0;
    int target_kind = parse_target_kind_name(target_kind_name);

    if (target_obj != NULL) {
        target_text = normalize_target_value(target_obj, target_kind);
        if (target_text == NULL) {
            goto error;
        }
    }

    syscall_key = normalize_c_name(syscall_name);
    if (syscall_name != NULL && syscall_key == NULL) {
        goto error;
    }

    if (operation != NULL) {
        operation_key = normalize_c_name(operation);
        if (operation_key == NULL) {
            goto error;
        }
        policy = get_policy_if_exists(self, operation_key);
        if (policy == NULL && PyErr_Occurred()) {
            goto error;
        }
        if (policy != NULL) {
            allow_list = PyTuple_GET_ITEM(policy, POLICY_ALLOW_INDEX);
            block_list = PyTuple_GET_ITEM(policy, POLICY_BLOCK_INDEX);
        }
    }

    if (allow_list != NULL && PyList_GET_SIZE(allow_list) > 0) {
        if (target_text == NULL) {
            reason = "target required for allow list";
            goto violation;
        }
        int allow_match = policy_list_matches(
            allow_list, target_kind, target_text);
        if (allow_match < 0) {
            goto error;
        }
        if (allow_match == 1) {
            goto success;
        }
        reason = "target not in allow list";
        goto violation;
    }

    if (block_list != NULL && PyList_GET_SIZE(block_list) > 0 &&
        target_text != NULL) {
        int block_match = policy_list_matches(
            block_list, target_kind, target_text);
        if (block_match < 0) {
            goto error;
        }
        if (block_match == 1) {
            reason = "target blocked";
            goto violation;
        }
    }

    if (syscall_key != NULL) {
        int blocked = PySet_Contains(self->blocked_syscalls, syscall_key);
        if (blocked < 0) {
            goto error;
        }
        if (blocked) {
            reason = "syscall blocked";
            goto violation;
        }
        Py_ssize_t allow_size = PySet_Size(self->allowed_syscalls);
        if (allow_size < 0) {
            goto error;
        }
        if (allow_size > 0) {
            int allowed = PySet_Contains(self->allowed_syscalls, syscall_key);
            if (allowed < 0) {
                goto error;
            }
            if (!allowed) {
                reason = "syscall not in allow list";
                goto violation;
            }
        }
    }

success:
    status = 0;
    goto cleanup;

violation:
    status = report_violation(syscall_name, operation,
                              target_kind_name, target_text, reason);
    goto cleanup;

error:
    status = -1;

cleanup:
    Py_XDECREF(target_text);
    Py_XDECREF(syscall_key);
    Py_XDECREF(operation_key);
    return status;
}

PyObject *
_PyAnotaSyscall_SignalStart(PyObject *Py_UNUSED(self), PyObject *args, PyObject *kwargs)
{
    static char *kwlist[] = {"pid", NULL};
    PyObject *pid_obj = Py_None;
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|O:ANOTA_SYSCALL_SIGNAL_START",
                                    kwlist, &pid_obj)) return NULL;
#ifndef MS_WINDOWS
    long pid = pid_obj == Py_None ? (long)getpid() : PyLong_AsLong(pid_obj);
    if (pid == -1 && PyErr_Occurred()) return NULL;
    if (pid <= 0 || (unsigned long)pid > 0xffffffffUL) {
        PyErr_SetString(PyExc_ValueError, "pid must be a positive 32-bit process id");
        return NULL;
    }
    if (sync_policy(get_singleton_struct(), pid, "replace") < 0) return NULL;
    Py_RETURN_NONE;
#else
    PyErr_SetString(PyExc_NotImplementedError, "Aya syscall monitoring requires Linux");
    return NULL;
#endif
}

PyObject *
_PyAnotaSyscall_SignalStop(PyObject *Py_UNUSED(self), PyObject *Py_UNUSED(ignored))
{
#ifndef MS_WINDOWS
    if (sync_policy(get_singleton_struct(), (monitor_enabled && monitor_origin_pid == (long)getpid())
        ? monitor_target_pid : (long)getpid(), "stop") < 0) return NULL;
    Py_RETURN_NONE;
#else
    PyErr_SetString(PyExc_NotImplementedError, "Aya syscall monitoring requires Linux");
    return NULL;
#endif
}

int
_PyAnotaSyscall_ClearAll(void)
{
    AnotaSyscallObject *self = get_singleton_struct();
    if (!self) return 0;
    PyObject *result = anota_syscall_clear(self, NULL);
    if (!result) return -1;
    Py_DECREF(result);
    return 0;
}

static int
url_kind_present(PyObject *rules, int kind)
{
    for (Py_ssize_t i = 0; i < PyList_GET_SIZE(rules); i++) {
        PyObject *entry = PyList_GET_ITEM(rules, i);
        if ((PyLong_AsLong(PyTuple_GET_ITEM(entry, 0)) & POLICY_ENTRY_BASE_MASK) == kind) return 1;
    }
    return 0;
}

static int
url_matches(PyObject *rules, int kind, PyObject *value)
{
    for (Py_ssize_t i = 0; i < PyList_GET_SIZE(rules); i++) {
        PyObject *entry = PyList_GET_ITEM(rules, i);
        if ((PyLong_AsLong(PyTuple_GET_ITEM(entry, 0)) & POLICY_ENTRY_BASE_MASK) != kind) continue;
        int rc = unicode_match_wildcard(PyTuple_GET_ITEM(entry, 1), value);
        if (rc != 0) return rc;
    }
    return 0;
}

PyObject *
_PyAnotaSyscall_URLActive(PyObject *self_obj, PyObject *unused)
{
    AnotaSyscallObject *self = get_singleton_struct();
    if (!self || monitor_syncing) Py_RETURN_FALSE;
    Py_ssize_t pos = 0;
    PyObject *key, *pair;
    while (PyDict_Next(self->path_policies, &pos, &key, &pair))
        for (int i = 0; i < 2; i++)
            if (url_kind_present(PyTuple_GET_ITEM(pair, i), POLICY_ENTRY_SCHEME) ||
                url_kind_present(PyTuple_GET_ITEM(pair, i), POLICY_ENTRY_HOST)) Py_RETURN_TRUE;
    Py_RETURN_FALSE;
}

PyObject *
_PyAnotaSyscall_CheckURL(PyObject *self_obj, PyObject *args)
{
    PyObject *scheme, *host;
    if (!PyArg_ParseTuple(args, "UU:_ANOTA_CHECK_URL", &scheme, &host)) return NULL;
    AnotaSyscallObject *self = get_singleton_struct();
    if (!self || monitor_syncing) Py_RETURN_NONE;
    const char *scopes[] = {"NETWORK", "URL"};
    for (int scope = 0; scope < 2; scope++) {
        PyObject *pair = PyDict_GetItemString(self->path_policies, scopes[scope]);
        if (!pair) continue;
        PyObject *allow = PyTuple_GET_ITEM(pair, 0), *block = PyTuple_GET_ITEM(pair, 1);
        for (int kind = POLICY_ENTRY_SCHEME; kind <= POLICY_ENTRY_HOST; kind++) {
            PyObject *value = kind == POLICY_ENTRY_SCHEME ? scheme : host;
            int denied = url_matches(block, kind, value);
            if (denied < 0) return NULL;
            const char *reason = denied ? "target blocked" : NULL;
            if (!denied && url_kind_present(allow, kind)) {
                int allowed = url_matches(allow, kind, value);
                if (allowed < 0) return NULL;
                if (!allowed) reason = "target not in allow list";
            }
            if (reason) report_violation("URL", scopes[scope],
                            kind == POLICY_ENTRY_SCHEME ? "SCHEME" : "HOST", value, reason);
        }
    }
    Py_RETURN_NONE;
}

int
_PyAnotaSyscall_IsController(PyObject *obj)
{ return Py_TYPE(obj) == &AnotaSyscall_Type || Py_TYPE(obj) == &AnotaSyscallOperation_Type; }
