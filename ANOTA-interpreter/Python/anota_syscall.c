#include "Python.h"
#include <ctype.h>
#include <string.h>
#include "anota_syscall.h"

#ifndef MS_WINDOWS
#  include <sys/types.h>
#  include <sys/socket.h>
#  include <sys/un.h>
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
} PolicyEntryKind;

#define POLICY_ENTRY_BASE_MASK 0xFF
#define POLICY_ENTRY_FLAG_WILDCARD 0x100

#ifndef ANOTA_SYSCALL_SOCKET_PATH
#  define ANOTA_SYSCALL_SOCKET_PATH "/tmp/anota_syscall.sock"
#endif

static int
send_monitor_command(const char *command, Py_ssize_t length)
{
#ifndef MS_WINDOWS
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        PyErr_SetFromErrno(PyExc_OSError);
        return -1;
    }
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    size_t path_len = strlen(ANOTA_SYSCALL_SOCKET_PATH);
    if (path_len >= sizeof(addr.sun_path)) {
        close(fd);
        PyErr_SetString(PyExc_RuntimeError,
                        "ANOTA_SYSCALL socket path is too long");
        return -1;
    }
    memcpy(addr.sun_path, ANOTA_SYSCALL_SOCKET_PATH, path_len + 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        PyErr_SetFromErrnoWithFilename(PyExc_OSError,
                                       ANOTA_SYSCALL_SOCKET_PATH);
        return -1;
    }

    const char *cursor = command;
    Py_ssize_t remaining = length;
    while (remaining > 0) {
        ssize_t wrote = send(fd, cursor, remaining, 0);
        if (wrote < 0) {
            if (errno == EINTR) {
                continue;
            }
            close(fd);
            PyErr_SetFromErrno(PyExc_OSError);
            return -1;
        }
        cursor += wrote;
        remaining -= wrote;
    }

    /* Best-effort read response (ignored). */
    char response[64];
    (void)recv(fd, response, sizeof(response), 0);
    close(fd);
    return 0;
#else
    PyErr_SetString(PyExc_NotImplementedError,
                    "ANOTA_SYSCALL_SIGNAL_* is only available on Unix platforms");
    return -1;
#endif
}

typedef struct {
    PyObject_HEAD
    PyObject *blocked_syscalls;   /* set of uppercase syscall names */
    PyObject *allowed_syscalls;   /* set of uppercase syscall names */
    PyObject *path_policies;      /* dict: op_name -> (allow_list, block_list) */
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
operation_add_paths(AnotaSyscallOperationObject *op,
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
    PyObject *path_kw = NULL;
    PyObject *domain_kw = NULL;
    PyObject *ip_kw = NULL;
    PyObject *proto_kw = NULL;
    int base_kind = POLICY_ENTRY_PATH;

    if (positional > 1) {
        PyErr_SetString(PyExc_TypeError,
                        "ANOTA_SYSCALL operation methods accept at most 1 "
                        "positional argument");
        return NULL;
    }

    if (kwargs != NULL && PyDict_Size(kwargs) > 0) {
        PyObject *tmp_lower, *tmp_upper;

        tmp_lower = PyDict_GetItemString(kwargs, "path");
        tmp_upper = PyDict_GetItemString(kwargs, "PATH");
        if (tmp_lower && tmp_upper && tmp_lower != tmp_upper) {
            PyErr_SetString(PyExc_TypeError,
                            "PATH specified multiple times");
            return NULL;
        }
        path_kw = tmp_lower ? tmp_lower : tmp_upper;

        tmp_lower = PyDict_GetItemString(kwargs, "domain");
        tmp_upper = PyDict_GetItemString(kwargs, "DOMAIN");
        if (tmp_lower && tmp_upper && tmp_lower != tmp_upper) {
            PyErr_SetString(PyExc_TypeError,
                            "DOMAIN specified multiple times");
            return NULL;
        }
        domain_kw = tmp_lower ? tmp_lower : tmp_upper;

        tmp_lower = PyDict_GetItemString(kwargs, "ip");
        tmp_upper = PyDict_GetItemString(kwargs, "IP");
        if (tmp_lower && tmp_upper && tmp_lower != tmp_upper) {
            PyErr_SetString(PyExc_TypeError,
                            "IP specified multiple times");
            return NULL;
        }
        ip_kw = tmp_lower ? tmp_lower : tmp_upper;

        tmp_lower = PyDict_GetItemString(kwargs, "protocol");
        tmp_upper = PyDict_GetItemString(kwargs, "PROTOCOL");
        if (tmp_lower && tmp_upper && tmp_lower != tmp_upper) {
            PyErr_SetString(PyExc_TypeError,
                            "PROTOCOL specified multiple times");
            return NULL;
        }
        proto_kw = tmp_lower ? tmp_lower : tmp_upper;

        Py_ssize_t expected = 0;
        if (path_kw) {
            expected++;
        }
        if (domain_kw) {
            expected++;
        }
        if (ip_kw) {
            expected++;
        }
        if (proto_kw) {
            expected++;
        }
        if (PyDict_Size(kwargs) > expected) {
            PyErr_SetString(PyExc_TypeError,
                            "unexpected keyword argument");
            return NULL;
        }
    }

    int provided = (positional > 0) +
                   (path_kw ? 1 : 0) +
                   (domain_kw ? 1 : 0) +
                   (ip_kw ? 1 : 0) +
                   (proto_kw ? 1 : 0);

    if (provided == 0) {
        PyErr_SetString(PyExc_TypeError,
                        "one of PATH, DOMAIN, IP, or PROTOCOL must be provided");
        return NULL;
    }
    if (provided > 1) {
        PyErr_SetString(PyExc_TypeError,
                        "provide only one of PATH, DOMAIN, IP, or PROTOCOL");
        return NULL;
    }

    if (positional == 1) {
        value = PyTuple_GET_ITEM(args, 0);
        base_kind = POLICY_ENTRY_PATH;
    }
    else if (path_kw) {
        value = path_kw;
        base_kind = POLICY_ENTRY_PATH;
    }
    else if (domain_kw) {
        value = domain_kw;
        base_kind = POLICY_ENTRY_DOMAIN;
    }
    else if (ip_kw) {
        value = ip_kw;
        base_kind = POLICY_ENTRY_IP;
    }
    else {
        value = proto_kw;
        base_kind = POLICY_ENTRY_PROTOCOL;
    }

    if (append_policy_value(target, base_kind, value) < 0) {
        return NULL;
    }

    Py_RETURN_NONE;
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
anota_syscall_block(AnotaSyscallObject *self, PyObject *args)
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
anota_syscall_allow(AnotaSyscallObject *self, PyObject *args)
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
anota_syscall_clear(AnotaSyscallObject *self, PyObject *Py_UNUSED(ignored))
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

static PyMethodDef AnotaSyscall_methods[] = {
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
_PyAnotaSyscall_SignalStart(PyObject *Py_UNUSED(self),
                            PyObject *args,
                            PyObject *kwds)
{
    PyObject *pid_obj = Py_None;
    static char *kwlist[] = {"pid", NULL};
    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                                     "|O:ANOTA_SYSCALL_SIGNAL_START",
                                     kwlist, &pid_obj)) {
        return NULL;
    }

    Py_ssize_t pid = 0;
    int has_pid = 0;
    if (!Py_IsNone(pid_obj)) {
        pid = PyLong_AsSsize_t(pid_obj);
        if (pid == -1 && PyErr_Occurred()) {
            return NULL;
        }
        if (pid < 0) {
            PyErr_SetString(PyExc_ValueError,
                            "pid must be greater than or equal to 0");
            return NULL;
        }
        has_pid = 1;
    }

    char buffer[64];
    Py_ssize_t length;
    if (has_pid) {
        length = PyOS_snprintf(buffer, sizeof(buffer),
                               "START %zd\n", pid);
        if (length < 0 || length >= (Py_ssize_t)sizeof(buffer)) {
            PyErr_SetString(PyExc_OverflowError,
                            "pid is too large");
            return NULL;
        }
    }
    else {
        strcpy(buffer, "START\n");
        length = (Py_ssize_t)strlen(buffer);
    }

    if (send_monitor_command(buffer, length) < 0) {
        return NULL;
    }
    Py_RETURN_NONE;
}

PyObject *
_PyAnotaSyscall_SignalStop(PyObject *Py_UNUSED(self), PyObject *Py_UNUSED(ignored))
{
    static const char stop_cmd[] = "STOP\n";
    if (send_monitor_command(stop_cmd, (Py_ssize_t)strlen(stop_cmd)) < 0) {
        return NULL;
    }
    Py_RETURN_NONE;
}
