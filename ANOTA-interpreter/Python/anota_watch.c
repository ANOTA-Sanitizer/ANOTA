#include "Python.h"
#include "anota_watch.h"
#include "methodobject.h"
#include "pycore_pystate.h"   // _PyThreadState_GET()
#include "pycore_pyerrors.h"  // _PyErr_SetString
#include <math.h>
#include <time.h>
#include <string.h>

#if defined(__linux__) && defined(__x86_64__)
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

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

#ifndef CLOCK_MONOTONIC_RAW
#define CLOCK_MONOTONIC_RAW CLOCK_MONOTONIC
#endif

typedef struct {
    double mean[2];
    double m2[2];
    double n[2];
} AnotaConTTest;

#if defined(__linux__) && defined(__x86_64__)
typedef struct {
    uintptr_t address;
    unsigned long long dr7;
} AnotaNativeWatchSpec;

typedef struct {
    int kind;
    int signal_no;
    int slot;
    int error_no;
    unsigned long long dr6;
    unsigned long long address;
} AnotaNativeWatchMessage;

#define ANOTA_NATIVE_MSG_READY 1
#define ANOTA_NATIVE_MSG_EVENT 2
#define ANOTA_NATIVE_MSG_DONE 3
#define ANOTA_NATIVE_MSG_ERROR 4
#endif

static int anota_native_watch_depth = 0;


/* --- helpers ---------------------------------------------------------- */

static inline AnotaWatchObject *
get_singleton_struct(void)
{
    return (AnotaWatchObject *)anota_singleton;
}

static inline int
anota_native_watch_reentrant(void)
{
    return anota_native_watch_depth > 0;
}

static void
anota_con_t_init(AnotaConTTest *ctx)
{
    ctx->mean[0] = ctx->mean[1] = 0.0;
    ctx->m2[0] = ctx->m2[1] = 0.0;
    ctx->n[0] = ctx->n[1] = 0.0;
}

static void
anota_con_t_push(AnotaConTTest *ctx, double x, int clazz)
{
    double delta;

    ctx->n[clazz] += 1.0;
    delta = x - ctx->mean[clazz];
    ctx->mean[clazz] += delta / ctx->n[clazz];
    ctx->m2[clazz] += delta * (x - ctx->mean[clazz]);
}

static double
anota_con_t_compute(AnotaConTTest *ctx)
{
    double var0;
    double var1;
    double den;

    if (ctx->n[0] < 2.0 || ctx->n[1] < 2.0) {
        return 0.0;
    }

    var0 = ctx->m2[0] / (ctx->n[0] - 1.0);
    var1 = ctx->m2[1] / (ctx->n[1] - 1.0);
    den = sqrt(var0 / ctx->n[0] + var1 / ctx->n[1]);
    if (den == 0.0) {
        return 0.0;
    }
    return (ctx->mean[0] - ctx->mean[1]) / den;
}

static long long
anota_con_now_ns(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC_RAW, &ts) != 0) {
        return -1;
    }
    return (long long)ts.tv_sec * 1000000000LL + (long long)ts.tv_nsec;
}

static PyObject *
normalize_call_args(PyObject *obj)
{
    if (PyTuple_Check(obj)) {
        Py_INCREF(obj);
        return obj;
    }
    return PyTuple_Pack(1, obj);
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

static int
anota_object_blocks_mode(PyObject *obj, unsigned char mode_bit)
{
    AnotaWatchObject *aw;
    PyObject *policies;
    int r;

    if (anota_singleton == NULL) {
        return 0;
    }

    aw = get_singleton_struct();
    if (aw == NULL || aw->policies == NULL) {
        return 0;
    }
    policies = aw->policies;
    if (!PyDict_CheckExact(policies) || PyDict_GET_SIZE(policies) == 0) {
        return 0;
    }

    r = decide_for_entry(policies, obj, NULL, mode_bit);
    if (r == -2) {
        return -1;
    }
    return r == -1;
}

static int
anota_watch_size(Py_ssize_t size)
{
    if (size >= 8) {
        return 8;
    }
    if (size >= 4) {
        return 4;
    }
    if (size >= 2) {
        return 2;
    }
    if (size >= 1) {
        return 1;
    }
    return 0;
}

static int
anota_native_region_for_object(PyObject *obj, void **address, Py_ssize_t *size)
{
    if (PyByteArray_Check(obj)) {
        Py_ssize_t n = PyByteArray_GET_SIZE(obj);
        if (n <= 0) {
            return 0;
        }
        *address = (void *)PyByteArray_AS_STRING(obj);
        *size = anota_watch_size(n);
        return *size > 0;
    }

    if (PyBytes_Check(obj)) {
        Py_ssize_t n = PyBytes_GET_SIZE(obj);
        if (n <= 0) {
            return 0;
        }
        *address = (void *)PyBytes_AS_STRING(obj);
        *size = anota_watch_size(n);
        return *size > 0;
    }

    return 0;
}

static void
anota_native_watch_guard_clear(_PyAnotaNativeWatchGuard *guard)
{
    int i;

    if (guard == NULL) {
        return;
    }

    if (guard->read_fd >= 0) {
        close(guard->read_fd);
        guard->read_fd = -1;
    }

    for (i = 0; i < guard->spec_count; i++) {
        Py_CLEAR(guard->objects[i]);
        guard->addresses[i] = NULL;
        guard->sizes[i] = 0;
    }

    guard->spec_count = 0;
    guard->tracer_pid = 0;
    guard->active = 0;
}

static int
anota_native_watch_guard_add(_PyAnotaNativeWatchGuard *guard, PyObject *obj)
{
    int blocked;
    void *address = NULL;
    Py_ssize_t size = 0;
    int i;

    if (guard->spec_count >= Py_ANOTA_NATIVE_WATCH_MAX_SPECS) {
        return 0;
    }
    if (obj == NULL || PyModule_Check(obj)) {
        return 0;
    }

    blocked = anota_object_blocks_mode(obj, ANOTA_MODE_W);
    if (blocked < 0) {
        return -1;
    }
    if (!blocked) {
        return 0;
    }

    if (!anota_native_region_for_object(obj, &address, &size)) {
        return 0;
    }

    for (i = 0; i < guard->spec_count; i++) {
        if (guard->objects[i] == obj || guard->addresses[i] == address) {
            return 0;
        }
    }

    Py_INCREF(obj);
    guard->objects[guard->spec_count] = obj;
    guard->addresses[guard->spec_count] = address;
    guard->sizes[guard->spec_count] = size;
    guard->spec_count++;
    return 0;
}

#if defined(__linux__) && defined(__x86_64__)
static int
anota_native_write_message(int fd, const AnotaNativeWatchMessage *msg)
{
    const char *buf = (const char *)msg;
    size_t remaining = sizeof(*msg);

    while (remaining > 0) {
        ssize_t written = write(fd, buf, remaining);
        if (written < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        buf += written;
        remaining -= (size_t)written;
    }
    return 0;
}

static int
anota_native_read_message(int fd, AnotaNativeWatchMessage *msg)
{
    char *buf = (char *)msg;
    size_t remaining = sizeof(*msg);

    while (remaining > 0) {
        ssize_t nread = read(fd, buf, remaining);
        if (nread == 0) {
            return 0;
        }
        if (nread < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        buf += nread;
        remaining -= (size_t)nread;
    }
    return 1;
}

static long
anota_native_ptrace(int request, pid_t pid, void *addr, void *data)
{
    errno = 0;
    long result = ptrace(request, pid, addr, data);
    if (result == -1 && errno != 0) {
        return -1;
    }
    return result;
}

static unsigned long long
anota_native_encode_dr7(int slot, Py_ssize_t size)
{
    unsigned long long dr7 = 0;
    unsigned long long len_bits;

    switch (size) {
    case 1:
        len_bits = 0x0;
        break;
    case 2:
        len_bits = 0x1;
        break;
    case 4:
        len_bits = 0x3;
        break;
    case 8:
        len_bits = 0x2;
        break;
    default:
        return 0;
    }

    dr7 |= 1ULL << (slot * 2);
    dr7 |= 0x1ULL << (16 + slot * 4);
    dr7 |= len_bits << (18 + slot * 4);
    return dr7;
}

static int
anota_native_wait_for_stop(pid_t pid, int *status)
{
    int rc;

    do {
        rc = waitpid(pid, status, 0);
    } while (rc < 0 && errno == EINTR);
    return rc == pid ? 0 : -1;
}

static void
anota_native_trace_parent(pid_t parent_pid,
                          int write_fd,
                          const AnotaNativeWatchSpec *specs,
                          int spec_count)
{
    AnotaNativeWatchMessage msg;
    unsigned long long dr7 = 0;
    int status;
    int i;

    memset(&msg, 0, sizeof(msg));

    if (anota_native_ptrace(PTRACE_ATTACH, parent_pid, NULL, NULL) < 0) {
        msg.kind = ANOTA_NATIVE_MSG_ERROR;
        msg.error_no = errno;
        (void)anota_native_write_message(write_fd, &msg);
        _exit(1);
    }

    if (anota_native_wait_for_stop(parent_pid, &status) < 0 || !WIFSTOPPED(status)) {
        msg.kind = ANOTA_NATIVE_MSG_ERROR;
        msg.error_no = errno ? errno : ECHILD;
        (void)anota_native_write_message(write_fd, &msg);
        _exit(1);
    }

    for (i = 0; i < spec_count; i++) {
        if (anota_native_ptrace(PTRACE_POKEUSER, parent_pid,
                                (void *)offsetof(struct user, u_debugreg[i]),
                                (void *)specs[i].address) < 0) {
            msg.kind = ANOTA_NATIVE_MSG_ERROR;
            msg.error_no = errno;
            (void)anota_native_write_message(write_fd, &msg);
            _exit(1);
        }
        dr7 |= specs[i].dr7;
    }
    if (anota_native_ptrace(PTRACE_POKEUSER, parent_pid,
                            (void *)offsetof(struct user, u_debugreg[6]),
                            (void *)0) < 0 ||
        anota_native_ptrace(PTRACE_POKEUSER, parent_pid,
                            (void *)offsetof(struct user, u_debugreg[7]),
                            (void *)dr7) < 0) {
        msg.kind = ANOTA_NATIVE_MSG_ERROR;
        msg.error_no = errno;
        (void)anota_native_write_message(write_fd, &msg);
        _exit(1);
    }

    msg.kind = ANOTA_NATIVE_MSG_READY;
    if (anota_native_write_message(write_fd, &msg) < 0) {
        _exit(1);
    }

    if (anota_native_ptrace(PTRACE_CONT, parent_pid, NULL, NULL) < 0) {
        _exit(1);
    }

    for (;;) {
        unsigned long long dr6 = 0;
        int stop_signal;

        if (anota_native_wait_for_stop(parent_pid, &status) < 0) {
            msg.kind = ANOTA_NATIVE_MSG_ERROR;
            msg.error_no = errno ? errno : ECHILD;
            (void)anota_native_write_message(write_fd, &msg);
            _exit(1);
        }

        if (!WIFSTOPPED(status)) {
            msg.kind = ANOTA_NATIVE_MSG_DONE;
            (void)anota_native_write_message(write_fd, &msg);
            _exit(0);
        }

        stop_signal = WSTOPSIG(status);
        if (stop_signal == SIGTRAP) {
            errno = 0;
            dr6 = (unsigned long long)ptrace(
                PTRACE_PEEKUSER,
                parent_pid,
                (void *)offsetof(struct user, u_debugreg[6]),
                NULL);
            if (!(dr6 == (unsigned long long)-1 && errno != 0) &&
                (dr6 & ((1ULL << spec_count) - 1ULL)) != 0) {
                int slot = 0;
                while (slot < spec_count && !(dr6 & (1ULL << slot))) {
                    slot++;
                }
                msg.kind = ANOTA_NATIVE_MSG_EVENT;
                msg.signal_no = stop_signal;
                msg.slot = slot;
                msg.dr6 = dr6;
                if (slot < spec_count) {
                    msg.address = specs[slot].address;
                }
                (void)anota_native_ptrace(PTRACE_POKEUSER, parent_pid,
                                          (void *)offsetof(struct user, u_debugreg[7]),
                                          (void *)0);
                (void)anota_native_ptrace(PTRACE_POKEUSER, parent_pid,
                                          (void *)offsetof(struct user, u_debugreg[6]),
                                          (void *)0);
                (void)anota_native_write_message(write_fd, &msg);
                (void)anota_native_ptrace(PTRACE_DETACH, parent_pid, NULL, NULL);
                _exit(0);
            }
        }

        if (stop_signal == SIGWINCH) {
            msg.kind = ANOTA_NATIVE_MSG_DONE;
            (void)anota_native_ptrace(PTRACE_POKEUSER, parent_pid,
                                      (void *)offsetof(struct user, u_debugreg[7]),
                                      (void *)0);
            (void)anota_native_ptrace(PTRACE_POKEUSER, parent_pid,
                                      (void *)offsetof(struct user, u_debugreg[6]),
                                      (void *)0);
            (void)anota_native_write_message(write_fd, &msg);
            (void)anota_native_ptrace(PTRACE_DETACH, parent_pid, NULL, NULL);
            _exit(0);
        }

        if (anota_native_ptrace(PTRACE_CONT, parent_pid, NULL,
                                (void *)(intptr_t)stop_signal) < 0) {
            msg.kind = ANOTA_NATIVE_MSG_ERROR;
            msg.error_no = errno;
            (void)anota_native_write_message(write_fd, &msg);
            _exit(1);
        }
    }
}

static int
anota_native_watch_start(PyThreadState *tstate, _PyAnotaNativeWatchGuard *guard)
{
    AnotaNativeWatchSpec specs[Py_ANOTA_NATIVE_WATCH_MAX_SPECS];
    AnotaNativeWatchMessage msg;
    int fds[2];
    pid_t pid;
    int i;
    int status;

    (void)tstate;

    if (guard->spec_count == 0) {
        return 0;
    }

    if (pipe(fds) < 0) {
        PyErr_SetFromErrno(PyExc_OSError);
        return -1;
    }

    pid = fork();
    if (pid < 0) {
        int saved_errno = errno;
        close(fds[0]);
        close(fds[1]);
        errno = saved_errno;
        PyErr_SetFromErrno(PyExc_OSError);
        return -1;
    }

    if (pid == 0) {
        close(fds[0]);
        for (i = 0; i < guard->spec_count; i++) {
            specs[i].address = (uintptr_t)guard->addresses[i];
            specs[i].dr7 = anota_native_encode_dr7(i, guard->sizes[i]);
        }
        anota_native_trace_parent(getppid(), fds[1], specs, guard->spec_count);
        _exit(1);
    }

    close(fds[1]);
    guard->tracer_pid = (int)pid;
    guard->read_fd = fds[0];

#ifdef PR_SET_PTRACER
    (void)prctl(PR_SET_PTRACER, (unsigned long)pid, 0, 0, 0);
#endif

    status = anota_native_read_message(guard->read_fd, &msg);
    if (status <= 0 || msg.kind != ANOTA_NATIVE_MSG_READY) {
        if (status > 0 && msg.kind == ANOTA_NATIVE_MSG_ERROR && msg.error_no != 0) {
            errno = msg.error_no;
            PyErr_SetFromErrno(PyExc_OSError);
        }
        else {
            PyErr_SetString(PyExc_RuntimeError,
                            "ANOTA_WATCH native monitor failed to initialize");
        }
        anota_native_watch_guard_clear(guard);
        waitpid(pid, NULL, 0);
        return -1;
    }

    guard->active = 1;
    return 0;
}
#else
static int
anota_native_watch_start(PyThreadState *tstate, _PyAnotaNativeWatchGuard *guard)
{
    (void)tstate;
    (void)guard;
    return 0;
}
#endif

static int
anota_native_watch_begin_common(PyThreadState *tstate,
                                PyObject *func,
                                _PyAnotaNativeWatchGuard *guard)
{
    if (guard->spec_count == 0 || anota_native_watch_reentrant()) {
        anota_native_watch_guard_clear(guard);
        guard->read_fd = -1;
        return 0;
    }

    anota_native_watch_depth++;
    if (anota_native_watch_start(tstate, guard) < 0) {
        anota_native_watch_depth--;
        return -1;
    }

    if (!guard->active) {
        anota_native_watch_depth--;
        anota_native_watch_guard_clear(guard);
    }

    (void)func;
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

static int
anota_native_collect_func_self(PyObject *func, _PyAnotaNativeWatchGuard *guard)
{
    if (PyCFunction_Check(func)) {
        if (anota_native_watch_guard_add(guard, PyCFunction_GET_SELF(func)) < 0) {
            return -1;
        }
    }
    return 0;
}

int
_PyAnota_NativeWatchBeginVectorcall(PyThreadState *tstate,
                                    PyObject *func,
                                    PyObject *const *args,
                                    Py_ssize_t nargs,
                                    Py_ssize_t nkwargs,
                                    PyObject *kwnames,
                                    _PyAnotaNativeWatchGuard *guard)
{
    Py_ssize_t total_args = nargs + nkwargs;
    Py_ssize_t i;

    (void)kwnames;
    memset(guard, 0, sizeof(*guard));
    guard->read_fd = -1;

    if (anota_native_collect_func_self(func, guard) < 0) {
        anota_native_watch_guard_clear(guard);
        return -1;
    }

    for (i = 0; i < total_args; i++) {
        if (anota_native_watch_guard_add(guard, args[i]) < 0) {
            anota_native_watch_guard_clear(guard);
            return -1;
        }
    }

    return anota_native_watch_begin_common(tstate, func, guard);
}

int
_PyAnota_NativeWatchBeginTupleDictCall(PyThreadState *tstate,
                                       PyObject *func,
                                       PyObject *args_tuple,
                                       PyObject *kwargs_dict,
                                       _PyAnotaNativeWatchGuard *guard)
{
    Py_ssize_t i;

    memset(guard, 0, sizeof(*guard));
    guard->read_fd = -1;

    if (anota_native_collect_func_self(func, guard) < 0) {
        anota_native_watch_guard_clear(guard);
        return -1;
    }

    if (args_tuple != NULL) {
        Py_ssize_t nargs = PyTuple_GET_SIZE(args_tuple);
        for (i = 0; i < nargs; i++) {
            if (anota_native_watch_guard_add(guard, PyTuple_GET_ITEM(args_tuple, i)) < 0) {
                anota_native_watch_guard_clear(guard);
                return -1;
            }
        }
    }

    if (kwargs_dict != NULL) {
        PyObject *key;
        PyObject *value;
        Py_ssize_t pos = 0;
        while (PyDict_Next(kwargs_dict, &pos, &key, &value)) {
            if (anota_native_watch_guard_add(guard, value) < 0) {
                anota_native_watch_guard_clear(guard);
                return -1;
            }
        }
    }

    return anota_native_watch_begin_common(tstate, func, guard);
}

int
_PyAnota_NativeWatchEnd(PyThreadState *tstate,
                        PyObject *func,
                        _PyAnotaNativeWatchGuard *guard)
{
    int violation = 0;
    int active;

    if (guard == NULL) {
        return 0;
    }

    active = guard->active;

#if defined(__linux__) && defined(__x86_64__)
    if (active) {
        AnotaNativeWatchMessage msg;
        int wait_rc;

        memset(&msg, 0, sizeof(msg));
        wait_rc = waitpid((pid_t)guard->tracer_pid, NULL, WNOHANG);
        if (wait_rc == 0) {
            raise(SIGWINCH);
        }

        wait_rc = anota_native_read_message(guard->read_fd, &msg);
        if (wait_rc < 0) {
            PyErr_SetFromErrno(PyExc_OSError);
            anota_native_watch_guard_clear(guard);
            anota_native_watch_depth--;
            return -1;
        }

        if (msg.kind == ANOTA_NATIVE_MSG_EVENT) {
            int slot = msg.slot;
            PyObject *target = NULL;

            if (slot >= 0 && slot < guard->spec_count) {
                target = guard->objects[slot];
            }
            PySys_FormatStderr(
                "ANOTA_WATCH violation: blocked native W access on object %R "
                "while calling %R\n",
                target != NULL ? target : Py_None,
                func);
            if (!_PyErr_Occurred(tstate)) {
                _PyErr_SetString(tstate, PyExc_RuntimeError,
                                 "ANOTA_WATCH native policy violation");
            }
            violation = -1;
        }
        else if (msg.kind == ANOTA_NATIVE_MSG_ERROR) {
            if (!_PyErr_Occurred(tstate)) {
                errno = msg.error_no ? msg.error_no : EIO;
                PyErr_SetFromErrno(PyExc_OSError);
            }
            violation = -1;
        }

        waitpid((pid_t)guard->tracer_pid, NULL, 0);
    }
#else
    (void)tstate;
    (void)func;
#endif

    anota_native_watch_guard_clear(guard);
    if (active) {
        anota_native_watch_depth--;
    }
    return violation;
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

static PyObject *
anota_con(AnotaWatchObject *self, PyObject *args, PyObject *kwargs)
{
    static char *kwlist[] = {
        "callable", "fixed_args", "random_args",
        "number_measurements", "threshold", "kwargs", NULL
    };
    PyObject *callable;
    PyObject *fixed_args_obj;
    PyObject *random_args_obj;
    PyObject *call_kwargs = Py_None;
    PyObject *fixed_args = NULL;
    PyObject *random_args = NULL;
    PyObject *result = NULL;
    PyObject *summary = NULL;
    PyObject *t_value_obj = NULL;
    PyObject *threshold_obj = NULL;
    PyObject *measurements_obj = NULL;
    PyObject *leakage_obj = NULL;
    Py_ssize_t number_measurements = 5000;
    double threshold = 4.5;
    AnotaConTTest tctx;
    PyThreadState *tstate = _PyThreadState_GET();

    (void)self;

    if (!PyArg_ParseTupleAndKeywords(
            args, kwargs, "OOO|ndO:CON", kwlist,
            &callable, &fixed_args_obj, &random_args_obj,
            &number_measurements, &threshold, &call_kwargs)) {
        return NULL;
    }

    if (!PyCallable_Check(callable)) {
        PyErr_SetString(PyExc_TypeError, "ANOTA_WATCH.CON expects a callable");
        return NULL;
    }
    if (number_measurements < 20) {
        PyErr_SetString(PyExc_ValueError,
                        "ANOTA_WATCH.CON requires at least 20 measurements");
        return NULL;
    }
    if (call_kwargs != Py_None && !PyDict_Check(call_kwargs)) {
        PyErr_SetString(PyExc_TypeError, "kwargs must be a dict or None");
        return NULL;
    }
    if (_PyAnota_CheckExecObject(tstate, callable) < 0) {
        return NULL;
    }

    fixed_args = normalize_call_args(fixed_args_obj);
    if (fixed_args == NULL) {
        return NULL;
    }
    random_args = normalize_call_args(random_args_obj);
    if (random_args == NULL) {
        Py_DECREF(fixed_args);
        return NULL;
    }

    anota_con_t_init(&tctx);
    for (Py_ssize_t i = 0; i < number_measurements; i++) {
        PyObject *call_args = (i & 1) ? random_args : fixed_args;
        long long start_ns;
        long long end_ns;
        int clazz = (i & 1) ? 1 : 0;

        start_ns = anota_con_now_ns();
        if (start_ns < 0) {
            PyErr_SetFromErrno(PyExc_OSError);
            goto done;
        }
        result = PyObject_Call(callable, call_args,
                               call_kwargs == Py_None ? NULL : call_kwargs);
        end_ns = anota_con_now_ns();
        if (end_ns < 0) {
            Py_XDECREF(result);
            PyErr_SetFromErrno(PyExc_OSError);
            goto done;
        }
        if (result == NULL) {
            goto done;
        }
        Py_DECREF(result);
        result = NULL;

        anota_con_t_push(&tctx, (double)(end_ns - start_ns), clazz);

        if ((i & 63) == 63 && PyErr_CheckSignals() < 0) {
            goto done;
        }
    }

    {
        double t_value = fabs(anota_con_t_compute(&tctx));
        int leakage_found = t_value >= threshold;

        summary = PyDict_New();
        if (summary == NULL) {
            goto done;
        }
        t_value_obj = PyFloat_FromDouble(t_value);
        threshold_obj = PyFloat_FromDouble(threshold);
        measurements_obj = PyLong_FromSsize_t(number_measurements);
        leakage_obj = PyBool_FromLong(leakage_found);
        if (t_value_obj == NULL || threshold_obj == NULL ||
            measurements_obj == NULL || leakage_obj == NULL) {
            goto done;
        }
        if (PyDict_SetItemString(summary, "t_stat", t_value_obj) < 0 ||
            PyDict_SetItemString(summary, "threshold", threshold_obj) < 0 ||
            PyDict_SetItemString(summary, "measurements", measurements_obj) < 0 ||
            PyDict_SetItemString(summary, "leakage_found", leakage_obj) < 0) {
            goto done;
        }

        if (leakage_found) {
            PySys_FormatStderr(
                "ANOTA_WATCH.CON detected timing leakage for %R "
                "(|t|=%R, threshold=%R, measurements=%R)\n",
                callable, t_value_obj, threshold_obj, measurements_obj);
            PyErr_SetString(PyExc_RuntimeError,
                            "ANOTA_WATCH.CON detected timing side-channel leakage");
            goto done;
        }
    }

done:
    Py_XDECREF(result);
    Py_XDECREF(t_value_obj);
    Py_XDECREF(threshold_obj);
    Py_XDECREF(measurements_obj);
    Py_XDECREF(leakage_obj);
    Py_DECREF(fixed_args);
    Py_DECREF(random_args);
    if (summary != NULL && PyErr_Occurred()) {
        Py_DECREF(summary);
        summary = NULL;
    }
    return summary;
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
    {"CON", (PyCFunction)anota_con, METH_VARARGS | METH_KEYWORDS,
     PyDoc_STR("CON(callable, fixed_args, random_args, number_measurements=5000,\n"
               "    threshold=4.5, kwargs=None)\n"
               "Run a Dudect-style timing test inside the interpreter.\n"
               "fixed_args and random_args are argument tuples (or single\n"
               "objects, which are promoted to one-argument tuples).")},
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
