#define PY_SSIZE_T_CLEAN
#include "Python.h"

__attribute__((no_sanitize("dataflow"))) extern int Py_BytesMain(int argc, char **argv);

__attribute__((no_sanitize("dataflow"))) int
anota_py_bytes_main(int argc, char **argv)
{
    return Py_BytesMain(argc, argv);
}

int
main(int argc, char **argv)
{
    return anota_py_bytes_main(argc, argv);
}
