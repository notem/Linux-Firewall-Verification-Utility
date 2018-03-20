/**
 * date: 2018-03-19
 * contributors(s):
 *   Nate Mathews, njm3308@rit.edu
 * description:
 *   python3 bindings for the least witness algorithm
 *   run setup.py to build and install the python module
 */
#include <Python.h>
#include "utils.h/algorithm.h"

/** wrapper for the least witness with slicing algorithm */
static PyObject *firewall_verifier_verify(PyObject *self, PyObject *args)
{
    uint32_t *lo, *hi, *va, count, *witness;

    // extract arrays and count from python argument object
    if (!PyArg_ParseTuple(args, "[I][I][I]I", &lo, &hi, &va, &count))
        return NULL;

    // run witness algorithm
    witness = with_slicing(lo, hi, va, count);

    // return 0 if no witness found
    if (witness == NULL)
        return PyLong_FromLong(0L);

    // otherwise, convert witness array into a python list
    PyObject *pyWitness = PyList_New(SIZE);
    for (int i=0; i<SIZE; i++)
    {
        PyObject *pyObject = PyLong_FromSize_t(witness[i]);
        PyList_Append(pyWitness, pyObject);
    }
    free(witness);      // free witness before returning
    return pyWitness;
}

/** Python Module method definitions */
static PyMethodDef FirewallVerifierMethods[] = {
        {"verify",  firewall_verifier_verify, METH_VARARGS,
                    "Verifies a property of a firewall."},
        {NULL, NULL, 0, NULL}        /* Sentinel */
};

/** Python Module information */
static struct PyModuleDef firewall_verifier_module = {
        PyModuleDef_HEAD_INIT,
        "firewall_verifier", /* name of module */
        NULL,     /* module documentation, may be NULL */
        -1,       /* size of per-interpreter state of the module,
                 or -1 if the module keeps state in global variables. */
        FirewallVerifierMethods
};

/** Python Module initialization function */
static PyObject *PythonError;
PyMODINIT_FUNC PyInit_firewall_verifier(void)
{
    PyObject *m;

    m = PyModule_Create(&firewall_verifier_module);
    if (m == NULL)
        return NULL;

    PythonError = PyErr_NewException("firewall_verifier.error", NULL, NULL);
    Py_INCREF(PythonError);
    PyModule_AddObject(m, "error", PythonError);
    return m;
}