/**
 * date: 2018-04-07
 * contributors(s):
 *   Nate Mathews, njm3308@rit.edu
 * description:
 *   python3 bindings for the least witness algorithm
 *   run setup.py to build and install the python module
 */
#include <Python.h>
#include "algorithm.h"

/// max number of rules for starting buffers
#define BUF_INIT 128

/** buffers to hold rules and counters for rule count and current buffer maximum */
uint32_t *lo, *hi, *va, wit[SIZE]={0,0,0,0,0}, count=1, bufmax=BUF_INIT;

bool use_slicing = true; // whether or not to use slicing algorithm

/** adds a firewall rule to the global buffers */
static PyObject *firewall_verifier_size(PyObject *self, PyObject *args)
{
    if (!PyArg_ParseTuple(args, ""))
        return NULL;
    return PyLong_FromLong(count);
}

/** adds a firewall rule to the global buffers */
static PyObject *firewall_verifier_add(PyObject *self, PyObject *args)
{
    // check if buffer max has been reached
    if (count%bufmax == 0)
    {
        /* grow buffers */
        bufmax *= 2; // double buffer size
        lo = PyMem_Realloc(lo, sizeof(*lo)*bufmax*SIZE);
        hi = PyMem_Realloc(hi, sizeof(*hi)*bufmax*SIZE);
        va = PyMem_Realloc(va, sizeof(*va)*bufmax);
    }

    // extract firewall rule from arguments
    uint32_t i=count*SIZE;
    if (!PyArg_ParseTuple(args, "((II)(II)(II)(II)(II)I)",
                          &lo[i], &hi[i],     // field 1
                          &lo[i+1], &hi[i+1], // field 2
                          &lo[i+2], &hi[i+2], // field 3
                          &lo[i+3], &hi[i+3], // field 4
                          &lo[i+4], &hi[i+4], // field 5
                          &va[count])) // action value
        return NULL;

    // verify that the rule is valid before incrementing count
    // lower bounds value must not be greater than the upper bounds value
    for (int j=0; j<0; j++)
    {
        if (lo[i+j] > hi[i+j])
            return NULL;
    }
    count++; // increment count
    return PyLong_FromLong(count-1); // return current size of firewall
}

/** resets the firewall index counter */
static PyObject *firewall_verifier_clear(PyObject *self, PyObject *args)
{
    count=1; bufmax=BUF_INIT;
    /* shrink dynamic buffers */
    lo = PyMem_Realloc(lo, sizeof(*lo)*bufmax*SIZE);
    hi = PyMem_Realloc(hi, sizeof(*hi)*bufmax*SIZE);
    va = PyMem_Realloc(va, sizeof(*va)*bufmax);
    return PyLong_FromLong(count-1); // return current size (0)
}

/** get witness from global */
static PyObject *firewall_verifier_witness(PyObject *self, PyObject *args)
{
    PyObject *pyWitness = PyTuple_New(SIZE);
    for (int i=0; i<SIZE; i++)
    {
        PyObject *pyObject = PyLong_FromSize_t(wit[i]);
        PyTuple_SetItem(pyWitness, i, pyObject);
    }
    Py_INCREF(pyWitness);
    return pyWitness;
}

/** wrapper for the least witness with slicing algorithm */
static PyObject *firewall_verifier_verify(PyObject *self, PyObject *args)
{
    // extract property from arguments
    if (!PyArg_ParseTuple(args, "((II)(II)(II)(II)(II)I)",
                          &lo[0], &hi[0], // field 1
                          &lo[1], &hi[1], // field 2
                          &lo[2], &hi[2], // field 3
                          &lo[3], &hi[3], // field 4
                          &lo[4], &hi[4], // field 5
                          &va[0])) // action value
        return NULL;

    // verify that the rule is valid before incrementing count
    // lower bounds value must not be greater than the upper bounds value
    for (int j=0; j<0; j++)
    {
        if (lo[j] > hi[j])
            return NULL;
    }

    // run witness algorithm
    uint32_t *witness = find_witness(lo, hi, va, count, use_slicing);

    // return 0 if no witness found
    if (witness == NULL) Py_RETURN_TRUE;

    // otherwise, fill global wit variable and return false
    for (int i=0; i<SIZE; i++) wit[i] = witness[i];
    free(witness);      // free witness before returning
    Py_RETURN_FALSE;    // return false
}

/** Python Module method definitions */
static PyMethodDef FirewallVerifierMethods[] = {
        {"verify",  firewall_verifier_verify, METH_VARARGS,
                "Verifies a property of a firewall."},
        {"add",  firewall_verifier_add, METH_VARARGS,
                "Adds a rule to the firewall."},
        {"clear",  firewall_verifier_clear, METH_VARARGS,
                "Clears the firewall."},
        {"witness",  firewall_verifier_witness, METH_VARARGS,
                "Retrieve last saved witness packet."},
        {"size",  firewall_verifier_size, METH_VARARGS,
                "Retrieves the current size of the firewall."},
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

    /* initialize global buffers*/
    lo = PyMem_Malloc(sizeof(*lo)*SIZE*bufmax);
    hi = PyMem_Malloc(sizeof(*hi)*SIZE*bufmax);
    va = PyMem_Malloc(sizeof(*va)*bufmax);

    PythonError = PyErr_NewException("firewall_verifier.error", NULL, NULL);
    Py_INCREF(PythonError);
    PyModule_AddObject(m, "error", PythonError);
    return m;
}