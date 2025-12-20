#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <listobject.h>

static PyObject* my_set(PyObject* self, PyObject* args) {
    PyObject* pList;
    Py_ssize_t index;
    PyObject* pNewItem;
    if (!PyArg_ParseTuple(args, "OnO", &pList, &index, &pNewItem)) {
        return NULL;
    }
    if (!PyList_Check(pList)) {
        PyErr_SetString(PyExc_TypeError, "First argument must be a list.");
        return NULL;
    }
    PyListObject* pListObj = (PyListObject*)pList;
    Py_ssize_t size = Py_SIZE(pListObj);
    if (index < 0 || index >= size) {
        PyErr_SetString(PyExc_IndexError, "list assignment index out of range");
        return NULL;
    }
    PyObject* pOldItem = pListObj->ob_item[index];
    Py_INCREF(pNewItem);
    pListObj->ob_item[index] = pNewItem;
    Py_RETURN_NONE;
}

static PyObject* my_append(PyObject* self, PyObject* args) {
    PyObject* pList;
    PyObject* pNewItem;
    if (!PyArg_ParseTuple(args, "OO", &pList, &pNewItem)) {
        return NULL;
    }
    if (!PyList_Check(pList)) {
        PyErr_SetString(PyExc_TypeError, "First argument must be a list.");
        return NULL;
    }
    PyListObject* pListObj = (PyListObject*)pList;
    Py_ssize_t size = Py_SIZE(pListObj);
    Py_INCREF(pNewItem);
    Py_SET_SIZE(pListObj, size + 1);
    pListObj->ob_item[size] = pNewItem;
    Py_RETURN_NONE;
}

static PyObject* myexit(PyObject* self, PyObject* args) {
    exit(0);
}


static PyMethodDef MyMethods[] = {
    {"my_set", my_set, METH_VARARGS, ""},
    {"my_append", my_append, METH_VARARGS, ""},
    {"myexit", myexit, METH_VARARGS, ""},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef my_arrays_module = {
    PyModuleDef_HEAD_INIT,
    "my_arrays",
    "",
    -1,
    MyMethods
};

PyMODINIT_FUNC PyInit_my_arrays(void) {
    return PyModule_Create(&my_arrays_module);
}