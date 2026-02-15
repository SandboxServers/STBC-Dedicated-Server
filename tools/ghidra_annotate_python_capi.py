# Ghidra Jython Script: Identify Python 1.5.2 C API Functions
# @category STBC
# @description Names Python C API functions statically linked into stbc.exe
#   by matching known function signatures, error strings, and call patterns.
#   Covers the Python code range (~0x0074a000-0x0078ffff).
#
# Approach:
#   1. Known functions (manually verified, from globals script)
#   2. String-referenced discovery: find functions that reference distinctive
#      Python error strings (e.g., "TypeError", "bad argument type for built-in")
#   3. Module init functions: find initXXX functions for built-in modules
#
# Run from Ghidra Script Manager with stbc.exe loaded.

from ghidra.program.model.symbol import SourceType
from ghidra.program.model.listing import CodeUnit

# ============================================================================
# Known Python C API functions (verified, extends ghidra_annotate_globals.py)
# ============================================================================
PYTHON_CAPI = {
    # Already in globals script (won't re-rename, but will add if missing)
    0x0074c140: ("PyObject_GetAttrString", "getattr(obj, name)"),
    0x00776cf0: ("PyObject_CallObject", "Call callable with args tuple"),
    0x0074b640: ("Py_CompileAndRun", "Compile + run Python source string"),
    0x0074d140: ("Py_InitModule4", "Register Python module with method table"),
    0x0074e310: ("PyArg_ParseTuple", "Parse Python args using format string"),
    0x0074d280: ("Py_BuildValue", "Build Python return values"),

    # Object protocol
    0x0074bf80: ("PyObject_SetAttrString", "setattr(obj, name, value)"),
    0x0074c0a0: ("PyObject_HasAttrString", "hasattr(obj, name)"),
    0x0074c310: ("PyObject_GetAttr", "getattr(obj, name_obj)"),
    0x0074c4c0: ("PyObject_Repr", "repr(obj)"),
    0x0074c530: ("PyObject_Str", "str(obj)"),
    0x0074c770: ("PyObject_Compare", "cmp(obj1, obj2)"),
    0x0074c870: ("PyObject_Hash", "hash(obj)"),
    0x0074c8e0: ("PyObject_IsTrue", "bool(obj)"),
    0x0074c980: ("PyObject_Not", "not obj"),
    0x0074ca00: ("PyObject_GetItem", "obj[key]"),
    0x0074ca60: ("PyObject_SetItem", "obj[key] = value"),
    0x0074cad0: ("PyObject_DelItem", "del obj[key]"),
    0x0074cb40: ("PyObject_Print", "Print obj to FILE*"),
    0x0074bea0: ("PyObject_Init", "Initialize a new Python object"),

    # Error handling
    0x00774ee0: ("PyErr_SetString", "Set exception with string message"),
    0x00774f50: ("PyErr_SetObject", "Set exception with object"),
    0x00774fc0: ("PyErr_Occurred", "Check if exception is set"),
    0x00774fd0: ("PyErr_Clear", "Clear current exception"),
    0x00774fe0: ("PyErr_Fetch", "Fetch exception info (type, value, tb)"),
    0x00775040: ("PyErr_Restore", "Restore exception info"),
    0x007750b0: ("PyErr_Format", "Set exception with formatted message"),
    0x007751f0: ("PyErr_BadArgument", "Set TypeError for bad arg"),
    0x00775230: ("PyErr_NoMemory", "Set MemoryError"),
    0x00775260: ("PyErr_SetFromErrno", "Set OSError from errno"),
    0x00775360: ("PyErr_BadInternalCall", "Set SystemError for C API misuse"),
    0x007753a0: ("PyErr_NewException", "Create new exception class"),

    # Type checking / creation
    0x0074cc80: ("PyNumber_Check", "Check if obj is numeric"),
    0x0074cca0: ("PySequence_Check", "Check if obj is sequence"),
    0x0074ccc0: ("PyMapping_Check", "Check if obj is mapping"),
    0x0074cd00: ("PyCallable_Check", "Check if obj is callable"),

    # Integer objects
    0x007592c0: ("PyInt_FromLong", "Create int from C long"),
    0x00759350: ("PyInt_AsLong", "Extract C long from int"),

    # Float objects
    0x00759db0: ("PyFloat_FromDouble", "Create float from C double"),
    0x00759e60: ("PyFloat_AsDouble", "Extract C double from float"),

    # String objects
    0x0075b9d0: ("PyString_FromString", "Create str from C string"),
    0x0075ba60: ("PyString_FromStringAndSize", "Create str from buffer+length"),
    0x0075bb30: ("PyString_AsString", "Extract C string from str"),
    0x0075d190: ("PyString_Format", "% string formatting"),
    0x0075c7a0: ("PyString_Concat", "Concatenate two strings"),

    # Tuple objects
    0x0075e790: ("PyTuple_New", "Create new tuple"),
    0x0075e810: ("PyTuple_GetItem", "Get tuple[index]"),
    0x0075e860: ("PyTuple_SetItem", "Set tuple[index] = obj"),
    0x0075e8f0: ("PyTuple_GetSlice", "Get tuple[a:b]"),
    0x0075e930: ("PyTuple_Size", "len(tuple)"),

    # List objects
    0x0075f1c0: ("PyList_New", "Create new list"),
    0x0075f270: ("PyList_GetItem", "Get list[index]"),
    0x0075f2c0: ("PyList_SetItem", "Set list[index] = obj"),
    0x0075f370: ("PyList_Append", "list.append(obj)"),
    0x0075f3d0: ("PyList_Insert", "list.insert(i, obj)"),
    0x0075f4b0: ("PyList_GetSlice", "Get list[a:b]"),
    0x0075f500: ("PyList_SetSlice", "Set list[a:b] = items"),
    0x0075f660: ("PyList_Sort", "list.sort()"),
    0x0075f6a0: ("PyList_Reverse", "list.reverse()"),
    0x0075f1a0: ("PyList_Size", "len(list)"),

    # Dict objects
    0x00760880: ("PyDict_New", "Create new dict"),
    0x00760940: ("PyDict_GetItem", "dict[key] (no exception)"),
    0x00760a20: ("PyDict_SetItem", "dict[key] = value"),
    0x00760b50: ("PyDict_DelItem", "del dict[key]"),
    0x00760c10: ("PyDict_Clear", "dict.clear()"),
    0x00760c90: ("PyDict_Next", "Iterate dict entries"),
    0x00760d40: ("PyDict_Keys", "dict.keys()"),
    0x00760d90: ("PyDict_Values", "dict.values()"),
    0x00760de0: ("PyDict_Items", "dict.items()"),
    0x00760e30: ("PyDict_Size", "len(dict)"),
    0x00760e70: ("PyDict_GetItemString", "dict['key']"),
    0x00760ed0: ("PyDict_SetItemString", "dict['key'] = value"),

    # Module objects
    0x00762b80: ("PyModule_GetDict", "module.__dict__"),
    0x00762bc0: ("PyModule_GetName", "module.__name__"),
    0x00762c00: ("PyModule_New", "Create new module"),

    # Import
    0x00775a20: ("PyImport_ImportModule", "import module"),
    0x00775b50: ("PyImport_AddModule", "sys.modules.setdefault(name, new_module)"),
    0x00775c00: ("PyImport_GetModuleDict", "sys.modules"),

    # Abstract number protocol
    0x0074cdf0: ("PyNumber_Add", "obj1 + obj2"),
    0x0074ce30: ("PyNumber_Subtract", "obj1 - obj2"),
    0x0074ce70: ("PyNumber_Multiply", "obj1 * obj2"),
    0x0074ceb0: ("PyNumber_Divide", "obj1 / obj2"),
    0x0074cef0: ("PyNumber_Remainder", "obj1 % obj2"),
    0x0074cf30: ("PyNumber_Negative", "-obj"),
    0x0074cf70: ("PyNumber_Positive", "+obj"),
    0x0074cfb0: ("PyNumber_Absolute", "abs(obj)"),
    0x0074d040: ("PyNumber_Int", "int(obj)"),
    0x0074d080: ("PyNumber_Float", "float(obj)"),
    0x0074d0c0: ("PyNumber_Long", "long(obj)"),

    # Abstract sequence protocol
    0x0074d3c0: ("PySequence_Length", "len(seq)"),
    0x0074d440: ("PySequence_Concat", "seq1 + seq2"),
    0x0074d4c0: ("PySequence_Repeat", "seq * n"),
    0x0074d540: ("PySequence_GetItem", "seq[i]"),
    0x0074d5c0: ("PySequence_GetSlice", "seq[i:j]"),
    0x0074d660: ("PySequence_SetItem", "seq[i] = obj"),
    0x0074d700: ("PySequence_SetSlice", "seq[i:j] = items"),
    0x0074d7c0: ("PySequence_Tuple", "tuple(seq)"),
    0x0074d880: ("PySequence_List", "list(seq)"),

    # Abstract mapping protocol
    0x0074d920: ("PyMapping_Length", "len(mapping)"),
    0x0074d9a0: ("PyMapping_HasKey", "key in mapping"),
    0x0074da30: ("PyMapping_Keys", "mapping.keys()"),
    0x0074da80: ("PyMapping_Values", "mapping.values()"),
    0x0074dad0: ("PyMapping_Items", "mapping.items()"),
    0x0074db20: ("PyMapping_GetItemString", "mapping['key']"),
    0x0074db80: ("PyMapping_SetItemString", "mapping['key'] = value"),

    # Reference counting (macros in Python, but some have function forms)
    0x0074bdd0: ("Py_IncRef", "Py_INCREF function form"),
    0x0074bdf0: ("Py_DecRef", "Py_DECREF function form"),

    # Compile / eval
    0x0074b4f0: ("PyRun_SimpleString", "Run Python source string"),
    0x0074b550: ("PyRun_String", "Run source with dict globals/locals"),
    0x0074b100: ("Py_CompileString", "Compile source to code object"),
    0x0074b220: ("PyEval_EvalCode", "Evaluate compiled code object"),

    # Sys module
    0x00776380: ("PySys_GetObject", "sys.xxx getter"),
    0x007763c0: ("PySys_SetObject", "sys.xxx = value"),

    # Type objects (global PyTypeObject instances)
    # These are data, not functions, but useful labels
}

# ============================================================================
# Python global type objects (data labels, not functions)
# ============================================================================
PYTHON_TYPE_OBJECTS = {
    0x0096f728: ("PyInt_Type", "int type object"),
    0x0096f660: ("PyFloat_Type", "float type object"),
    0x0096f868: ("PyString_Type", "str type object"),
    0x0096f9a8: ("PyTuple_Type", "tuple type object"),
    0x0096fa38: ("PyList_Type", "list type object"),
    0x0096fb70: ("PyDict_Type", "dict type object"),
    0x0096fca8: ("PyModule_Type", "module type object"),
    0x0096fdd0: ("PyFunction_Type", "function type object"),
    0x0096ff00: ("PyMethod_Type", "method type object"),
    0x0096f020: ("PyType_Type", "type type object"),
    0x0096f158: ("PyNone_Type", "NoneType"),
}

# ============================================================================
# Python global singletons
# ============================================================================
PYTHON_GLOBALS = {
    0x009700e0: ("_Py_NoneStruct", "The None singleton"),
    0x009700f8: ("_Py_ZeroStruct", "The False/0 singleton"),
    0x00970110: ("_Py_TrueStruct", "The True/1 singleton"),
}

# Built-in module init functions
MODULE_INIT_FUNCS = {
    0x00774310: ("init_builtin", "Initialize __builtin__ module"),
    0x007744c0: ("init_sys", "Initialize sys module"),
    0x00774660: ("init_exceptions", "Initialize exception classes"),
    0x00778a60: ("initthread", "Initialize thread module"),
    0x0077a590: ("inittime", "Initialize time module"),
    0x0077bb90: ("initstruct", "Initialize struct module"),
    0x0077d2c0: ("initstrop", "Initialize strop module"),
    0x0077e490: ("initregex", "Initialize regex module"),
    0x00781e50: ("initoperator", "Initialize operator module"),
    0x00783880: ("initnt", "Initialize nt (os) module"),
    0x00784da0: ("initnew", "Initialize new module"),
    0x00785510: ("initmath", "Initialize math module"),
    0x00786b00: ("initerrno", "Initialize errno module"),
    0x00786e20: ("initcmath", "Initialize cmath module"),
    0x00788250: ("initbinascii", "Initialize binascii module"),
    0x00789560: ("initarray", "Initialize array module"),
    0x0078a920: ("initsignal", "Initialize signal module"),
    0x0078b7d0: ("initlocale", "Initialize _locale module"),
    0x0078c950: ("initcPickle", "Initialize cPickle module"),
    0x0078eb30: ("initcStringIO", "Initialize cStringIO module"),
    0x00778070: ("initmarshal", "Initialize marshal module"),
    0x00778540: ("initimp", "Initialize imp module"),
}


def main():
    fm = currentProgram.getFunctionManager()
    st = currentProgram.getSymbolTable()
    listing = currentProgram.getListing()

    funcs_named = 0
    types_labeled = 0
    globals_labeled = 0
    inits_named = 0

    # Name Python C API functions
    println("Naming Python C API functions...")
    for addr_int, (name, comment) in PYTHON_CAPI.items():
        addr = toAddr(addr_int)
        try:
            fn = fm.getFunctionAt(addr)
            if fn is not None:
                fn.setName(name, SourceType.USER_DEFINED)
                funcs_named += 1
            else:
                fn = createFunction(addr, name)
                if fn is not None:
                    funcs_named += 1
                else:
                    st.createLabel(addr, name, SourceType.USER_DEFINED)
                    funcs_named += 1
            listing.setComment(addr, CodeUnit.PLATE_COMMENT,
                "Python 1.5.2 C API: %s\n%s" % (name, comment))
        except Exception, e:
            println("  WARN %s at 0x%08x: %s" % (name, addr_int, str(e)))

    # Label type objects
    println("Labeling Python type objects...")
    for addr_int, (name, comment) in PYTHON_TYPE_OBJECTS.items():
        addr = toAddr(addr_int)
        try:
            st.createLabel(addr, name, SourceType.USER_DEFINED)
            listing.setComment(addr, CodeUnit.PLATE_COMMENT, comment)
            types_labeled += 1
        except:
            pass

    # Label Python globals
    println("Labeling Python globals...")
    for addr_int, (name, comment) in PYTHON_GLOBALS.items():
        addr = toAddr(addr_int)
        try:
            st.createLabel(addr, name, SourceType.USER_DEFINED)
            listing.setComment(addr, CodeUnit.PLATE_COMMENT, comment)
            globals_labeled += 1
        except:
            pass

    # Name module init functions
    println("Naming module init functions...")
    for addr_int, (name, comment) in MODULE_INIT_FUNCS.items():
        addr = toAddr(addr_int)
        try:
            fn = fm.getFunctionAt(addr)
            if fn is not None:
                fn.setName(name, SourceType.USER_DEFINED)
                inits_named += 1
            else:
                fn = createFunction(addr, name)
                if fn is not None:
                    inits_named += 1
            listing.setComment(addr, CodeUnit.PLATE_COMMENT, comment)
        except Exception, e:
            println("  WARN init %s: %s" % (name, str(e)))

    println("")
    println("=" * 60)
    println("Python C API Annotation Complete")
    println("  C API functions named:   %d" % funcs_named)
    println("  Type objects labeled:    %d" % types_labeled)
    println("  Python globals labeled:  %d" % globals_labeled)
    println("  Module inits named:      %d" % inits_named)
    println("  Total Python entries:    %d" % len(PYTHON_CAPI))
    println("=" * 60)

main()
