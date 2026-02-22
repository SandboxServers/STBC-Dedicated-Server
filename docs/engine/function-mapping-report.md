> [docs](../README.md) / [engine](README.md) / function-mapping-report.md

# Function Mapping Report

Coverage analysis of stbc.exe (~18,247 functions) after running all Ghidra annotation scripts.

## Annotation Script Suite

Run order matters — later scripts benefit from names applied by earlier ones.

| # | Script | What It Does | Functions Named |
|---|--------|-------------|---------------------|
| 1 | `ghidra_annotate_globals.py` | Labels 13 globals, 62 key RE'd functions, 22 Python module tables | 97 |
| 2 | `ghidra_annotate_nirtti.py` | Labels 117 NiRTTI factory + 117 registration functions, guard flags | 234 |
| 3 | `ghidra_annotate_swig.py` | Names 3,990 SWIG wrapper functions from PyMethodDef table | 3,990 |
| 4 | `ghidra_annotate_vtables.py` | Auto-discovers vtables from 97 factories, names constructors + slots | 1,270 |
| 5 | `ghidra_annotate_swig_targets.py` | Traces SWIG wrappers to name underlying C++ implementations | 4 |
| 6 | `ghidra_annotate_pymodules.py` | Walks 21 Python module method tables, names C implementations | 266 |
| 7 | `ghidra_annotate_python_capi.py` | Names 113 Python 1.5.2 C API functions, type objects, globals, 10 module inits | 137 |
| 8 | `ghidra_discover_strings.py` | Names functions from "ClassName::MethodName" debug strings | 33 (+515 comments) |

**Recommended run order:** 1 → 2 → 3 → 7 → 6 → 4 → 5 → 8

Scripts 1-3 and 7 provide foundational names that scripts 4-5 use for helper detection. Script 8 runs last to benefit from all prior naming.

> **Note on swig_targets:** Most SWIG wrappers (3,986 of 3,990) are inline field accessors with no non-helper CALL instructions, so they have no separate C++ target function to name. The 4 that do get named are wrappers that call unique C++ implementations.

## Coverage Summary

| Category | Count | % of 18,247 |
|----------|-------|-------------|
| Auto-generated (Unwind/Catch handlers) | ~4,695 | 26% |
| Named by annotation scripts | ~6,031 | 33% |
| **Total named/excluded** | **~10,726** | **59%** |
| Remaining unnamed (game-specific) | ~3,750 | 21% |
| Remaining unnamed (compiler/helper) | ~3,771 | 20% |

## What Each Script Discovers

### ghidra_annotate_vtables.py (Phase 1+2)

Auto-discovery pipeline for 117 NiRTTI factory classes (97 vtables discovered, 20 failed):
1. Decompiles factory function -> finds constructor (first non-NiAlloc CALL after NiAlloc)
2. Scans constructor -> finds vtable address (MOV to .rdata with noop verification at slot 11)
3. Counts vtable slots using sorted boundary detection
4. Names: vtable label, constructor (`ClassName_ctor`), scalar_deleting_dtor, base 12 NiObject slots

Actual results: 1,090 virtual function slots + 96 constructors + 84 destructors = 1,270 total.

Verified slot names for known hierarchies:
- **NiObject** (12 slots): GetRTTI through IsEqual
- **NiAVObject** (27 additional slots): UpdateControllers through UpdateWorldBound
- **NiNode** (4 additional slots): AttachChild through SetAt
- **NiProperty** (2 additional slots): Type, Update
- **NiExtraData** (1 additional slot): GetSize
- **NiAccumulator** (4 additional slots): RegisterObjectArray through FinishAccumulating

Key verification: slot 11 (vtable+0x2C) must equal `0x0040da50` (universal noop).

### ghidra_annotate_swig_targets.py (Phase 3)

Two-pass frequency analysis:
- Pass 1: Walk all 3,990 SWIG wrappers, collect all CALL targets
- Pass 2: Targets appearing in >50 wrappers = helpers (PyArg_ParseTuple, SWIG_GetPointerObj, etc.)
- Pass 3: Last non-helper CALL in each wrapper = the C++ implementation

Names derived from wrapper: `swig_NiNode_GetName` → target named `NiNode_GetName`.
Handles `delete_X` → `X_dtor`, `new_X` → `X_new`.

Inline wrappers (field access, no CALL) are skipped — these have no separate target function.

### ghidra_annotate_pymodules.py (Phase 7)

Walks 21 non-SWIG Python module method tables (same 16-byte PyMethodDef format as SWIG):

| Module | Table Address | Description |
|--------|-------------|-------------|
| builtin | 0x00961490 | `__builtin__` module |
| imp | 0x00963a80 | Module import |
| marshal | 0x009643a0 | Serialization |
| locale | 0x00964658 | Locale support |
| cPickle | 0x00964b60 | Fast pickle |
| cStringIO | 0x009660a8 | String I/O |
| thread | 0x00966ab0 | Threading |
| time | 0x00967410 | Time functions |
| struct | 0x009686c0 | Binary packing |
| strop | 0x009697d8 | String operations |
| regex | 0x00969d28 | Regular expressions |
| operator | 0x0096a078 | Operator overloads |
| nt | 0x0096b888 | OS interface |
| new | 0x0096bd88 | Object creation |
| math | 0x0096c378 | Math functions |
| errno | 0x0099f5c8 | Error codes |
| cmath | 0x0096d178 | Complex math |
| binascii | 0x0096d818 | Binary ↔ ASCII |
| array | 0x0096e118 | Array type |
| sys | 0x0096faa8 | System interface |
| signal | 0x009743d8 | Signal handling |

Names: `py_<module>_<method>` (e.g., `py_time_time`, `py_struct_pack`).

### ghidra_annotate_python_capi.py (Phase 4)

Labels ~130 Python 1.5.2 C API functions statically linked into stbc.exe (range ~0x0074a000-0x0078ffff):

- Object protocol: GetAttr, SetAttr, Compare, Hash, etc.
- Error handling: PyErr_SetString, PyErr_Format, etc.
- Type operations: Int, Float, String, Tuple, List, Dict creation and access
- Abstract protocols: Number, Sequence, Mapping
- Module/Import: PyImport_ImportModule, Py_InitModule4
- Compile/eval: PyRun_SimpleString, Py_CompileString, PyEval_EvalCode
- 11 type object labels (PyInt_Type, PyFloat_Type, etc.)
- 3 singleton labels (_Py_NoneStruct, _Py_ZeroStruct, _Py_TrueStruct)
- 22 module init functions (init_builtin, inittime, initstrop, etc.)

### ghidra_discover_strings.py (Phase 6)

Scans all defined strings for patterns identifying function names:
- `"ClassName::MethodName"` — C++ debug assertions/error messages
- `"ClassName::MethodName: error text"` — prefix matching
- Names function if it's the sole unnamed reference to the string

Runs last to benefit from all prior naming (avoids renaming already-named functions).

## Unmappable Functions

### Game-Specific Class Internals (~2,520-2,940)

~420 Totally Games proprietary classes (ShipClass, TGUIObject, STMission_*, AIShipBehavior, etc.). Zero external documentation. Only discoverable through per-function manual RE.

### NI 3.1-Only Subsystems (~250-340)

42 NI classes with no Gamebryo 1.2 source: Bezier patches (11), old animation system (8), old texture properties (5), DirectDraw rendering (8), NI 3.1-specific nodes (3), audio (4), misc (3).

### Compiler-Generated Code (~800-1,200)

Thunks, inlined CRT, template instantiations, exception handlers, adjuster thunks. No meaningful semantic names possible.

### Anonymous Helpers (~200-400)

1-10 instruction functions with no strings, no distinctive patterns. Too small to identify purpose.

## Phase 5 (COM Interfaces) — 0 Yield

COM vtables for DDraw7/D3D7/Surface7 are in external DirectX DLLs, not in stbc.exe. The NetImmerse wrapper classes (NiDX8Renderer etc.) are NiObject-derived and already handled by the vtable script. No additional functions to name.

## Key Architectural Discovery: NI 3.1 vs Gb 1.2 Vtable Differences

NI 3.1 has significantly MORE virtual methods than Gb 1.2 in several key hierarchies:

| Class | NI 3.1 Slots | Gb 1.2 Slots | Delta |
|-------|-------------|-------------|-------|
| NiAVObject | 39 | 27 | +12 |
| NiNode | 43 | 31 | +12 |
| NiGeometry | 64 | 27 | +37 |

This means class-specific virtual method names CANNOT be blindly copied from Gb 1.2 header ordering — the slot indices don't match. The vtable script uses verified base-class slot names (NiObject 0-11, NiAVObject 12-38, NiNode 39-42) and leaves class-specific extended slots as numbered entries (`vfunc_NN`) pending manual verification.
