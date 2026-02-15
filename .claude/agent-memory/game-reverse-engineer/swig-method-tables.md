# SWIG Method Tables Analysis (2026-02-15)

## App/Appc Shared Method Table
- **Table address**: 0x008e6438 (in .data section)
- **Terminator**: 0x008f5d98 (NULL entry)
- **Entry count**: 3990 methods
- **Table size**: 63,856 bytes (62.4 KB, including 16-byte NULL terminator)
- **Entry layout**: Standard `PyMethodDef` (16 bytes per entry on x86-32)
  - +0x00: `char *ml_name` (method name string pointer)
  - +0x04: `PyCFunction ml_meth` (wrapper function pointer)
  - +0x08: `int ml_flags` (always 1 = METH_VARARGS)
  - +0x0C: `char *ml_doc` (always NULL)
- **Function pointer range**: 0x00470dd0 - 0x006ff980

## Module Initialization
- **Appc**: initAppc at 0x0065a250, calls Py_InitModule4 at 0x0065a26e
- **App**: Created via TG_ImportModule("App") at 0x0043b1ba (our proxy patches this)
- **Both use the SAME method table** at 0x008e6438
- App and Appc are aliases for the same SWIG binding layer

## Py_InitModule4 = FUN_0074d140
- Signature: `PyObject* Py_InitModule4(char *name, PyMethodDef *methods, char *doc, PyObject *self, int api_version)`
- api_version = 0x3EF (1007) for all BC modules
- 22 total calls in stbc.exe (one per built-in module)

## SWIG Type Info Array
- **Array address**: 0x00900a94 (pointer array)
- **Entry count**: 348 type descriptors
- **Located after method table** at 0x008f5da8
- Layout per entry: `{ char *name, void *converter, char *str, swig_type_info *next }`
- Names like `_p_TGNetwork`, `_p_ShipClass`, `_p_TopWindow`, etc.

## SWIG Wrapper Pattern (all 3990 wrappers follow this)
1. `PyArg_ParseTuple` (0x0074e310) - parse Python args using format string
2. `SWIG_GetPointerObj` (0x005bae00) - unwrap SWIG pointer to raw C++ pointer
3. Direct C++ method call (thiscall on unwrapped pointer)
4. `SWIG_NewPointerObj` (0x005bb0e0) - wrap C++ return value as SWIG pointer
- **NO indirection layer** - wrappers call C++ methods directly

## Key SWIG Helper Functions
| Address | Name | Purpose |
|---------|------|---------|
| 0x0074e310 | PyArg_ParseTuple | Parse Python args (va_args) |
| 0x005bae00 | SWIG_GetPointerObj | Unwrap SWIG ptr -> raw C++ ptr |
| 0x005bb0e0 | SWIG_NewPointerObj | Wrap raw C++ ptr -> SWIG ptr |
| 0x005bb040 | SWIG_MakePtr | Format pointer string |
| 0x005bad40 | initAppc_pre | Pre-init setup (swigvarlink) |
| 0x0074d140 | Py_InitModule4 | Register Python module |
| 0x0074d280 | Py_BuildValue | Build return values |

## All 22 Built-in Python Modules
| Module | Method Table | Init Call Site |
|--------|-------------|----------------|
| Appc | 0x008e6438 | 0x0065a26e |
| __builtin__ | 0x00961490 | 0x00755cd8 |
| imp | 0x00963a80 | 0x0075dee7 |
| marshal | 0x009643a0 | 0x0075f983 |
| _locale | 0x00964658 | 0x00760425 |
| cPickle | 0x00964b60 | 0x00766dc1 |
| cStringIO | 0x009660a8 | 0x00767b98 |
| thread | 0x00966ab0 | 0x00768157 |
| time | 0x00967410 | 0x00768807 |
| struct | 0x009686c0 | 0x00769f87 |
| strop | 0x009697d8 | 0x0076bc40 |
| regex | 0x00969d28 | 0x0076ce26 |
| operator | 0x0096a078 | 0x0076d786 |
| nt | 0x0096b888 | 0x0076e7c8 |
| new | 0x0096bd88 | 0x0076ee96 |
| math | 0x0096c378 | 0x0076f548 |
| errno | 0x0099f5c8 | 0x0076f628 |
| cmath | 0x0096d178 | 0x007711a8 |
| binascii | 0x0096d818 | 0x00771e85 |
| array | 0x0096e118 | 0x00773766 |
| sys | 0x0096faa8 | 0x0077a1fb |
| signal | 0x009743d8 | 0x00781cdc |

## Top 15 Classes by Method Count
| Class | Methods |
|-------|---------|
| delete_* | 228 |
| new_* | 156 |
| CharacterClass | 109 |
| TGUIObject | 90 |
| ShipClass | 80 |
| UtopiaModule | 75 |
| TGSound | 56 |
| PhaserProperty | 53 |
| SetClass | 52 |
| TGMessage | 50 |
| STMenu | 50 |
| TractorBeamProperty | 50 |
| ShipSubsystem | 45 |
| MultiplayerWindow | 43 |
| PhysicsObjectClass | 41 |
