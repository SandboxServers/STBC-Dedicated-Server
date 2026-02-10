# Python 1.5.2 Compatibility Review - Full Codebase (2026-02-07)

## Files Reviewed
1. `src/proxy/ddraw_main.c` - Embedded Python strings in RunPyCode() calls
2. `src/scripts/Custom/DedicatedServer.py` - Main server Python script (1061 lines)
3. `src/scripts/Local.py` - Boot hook (75 lines)

## Overall Assessment: PASS (No blocking issues found)

All three files are well-written for Python 1.5.2 compatibility. The author clearly
understands the constraints and has consistently used correct 1.5.2 idioms throughout.

---

## DedicatedServer.py - Detailed Review

### Verified CORRECT Patterns
- `import strop` + `strop.find()`, `strop.split()`, `strop.join()` for string operations
- `dict.has_key(k)` instead of `k in dict` (lines 125, 130, 232, 611, 636, 639, 692, 699)
- `except Exception, e:` syntax (comma, not `as`) throughout
- `count = count + 1` and `gui_stubs = gui_stubs + 1` instead of `+=`
- `print "string"` as statement (lines 25, 168, 170, 304, 322, 1060)
- `range(len(sequence))` instead of `enumerate()` (line 110)
- `new.function()` for creating function copies (lines 66, 248, 792)
- `sys.exc_info()` (available in 1.5.2)
- `*args` in function definitions (line 215)
- `for key, val in dict.items():` tuple unpacking (line 717)
- `0` and `1` instead of `True`/`False`
- No list comprehensions anywhere
- No augmented assignments anywhere
- No string methods used (no `.split()`, `.join()`, `.replace()`, etc.)
- No `finally` clauses (avoids try/except/finally issue)
- `filter(lambda k: ..., list)` (valid in 1.5.2)
- `getattr()`, `setattr()`, `hasattr()` (all valid in 1.5.2)
- `dir(module)` (valid in 1.5.2)
- `sys.modules.get(key, default)` (dict.get() is valid in 1.5.2)
- `chr()` and `int()` builtins (valid in 1.5.2)
- `__import__()` with correct understanding of 1.5.2 package semantics
- `traceback.print_exc(file=sio)` (keyword arg, valid in 1.5.2)
- Nested `try/except` blocks (valid; only try/except+finally is prohibited)
- `str()` on various objects (valid in 1.5.2)
- `type()` builtin (valid in 1.5.2)
- String concatenation with `+` operator (valid)
- `%` string formatting (valid in 1.5.2)

### No Issues Found
The previous review (2026-02-07 earlier session) also found no blocking issues.

---

## Local.py - Detailed Review

### Verified CORRECT Patterns
- `except Exception, e:` syntax (lines 32, 45, 68)
- `import traceback, cStringIO` (both available in 1.5.2)
- `cStringIO.StringIO()` (available in 1.5.2)
- `print "string"` as statement (lines 35, 41, 44, 51)
- `str()` on objects (valid)
- `%` string formatting (line 74)

### No Issues Found

---

## ddraw_main.c Embedded Python - Detailed Review

### RunPyCode Call #1 (lines 1177-1183): GameLoop mission patch
```python
import sys
if sys.modules.has_key('Custom.DedicatedServer'):
    ds = sys.modules['Custom.DedicatedServer']
    n = ds.PatchLoadedMissionModules()
    if n > 0:
        ds._log('GAMELOOP PATCH: patched ' + str(n) + ' at tick')
```
**Verdict: PASS** - All constructs valid in 1.5.2.

### RunPyCode Call #2 (line 1571): Simple pass test
```python
pass
```
**Verdict: PASS** - Trivially valid.

### RunPyCode Call #3 (lines 1588-1606): InitNetwork dispatch
```python
import sys
_ds_log = None
if sys.modules.has_key('Custom.DedicatedServer'):
    _ds_log = sys.modules['Custom.DedicatedServer']._log
try:
    _m1 = sys.modules['Multiplayer.Episode.Mission1.Mission1']
    if hasattr(_m1, 'InitNetwork'):
        if _ds_log: _ds_log('C-SIDE: calling InitNetwork(%d)')
        _m1.InitNetwork(%u)
        if _ds_log: _ds_log('C-SIDE: InitNetwork(%d) OK')
    else:
        if _ds_log: _ds_log('C-SIDE: InitNetwork not found on Mission1')
except:
    import sys
    _ei = sys.exc_info()
    _msg = 'C-SIDE: InitNetwork(%d) FAILED: ' + str(_ei[0]) + ': ' + str(_ei[1])
    if _ds_log: _ds_log(_msg)
    print _msg
```
**Verdict: PASS** - All constructs valid in 1.5.2. The `%d` and `%u` are C format
specifiers in wsprintfA, not Python format strings. The bare `except:` is valid.
`print _msg` is a valid print statement. `sys.exc_info()` is available in 1.5.2.

### RunPyCode Call #4 (lines 1699-1703): Phase 0 SWIG flags
```python
import App
App.g_kUtopiaModule.SetMultiplayer(1)
App.g_kUtopiaModule.SetIsHost(1)
App.g_kUtopiaModule.SetIsClient(0)
```
**Verdict: PASS** - Simple attribute access and method calls, valid in 1.5.2.

### RunPyCode Call #5 (lines 1707-1717): Phase 0 config
```python
try:
    import App
    App.g_kConfigMapping.SetStringValue(
        'Multiplayer Options', 'Game_Name', 'Dedicated Server')
    App.g_kConfigMapping.SetStringValue(
        'Multiplayer Options', 'Player_Name', 'Server')
    App.g_kConfigMapping.SetStringValue(
        'Multiplayer Options', 'Password', '')
except:
    pass
```
**Verdict: PASS** - Standard try/except with method calls, valid in 1.5.2.

### RunPyCode Call #6 (lines 1813-1817): Phase 3 pre-check
```python
import sys
_has_ds = sys.modules.has_key('Custom.DedicatedServer')
_mods = filter(lambda k: k[:6]=='Custom', sys.modules.keys())
print 'DS_TIMER3: has_DS=' + str(_has_ds) + ' custom_mods=' + str(_mods)
```
**Verdict: PASS** - `filter()` with `lambda` is valid in 1.5.2. `dict.keys()` returns
a list in 1.5.2. String slicing `k[:6]` is valid. `==` comparison is valid.
`dict.has_key()` is correct for 1.5.2. `print` statement syntax is correct.

### RunPyCode Call #7 (lines 1821-1855): Phase 3 main automation
```python
import sys
try:
    import App
    tw = App.TopWindow_GetTopWindow()
    print 'DS_TIMER3: tw=' + str(tw) + ' type=' + str(type(tw))
    if tw is not None:
        if sys.modules.has_key('Custom.DedicatedServer'):
            ds = sys.modules['Custom.DedicatedServer']
            print 'DS_TIMER3: calling TopWindowInitialized'
            ds.TopWindowInitialized(tw)
            n = ds.PatchLoadedMissionModules()
            f = open('dedicated_init.log', 'a')
            f.write('DS_TIMER: TopWindowInitialized called OK\n')
            f.write('DS_TIMER: PatchLoadedMissionModules = ' + str(n) + '\n')
            f.close()
        else:
            print 'DS_TIMER3: Custom.DedicatedServer NOT in sys.modules!'
            f = open('dedicated_init.log', 'a')
            f.write('DS_TIMER ERROR: Custom.DedicatedServer not loaded\n')
            f.close()
    else:
        print 'DS_TIMER3: TopWindow is None'
        f = open('dedicated_init.log', 'a')
        f.write('DS_TIMER: TopWindow_GetTopWindow returned None\n')
        f.close()
except:
    ei = sys.exc_info()
    print 'DS_TIMER3 ERROR: ' + str(ei[0]) + ': ' + str(ei[1])
    try:
        f = open('dedicated_init.log', 'a')
        f.write('DS_TIMER Phase3 ERROR: ' + str(ei[0]) + ': ' + str(ei[1]) + '\n')
        f.close()
    except:
        print 'DS_TIMER3: ALSO FAILED to write log!'
```
**Verdict: PASS** - All constructs valid in 1.5.2. Nested try/except (not try/except/finally)
is correct. `is not None` comparison is valid in 1.5.2.

---

## Conclusion
**No Python 1.5.2 compatibility issues found in any of the three files.**
The codebase demonstrates excellent awareness of 1.5.2 limitations throughout.
