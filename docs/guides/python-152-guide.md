> [docs](../README.md) / [guides](README.md) / python-152-guide.md

# Python 1.5.2 Survival Guide

Bridge Commander embeds Python 1.5.2 (released April 1999). This is not "old Python" — it is a fundamentally different language from modern Python. Code that looks correct to a modern eye will crash silently, corrupt state, or produce baffling errors.

All scripts in `src/scripts/` must be Python 1.5.2 compatible.

## Syntax Differences

### print is a statement, not a function
```python
# CORRECT (1.5.2)
print "hello"
print "value:", x

# WRONG - SyntaxError
print("hello")
```

### except uses comma, not 'as'
```python
# CORRECT (1.5.2)
try:
    something()
except Exception, e:
    print "Error:", e

# WRONG - SyntaxError
except Exception as e:
```

### No list comprehensions
```python
# CORRECT (1.5.2)
result = []
for x in items:
    result.append(x * 2)

# WRONG - SyntaxError
result = [x * 2 for x in items]
```

### No ternary expressions
```python
# CORRECT (1.5.2)
if condition:
    x = a
else:
    x = b

# WRONG - SyntaxError
x = a if condition else b
```

### No augmented assignment
```python
# CORRECT (1.5.2)
x = x + 1

# WRONG - SyntaxError
x += 1
```

### No nested scopes (closures)
```python
# WRONG - inner function can't see 'outer_var'
def outer():
    outer_var = 42
    def inner():
        return outer_var  # NameError!

# CORRECT - use default argument to capture
def outer():
    outer_var = 42
    def inner(_v=outer_var):
        return _v
```

This is why `DedicatedServer.py` uses default arguments extensively — it's the only way to capture variables in nested functions.

## Missing Builtins and Operations

### `in` operator does NOT work on dictionaries
```python
# WRONG - raises TypeError in 1.5.2
if key in my_dict:
    pass

# CORRECT
if my_dict.has_key(key):
    pass
```

This is the single most common mistake. Modern Python treats `in` on a dict as a key lookup. Python 1.5.2 does not support this.

### `in` operator does NOT work for substring search
```python
# WRONG - TypeError in 1.5.2
if "sub" in "substring":
    pass

# CORRECT
import strop
if strop.find("substring", "sub") >= 0:
    pass
```

Use `strop.find()` instead. The `strop` module is a C implementation of string operations available in 1.5.2.

### No `bool` type
```python
# These don't exist in 1.5.2
True   # NameError
False  # NameError

# Use integers instead
true_val = 1
false_val = 0
```

### No `os.path.join` (effectively)
The `os` module exists but is unreliable in BC's embedded interpreter. Use string concatenation for paths.

### No `str.startswith()` or `str.endswith()`
```python
# WRONG
if name.startswith("USS"):
    pass

# CORRECT
if name[:3] == "USS":
    pass
```

### No `str.replace()`
```python
# WRONG
s = s.replace("old", "new")

# CORRECT
import strop
s = strop.replace(s, "old", "new")
```

## BC-Specific Dangers

### Python errors can crash the server
In BC's embedded interpreter, an unhandled Python exception doesn't just print a traceback — it can corrupt the interpreter state and trigger `Py_FatalError`, which calls `abort()`. Our `PatchPyFatalError` and SIGABRT handler mitigate this, but wrapping code in `try/except` is still essential.

```python
# Always wrap risky operations
try:
    result = some_swig_call()
except:
    pass  # or log the error
```

### SWIG shadow classes don't exist
The `App` module in BC is a raw SWIG-generated C module. There are no Python shadow wrapper classes. You must use the **functional API**:

```python
# WRONG - no shadow classes
network = App.TGWinsockNetwork()
network.HostOrJoin(addr, pw, port)

# CORRECT - functional API
import App
wsn = App.UtopiaModule_GetNetwork(um)
App.TGNetwork_HostOrJoin(wsn, addr, pw, port)
```

Function names follow the pattern `ClassName_MethodName(self, args)`.

### SWIG type checking is strict
SWIG validates pointer types by their string suffix. You cannot cast between types:

```python
# WRONG - SWIG will reject this
App.TGWinsockNetwork_SomeMethod(tg_network_ptr)
# TypeError: Type error in argument 1 of TGWinsockNetwork_SomeMethod. Expected _p_TGWinsockNetwork
```

If a function wants `_p_TGWinsockNetwork` and you have `_p_TGNetwork`, there's no workaround in Python — you must find a function that returns the correct type.

### File writing is disabled
BC's embedded Python disables `open()` for write modes. You cannot create files from Python. Logging must go through C hooks (the proxy DLL's debug console redirect) or use `print` (which we redirect to `dedicated_console.log`).

```python
# WRONG - open() for writing raises IOError
f = open("mylog.txt", "w")

# CORRECT - use print (redirected to dedicated_console.log)
print "My log message"
```

The one exception: `dedicated_init.log` is opened from C before Python starts, and the file handle is passed through `sys._ds_base_path`.

### __import__ returns the top-level package
```python
# WRONG - this returns package 'A', not module 'C'
mod = __import__('A.B.C')

# CORRECT - after import, the module is in sys.modules
__import__('A.B.C')
mod = sys.modules['A.B.C']
```

### func_code replacement for event handlers
BC's event system holds direct references to function objects. Replacing a module attribute won't affect already-registered handlers. To patch a handler, replace its `func_code`:

```python
def wrapper(orig=original_func):
    try:
        orig()
    except:
        pass

original_func.func_code = wrapper.func_code
original_func.func_defaults = wrapper.func_defaults
```

This is how `DedicatedServer.py` wraps mission handlers with error handling.

## Testing Python Changes

There's no way to run BC's Python scripts outside the game — they depend on SWIG bindings that only exist in the game process. The testing workflow is:

1. Edit the `.py` file
2. `make run-server` (deploys and launches)
3. Check `dedicated_init.log` and `dedicated_console.log` for errors
4. If it crashes, check `crash_dump.log`

For syntax validation before deploying, you can use Python 2.7 as a rough check (it's more compatible with 1.5.2 than Python 3), but many 1.5.2 limitations won't be caught.

## Quick Reference

| Modern Python | Python 1.5.2 Equivalent |
|--------------|------------------------|
| `print(x)` | `print x` |
| `except E as e:` | `except E, e:` |
| `[x for x in y]` | `map/filter` or explicit loop |
| `x if c else y` | `if/else` block |
| `x += 1` | `x = x + 1` |
| `key in dict` | `dict.has_key(key)` |
| `"sub" in s` | `strop.find(s, "sub") >= 0` |
| `s.replace(a, b)` | `strop.replace(s, a, b)` |
| `s.startswith(x)` | `s[:len(x)] == x` |
| `True / False` | `1 / 0` |
| `os.path.join(a,b)` | `a + "\\" + b` |
| Closures | Default argument capture |
