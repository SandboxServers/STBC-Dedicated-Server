# InitNetwork Crash Analysis (2026-02-07)

## Context
Black screen issue SOLVED. Server now crashes during InitNetwork execution when a client connects.

## The Two InitNetwork Implementations

### Original (reference scripts) - uses App shadow classes
```python
pMessage = App.TGMessage_Create()   # Returns TGMessagePtr shadow class
pMessage.SetGuaranteed(1)           # Shadow method call
kStream = App.TGBufferStream()      # Shadow class constructor
kStream.OpenBuffer(256)             # Shadow method call
```
App.TGMessage_Create (App.py:10604) wraps: `val = apply(Appc.TGMessage_Create,...); if val: val = TGMessagePtr(val)`

### Our replacement - uses Appc raw C module
```python
pMessage = Appc.TGMessage_Create()           # Returns raw SWIG pointer string
Appc.TGMessage_SetGuaranteed(pMessage, 1)    # Direct C call with raw pointer
kStream = Appc.new_TGBufferStream()           # Returns raw SWIG pointer string
Appc.TGBufferStream_OpenBuffer(kStream, 256)  # Direct C call with raw pointer
```

## Why Old Code Survived, New Code Crashes
- Old: App.TGMessage_Create returned raw string (shadow wrap failed) -> AttributeError -> caught by except:
- New: Appc functions parse raw pointer string, dereference C++ object directly -> if object invalid -> native crash (uncatchable)

## Threading Model (NOT the cause)
- GameLoopTimerProc: main thread, 33ms timer, calls RunPyCode for InitNetwork
- DedicatedServerTimerProc: main thread, 500ms timer, bootstrap only (done by InitNetwork time)
- HeartbeatThread: background thread, Python calls only in first 30s, then read-only C API
- WM_TIMER dispatched sequentially on main thread - no overlap between timer procs
- No Python re-entrancy possible between GameLoopTimerProc invocations

## MISSION_INIT_MESSAGE Value
- `App.MAX_MESSAGE_TYPES + 10` - compile-time constant from Appc module, always valid
- Likely value ~26-42, well within chr() range (0-255)

## C-Side wsprintfA Buffer
- Template ~450 bytes + 4 numeric substitutions in 512-byte buffer
- Tight but safe for typical peer IDs (small numbers)
- Recommend 1024 bytes for safety since wsprintfA has no bounds checking

## Most Likely Crash Causes
1. Appc.TGMessage_Create() returns None/garbage when message pool uninitialized
2. Appc.TGNetwork_SendTGMessage() accesses peer in transient state (connecting/disconnecting)
3. Game allocator broken in headless mode (full init sequence incomplete)

## Recommended Fix: Per-Call Logging
Add _logfn() before EVERY Appc.* call so last log line identifies the crashing function.
Add None/empty-string checks on every Create/new return value.
