# InitNetwork Server Crash Analysis (Revised)

## CRITICAL CORRECTION: 0x0078xxxx is Python Parser, NOT NIF

The functions at 0x0078xxxx with "shift/push addchild" are the **Python 1.5.2 LALR
parser** (shift-reduce parser for building concrete syntax trees from Python source).
Evidence:
- "shift: no mem in addchild" = PyNode_AddChild allocation failure
- "push: no mem in addchild" = parser push operation failure
- "s_push: parser stack overflow" = parser stack overflow
- FUN_007839d0 references `s_<string>_0095dac8` and `DAT_009b3f44` (Py_VerboseFlag)
- FUN_0074b640 calls FUN_0074b860 = `Py_CompileString` -> parser
- FUN_00777780 is Python `exec` builtin, calls same parser chain

## Crash Sequence (3 events, same millisecond, tick 267)

### Crash 1: FUN_007840f0 at 0x00784182 (parse tree corruption)
- Instruction: `MOV word ptr [EAX], DX` writing to address 0x2F5C
- Function: **PyNode_AddChild** -- adds child to Python parse tree node
- EAX = 0x2F5C (small invalid address, not a valid heap pointer)
- The node's children array pointer (param_1+0x0C) contained garbage (0x2F5C area)
- Parse tree is corrupt at this point

### Crash 2: FUN_007179c0 at 0x007179FB (FATAL)
- Instruction: `MOV EDI, dword ptr [EBX + -0x4]` where EBX=0x003F003F
- Function: **NiRealloc** (used as Python's PyMem_Realloc)
- EBX = 0x003F003F = "??" ASCII -- garbage from corrupt parse tree
- Tries to read size header at 0x003F003B -> access violation
- Fatal crash (not a simple NULL deref)

### Crash 3: FUN_00717960 at 0x0071796B (FATAL)
- Instruction: `MOV EAX, dword ptr [EAX + -0x4]` where EAX=0x121
- Function: **NiFree** (used as Python's PyMem_Free)
- EAX = 0x121 (289) -- a size value mistakenly used as pointer
- Cascade from crash 2 corrupting allocator accounting

## Root Cause: GIL Violation + Heap Corruption

The Python memory allocator (FUN_00717840/FUN_007179c0/FUN_00717960) uses a
custom pool with 4-byte size headers before each allocation:

```
[size:4 bytes][data:N bytes]
              ^ returned pointer
```

The pool manager at DAT_0099c478 tracks allocations via sorted tables at
DAT_0099c484. Corrupting any allocation's header causes cascading failures.

### How corruption enters:

The HeartbeatThread (background) was calling PyRun_String concurrently with
GameLoopTimerProc (main thread). Python 1.5.2's allocator at 0x0099C478 has
zero thread safety. Concurrent malloc/free corrupts free lists and size headers.

By the time RunPyCode compiles the InitNetwork invocation string at tick 267,
the pool is corrupt. PyNode_AddChild gets a node whose children array
pointer (offset +0x0C) is 0x2F5C instead of NULL or a valid heap address.

### The "??" Signature

0x003F003F = two "?" characters. In Python 1.5.2 source code, "??" doesn't appear
in normal syntax. But if the allocator returned a buffer that overlaps with some
previously-freed string data, the parse tree node pointers could contain ASCII
text from that freed string. The "??" could be from:
- A URL or query string parameter
- An error format string
- Raw SWIG pointer format characters

## Key Insight: InitNetwork DID Succeed

The client received the MISSION_INIT_MESSAGE (screenshots show ship selection).
The Python code sent the message, then returned to C. The crash happens when
the C code's RunPyCode finishes and the engine processes the next tick -- or
possibly during cleanup of the Python execution context.

## Fix Applied
Remove ALL Python API calls from HeartbeatThread. The HeartbeatThread should only:
- Call EnumThreadWindows for dialog dismissal (Win32 API, safe)
- Read memory addresses for logging (read-only, safe enough)
- SetTimer on game window (posts WM_TIMER to main thread's queue, safe)

Move the 15-second diagnostic to a flag checked by GameLoopTimerProc on the main thread.
Strategy 2 gives immediate crash resilience. Strategy 4 reduces root cause.
