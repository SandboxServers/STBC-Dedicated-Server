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

### Crash 1: FUN_007840f0 at 0x00784182 (RECOVERED by VEH)
- Instruction: `MOV word ptr [EAX], DX` writing to address 0x2F5C
- Function: **PyNode_AddChild** -- adds child to Python parse tree node
- EAX = 0x2F5C (small invalid address, not a valid heap pointer)
- The node's children array pointer (param_1+0x0C) contained garbage (0x2F5C area)
- VEH caught it as "NULL write+0x2F5C", redirected EAX to g_pNullDummy+0x2F5C
- Parse tree node written to dummy memory -> tree is now corrupt

### Crash 2: FUN_007179c0 at 0x007179FB (FATAL)
- Instruction: `MOV EDI, dword ptr [EBX + -0x4]` where EBX=0x003F003F
- Function: **NiRealloc** (used as Python's PyMem_Realloc)
- EBX = 0x003F003F = "??" ASCII -- garbage from corrupt parse tree
- Tries to read size header at 0x003F003B -> access violation
- NOT catchable by VEH (not a low-address NULL deref)

### Crash 3: FUN_00717960 at 0x0071796B (FATAL)
- Instruction: `MOV EAX, dword ptr [EAX + -0x4]` where EAX=0x121
- Function: **NiFree** (used as Python's PyMem_Free)
- EAX = 0x121 (289) -- a size value mistakenly used as pointer
- Cascade from crash 2 corrupting allocator accounting

## Root Cause: Heap Corruption from VEH Read Fixes

The Python memory allocator (FUN_00717840/FUN_007179c0/FUN_00717960) uses a
custom pool with 4-byte size headers before each allocation:

```
[size:4 bytes][data:N bytes]
              ^ returned pointer
```

The pool manager at DAT_0099c478 tracks allocations via sorted tables at
DAT_0099c484. Corrupting any allocation's header causes cascading failures.

### How corruption enters:

1. During Phase 2 bootstrap and ongoing engine ticks, VEH read fixes replace
   NULL pointers with g_pNullDummy (a 64KB zeroed buffer). Any engine code
   that reads a "size" or "count" from this dummy gets 0, and any code that
   reads a "pointer" gets 0x00000000.

2. The Python allocator shares the same NiAlloc pool with the engine. If any
   engine operation writes through a VEH-redirected pointer, it can corrupt
   allocator metadata (size headers, free lists, pool tables).

3. By the time RunPyCode compiles the InitNetwork invocation string at tick 267,
   the pool is subtly corrupt. PyNode_AddChild gets a node whose children array
   pointer (offset +0x0C) is 0x2F5C instead of NULL or a valid heap address.

4. VEH "fixes" the 0x2F5C write but this makes things worse -- the parse tree
   continues with garbage data, eventually feeding 0x003F003F ("??") to NiRealloc.

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

## Fix Strategies

### Strategy 1: Isolate Python's Memory Pool (BEST)
Patch the Python allocator entry points to use standard CRT malloc/free/realloc
instead of NiAlloc pool. This prevents engine VEH fixes from corrupting Python's
heap. Patch:
- FUN_00718d60 callers from Python: redirect to malloc wrapper
- OR: patch Python's internal allocator at a higher level

### Strategy 2: Catch Fatal Allocator Crashes in VEH
Extend VEH to handle crashes in 0x00717xxx range (allocator) by:
- If EIP is in FUN_007179c0 (NiRealloc) and the fault is from reading size header
  at [ptr-4], return NULL (allocation failure) instead of crashing
- If EIP is in FUN_00717960 (NiFree) and the fault is from reading size header,
  skip the free (leak the memory) instead of crashing

### Strategy 3: Prevent Heap Corruption at Source
Make VEH NULL-write handler safer: instead of redirecting writes to g_pNullDummy,
skip the instruction entirely (advance EIP past the instruction). This prevents
writes to dummy memory that corrupt shared data structures.

### Strategy 4: Reduce VEH Fix Count
Identify and patch the specific engine functions that trigger VEH read/write
fixes most frequently, replacing them with proper stubs. Fewer VEH fixes
means less chance of corruption.

### RECOMMENDED: Strategy 2 (VEH allocator protection) + Strategy 4 (reduce fixes)
Strategy 2 gives immediate crash resilience. Strategy 4 reduces root cause.
