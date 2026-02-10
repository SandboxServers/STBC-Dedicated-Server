# Compressed Vector Read Crash Analysis (2026-02-09)

## Crash: EIP=0x006D2EB8, accessing 0x00000051 (read)

### Functions
- **FUN_006d2eb0**: ReadCompressedVector3 - reads 3 bytes via vtable, decodes to 3 floats
  - Prologue: SUB ESP,0xC / PUSH ESI / MOV ESI,ECX
  - 4 vtable calls: 3x vtable+0x50 (ReadByte) + 1x vtable+0xB8 (decode, 6 stack params callee-clean)
  - Epilogue: POP ESI / ADD ESP,0xC / RET 0xC
- **FUN_006d2fd0**: Same structure, 4 params (RET 0x10), decode at vtable+0xB4 (7 stack params)
- **FUN_005b21c0**: Ship state update RECEIVER (processes incoming 0x1C packets)
  - Calls FUN_006d2eb0 twice (bit 0x04 and bit 0x08 of flags)
  - Calls FUN_006d2fd0 once (bit 0x02 of flags)
- **FUN_0069f930 / FUN_0069fbb0**: Game object replication, also call both functions

### Stream Reader Class
- Vtable: PTR_LAB_00895c58 (derived), PTR_FUN_00895d60 (base)
- Constructor: FUN_006cefe0 (derived), FUN_006d1fc0 (base)
- Destructor: FUN_006cf120
- vtable+0x50 = FUN_006cf540 (ReadByte)
- vtable+0x58 = FUN_006cf600 (ReadShort)
- vtable+0x70 = FUN_006cf6b0 (ReadFloat)
- vtable+0xB0 = FUN_006d2a60 (DecodeVector variant 1)
- vtable+0xB4 = 0x006d2ba0 (DecodeVector variant 2, 7 params, callee-clean)
- vtable+0xB8 = 0x006d2c60 (DecodeVector variant 3, 6 params, callee-clean)
- 0x006d2ba0 and 0x006d2c60 are NOT in Ghidra function database

### Root Cause: Corrupt Stream Reader Vtable
1. Stream reader object's vtable pointer is corrupted (value = 1 or 0)
2. FUN_006d2eb0 makes 4 vtable calls, all dereference invalid addresses
3. The 4th call (vtable+0xB8) has 6 PUSHED PARAMS (callee-clean convention)
4. If the callee never executes, 24 bytes are stranded on the stack
5. Function epilogue (POP ESI / ADD ESP,0xC / RET 0xC) uses wrong offsets
6. RET pops garbage as return address -> cascading crash through caller chain
7. Caller's ESP offset -> next LEA ECX,[ESP+0x58] gives wrong this ptr -> fatal

### Fix: PatchCompressedVectorRead
- Code caves at FUN_006d2eb0 and FUN_006d2fd0 entry points
- Validate vtable pointer is in stbc.exe .rdata range (0x00800000-0x008FFFFF)
- Also NULL-check ECX (this pointer)
- If invalid: zero-fill output float params, RET cleanly (no vtable calls)
- If valid: execute original prologue, JMP back to function body
- Prevents the cascading failure that corrupts the caller's stack

### Key Lesson: Generic Crash Recovery Cannot Handle Callee-Clean Vtable Calls
When a vtable call uses __thiscall/stdcall convention (callee cleans stack params),
and the callee never executes (EIP=0 from corrupt vtable), generic exception recovery
cannot restore the correct stack state -- the pushed params are stranded. This leaves
the stack misaligned for the epilogue, causing cascading crashes through the call chain.
The only safe approach is to validate the vtable BEFORE the call (PatchCompressedVectorRead).
