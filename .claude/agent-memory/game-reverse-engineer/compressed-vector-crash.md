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

### Root Cause: VEH Cascading Stack Corruption
1. Stream reader object's vtable pointer is corrupted (value = 1 or 0)
2. FUN_006d2eb0 makes 4 vtable calls, all fail (EIP=0)
3. VEH handler recovers from each: pops return address, sets EAX=0, resumes
4. The 4th call (vtable+0xB8) had 6 PUSHED PARAMS that the callee was supposed to clean
5. Callee never ran -> 24 bytes stranded on stack
6. Function epilogue (POP ESI / ADD ESP,0xC / RET 0xC) uses wrong offsets
7. RET pops garbage as return address -> EIP=0x04752402 (another VEH fix)
8. VEH finds real return address deeper on stack but adjusts ESP incorrectly
9. Caller's ESP is now 12 bytes off -> next LEA ECX,[ESP+0x58] gives wrong this ptr
10. Second call to FUN_006d2eb0 reads [wrong_addr] = 1, CALL [1+0x50] -> fatal crash

### Fix: PatchCompressedVectorRead
- Code caves at FUN_006d2eb0 and FUN_006d2fd0 entry points
- Validate vtable pointer is in stbc.exe .rdata range (0x00800000-0x008FFFFF)
- Also NULL-check ECX (this pointer)
- If invalid: zero-fill output float params, RET cleanly (no vtable calls)
- If valid: execute original prologue, JMP back to function body
- Prevents the cascading VEH failure that corrupts the caller's stack

### Key Lesson: VEH Cannot Safely Recover from Callee-Clean Vtable Calls
When a vtable call uses __thiscall/stdcall convention (callee cleans stack params),
and the callee never executes (EIP=0 crash), the VEH handler only pops the return
address but NOT the stack params. This leaves the stack misaligned for the epilogue.
Generic VEH recovery is UNSAFE for functions with callee-clean vtable calls.
The only safe approach is to prevent the crash from reaching the vtable call.
