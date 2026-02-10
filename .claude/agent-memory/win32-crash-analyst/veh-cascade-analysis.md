# VEH Cascade Analysis: FlatBufferStream -> Event Dispatcher Crash (2026-02-10)

## Log Sequence
```
VEH-FIX: FlatBufferStream dead-marker write at EIP=0x006CF1DC to 0x00895C58 skipped (#1)
VEH-FIX: bad EIP=0x0, return to 0x0069F3E5 (ESP+48, fix #2)
VEH-FIX: bad EIP=0x5, return to 0x006E2249 (ESP+10, fix #3)
!!! CRASH: EIP=0x006E2249 accessing 0x0000002D (read)
```

## Crash Chain Reconstruction

### Fix #1: FlatBufferStream dead-marker (SAFE)
- EIP=0x006CF1DC: `MOV [EAX], 0xFFFFFFFE` writing to .rdata at 0x00895C58
- Skip to 0x006CF1E2 (RET) -- correct, dead marker is diagnostic only
- Problem: the RET pops 0x00000000 from stack = corrupted return address

### Fix #2: Bad EIP=0x0 (DANGEROUS)
- Stack-scan found 0x0069F3E5 at ESP+48 (12 DWORDs deep)
- 0x0069F3E5 is inside MultiplayerGame::ReceiveMessageHandler (LAB_0069f2a0)
- Handler set ESP += 52, EAX = 0
- Destroyed: All callee-saved registers (ESI, EDI, EBX, EBP) from intermediate frames
- Result: Code at 0x0069F3E5 executes with wrong stack frame

### Fix #3: Bad EIP=0x5 (DANGEROUS)
- Code at 0x0069F3E5 dereferenced EAX=0 (set by fix #2), went to vtable+0x5 = 0x5
- Stack-scan found 0x006E2249 at ESP+10 (4 DWORDs deep)
- 0x006E2249 is mid-loop in FUN_006e21d0 (event handler dispatcher)
- ESI=0x21 (stale from pre-cascade context), not the event dispatcher `this`

### Fix #4: Final crash (UNRECOVERABLE without cascade limit)
- `MOV EAX, [ESI+0x0C]` where ESI=0x21 -> read from 0x2D -> access violation
- ESI should be event dispatcher `this`, but function prologue never ran in this recovery path
- Adding VEH fix here would leave event system recursion counter corrupted (this+0x30)

## Why the Return Address Was 0x00000000

The immediate caller of FUN_006cf1c0 is ChecksumCompleteHandler (FUN_006a1b10).
The TGNetworkStreamWriter is a STACK-LOCAL object in FUN_006a1b10.
The return address for FUN_006cf1c0 should be ~0x006a1dc2 (instruction after CALL at 0x006a1dbd).

The zero return address means the stack frame of FUN_006a1b10 was corrupted.
Most likely cause: the 100/sec AsteroidField/GetBoundingBox VEH recoveries run on the SAME
thread during re-entrant event dispatch, and their stack manipulation (ESP adjustments)
corrupts the outer function's frame.

## Register Analysis at Final Crash
- EAX=0x01290000: g_pNullDummy (from VEH redirect between fix #3 and crash)
- ESI=0x21: stale register, not valid `this` ptr
- EDX=0xC000000D: NTSTATUS STATUS_INVALID_PARAMETER leaked from exception dispatch
- EBX=0x0472F10C, ECX=0x0470B200, EDI=0x043C7E54, EBP=0x04745A24: heap ptrs from destroyed frames

## Key Functions in the Chain
- FUN_006cf1c0 (0x006CF1C0): TGNetworkStreamWriter::Cleanup -- initial crash site
- LAB_0069f2a0 (gap, no function): MultiplayerGame::ReceiveMessageHandler -- jump table dispatcher
- FUN_006e21d0 (0x006E21D0-0x006E230D): Event handler iterator
- FUN_006db620 (0x006DB620): Event dispatch lookup, calls FUN_006e21d0
- FUN_006e0c30 (0x006E0C30): Handler invocation via function pointer

## Recommendation: Cascade Depth Limiting
Instead of adding targeted fixes at each cascade step, implement a cascade counter:
1. Track consecutive bad-EIP recoveries (increment on each, reset to 0 on successful instruction)
2. After 2 consecutive bad-EIP recoveries, stop stack-scanning
3. Instead: longjmp to game loop recovery point, or skip to known-safe frame
4. This loses the current event dispatch but preserves game state stability
