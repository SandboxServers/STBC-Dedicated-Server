# Crash Site Analysis

## 0x006CF1DC - TGNetworkStreamWriter cleanup writes dead marker to .rdata
- **Function**: FUN_006cf1c0 (cleanup/reset, also vtable entry at 0x00895C5C)
- **Instruction**: `MOV DWORD PTR [EAX], 0xFFFFFFFE` (6 bytes, 0x006CF1DC-0x006CF1E1)
- **Exception**: Write AV to 0x00895C58 (.rdata section, vtable for TGNetworkStreamWriter)
- **Root cause**: this+0x1C == 0 (buffer never attached), so function takes "no buffer" branch which writes dead marker through this+0x04. But this+0x04 IS the vtable address (0x00895C58), NOT the heap sub-object ptr.
- **Why this+0x04 = vtable**: The sub-object ptr at +0x04 was set correctly by base ctor FUN_006d1fc0. But this+0x00 IS the vtable. The dead marker path does `MOV EAX,[ECX+0x04]` which loads the sub-object ptr. At crash time, this+0x04 happens to contain 0x00895C58 -- meaning either (a) the sub-object heap alloc actually returned 0x00895C58 (impossible, it's .rdata), or (b) the object's memory was corrupted/shifted so +0x04 reads from +0x00.
- **Caller chain**: FUN_006a1b10 @ 0x006a1dbd -> FUN_006cf1c0 (direct call after packet send)
- **Status**: Addressed by removing the double FUN_006a1e70 call that caused the race condition. CrashDumpHandler logs full diagnostics if it recurs.

## Vtable layout at 0x00895C58 (TGNetworkStreamWriter derived vtable):
- +0x00: 0x006CF170 (unknown method)
- +0x04: 0x006CF1C0 (FUN_006cf1c0 = cleanup/reset)

## FUN_006a1b10 stream object lifecycle:
1. 0x006a1c89: construct TGNetworkStreamWriter on stack (FUN_006cefe0)
2. 0x006a1cab: Init(buffer, 0x100) -- sets this+0x1C (FUN_006cf180)
3. 0x006a1cb6-0x006a1d3a: write settings data (game time, flags, map name, etc.)
4. 0x006a1d95: get written size (FUN_006cf9b0, reads this+0x24)
5. 0x006a1da2: copy to network packet (FUN_006b84d0)
6. 0x006a1db4: send packet (FUN_006b4c10)
7. 0x006a1dbd: cleanup/reset (FUN_006cf1c0) <<< CRASH IF this+0x1C==0
8. 0x006a1dd5-0x006a1dfb: build+send 1-byte marker packet
9. 0x006a1e21: destructor (FUN_006cf120)

## 0x006E2249 - Event dispatcher loop crash (cascade artifact)
- **Function**: FUN_006e21d0 (event handler iterator, __thiscall)
- **Instruction**: `MOV EAX, [ESI+0x0C]` -- read handler count from this+0x0C
- **Exception**: Read AV at 0x0000002D (ESI=0x21 + 0x0C = 0x2D)
- **Root cause**: Cascade crash from 0x006CF1DC. Not a standalone crash site.
- **ESI=0x21**: Stale register value, not a valid pointer
- **EDX=0xC000000D**: NTSTATUS STATUS_INVALID_PARAMETER from exception dispatch, not game code
- **FUN_006e21d0 epilogue**: 0x006E2308 (POP EDI/ESI/EBP/EBX/ECX; RET 4)

## 0x0069F3E5 - ReceiveMessageHandler mid-function (cascade artifact)
- **Function**: LAB_0069f2a0 (MultiplayerGame::ReceiveMessageHandler) -- NOT in Ghidra function DB
- **Role**: Main game opcode dispatcher, switch/jump-table at 0x0069F534
- **Not a standalone crash**: Only appears as intermediate step in cascade from 0x006CF1DC

## Previously documented sites:
- 0x006D1E10 - TGL::FindEntry NULL+0x1C (FIXED: code cave PatchTGLFindEntry)
- 0x005b1d57 - Network update NULL lists (FIXED: code cave PatchNetworkUpdateNullLists)
- 0x005b22b5 - Subsystem hash check (FIXED: code cave PatchSubsystemHashCheck)
- 0x006d2eb0/0x006d2fd0 - Compressed vector read (FIXED: PatchCompressedVectorRead)
- 0x00419963 - AsteroidField ctor (addressed by renderer pipeline restoration)
- 0x004360CB - GetBoundingBox (addressed by renderer pipeline restoration)
