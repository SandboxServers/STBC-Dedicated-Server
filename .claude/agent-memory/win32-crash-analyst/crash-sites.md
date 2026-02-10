# Crash Site Analysis

## 0x006CF1DC - TGNetworkStreamWriter cleanup writes dead marker to .rdata
- **Function**: FUN_006cf1c0 (cleanup/reset, also vtable entry at 0x00895C5C)
- **Instruction**: `MOV DWORD PTR [EAX], 0xFFFFFFFE` (6 bytes, 0x006CF1DC-0x006CF1E1)
- **Exception**: Write AV to 0x00895C58 (.rdata section, vtable for TGNetworkStreamWriter)
- **Root cause**: this+0x1C == 0 (buffer never attached), so function takes "no buffer" branch which writes dead marker through this+0x04. But this+0x04 IS the vtable address (0x00895C58), NOT the heap sub-object ptr.
- **Why this+0x04 = vtable**: The sub-object ptr at +0x04 was set correctly by base ctor FUN_006d1fc0. But this+0x00 IS the vtable. The dead marker path does `MOV EAX,[ECX+0x04]` which loads the sub-object ptr. At crash time, this+0x04 happens to contain 0x00895C58 -- meaning either (a) the sub-object heap alloc actually returned 0x00895C58 (impossible, it's .rdata), or (b) the object's memory was corrupted/shifted so +0x04 reads from +0x00.
- **Likely trigger**: VEH recovery at 0x00419963/0x004360CB (~100/sec) corrupts stack during FUN_006a1b10 (ChecksumCompleteHandler), causing FUN_006cf180 (Init) to be skipped or write to wrong offset. Result: this+0x1C stays 0.
- **Caller chain**: FUN_006a1b10 @ 0x006a1dbd -> FUN_006cf1c0 (direct call after packet send)
- **Status**: NOT handled by current VEH (faultAddr 0x00895C58 > 0x10000, not in NULL page)
- **Fix**: VEH targeted EIP skip: `if (isWrite && eip == 0x006CF1DC && faultAddr == 0x00895C58) ctx->Eip = 0x006CF1E2;`
- **Risk**: Very low. Dead marker write is diagnostic only, skipping has zero functional impact.
- **Important**: Must be checked BEFORE `faultAddr < 0x10000` guard since 0x00895C58 is not in NULL page.

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

## 0x006E2249 - Event dispatcher loop crash (VEH CASCADE ARTIFACT)
- **Function**: FUN_006e21d0 (event handler iterator, __thiscall)
- **Instruction**: `MOV EAX, [ESI+0x0C]` -- read handler count from this+0x0C
- **Exception**: Read AV at 0x0000002D (ESI=0x21 + 0x0C = 0x2D)
- **Root cause**: NOT a real game crash. This is the 4th crash in a VEH cascade:
  1. 0x006CF1DC FlatBufferStream dead-marker -> skip to RET
  2. RET pops 0x0 return addr -> blind stack scan -> jump to 0x0069F3E5 (ReceiveMessageHandler)
  3. 0x0069F3E5 dereferences EAX=0 -> EIP=0x5 -> stack scan -> jump to 0x006E2249
  4. ESI=0x21 (stale register from pre-cascade) -> crash
- **ESI=0x21**: Not a valid pointer. Stale value left in ESI because VEH jumped mid-function, bypassing prologue (MOV ESI,ECX at 0x006e21d4)
- **EDX=0xC000000D**: NTSTATUS STATUS_INVALID_PARAMETER from exception dispatch, not game code
- **Status**: NOT fixable with VEH skip. Symptom of cascade, not root cause.
- **Fix**: Cascade depth limiting in bad-EIP handler (see veh-cascade-analysis.md)
- **FUN_006e21d0 epilogue**: 0x006E2308 (POP EDI/ESI/EBP/EBX/ECX; RET 4)

## 0x0069F3E5 - ReceiveMessageHandler mid-function (VEH CASCADE ARTIFACT)
- **Function**: LAB_0069f2a0 (MultiplayerGame::ReceiveMessageHandler) -- NOT in Ghidra function DB
- **Role**: Main game opcode dispatcher, switch/jump-table at 0x0069F534
- **Context**: VEH bad-EIP handler found this address at ESP+48 during stack scan
- **Not a standalone crash**: Only appears as intermediate step in VEH cascade from 0x006CF1DC

## Previously documented sites (see project MEMORY.md for details):
- 0x006D1E10 - TGL::FindEntry NULL+0x1C (FIXED: code cave)
- 0x006F4DA1 - WString::Assign safe (FIXED: VEH EIP skip)
- 0x006F4EEC - WString::Assign unsafe (FIXED: VEH EBX redirect)
- 0x00731D43 - TGAnimAction::Init (FIXED: VEH EDI redirect)
- 0x005b1edb - subsystem list iteration (FIXED: VEH EIP skip)
- 0x005b1f82 - weapon list iteration (FIXED: VEH EIP skip)
- 0x00419963 - AsteroidField ctor (VEH handled, ~60-100/sec, NEEDS ROOT FIX)
- 0x004360CB - GetBoundingBox (VEH handled, frequent, NEEDS ROOT FIX)
