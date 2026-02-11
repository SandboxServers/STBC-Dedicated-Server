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

## 0x006CF628 - TGNetworkStream::ReadUint16 NULL buffer dereference
- **Function**: FUN_006cf600 (ReadUint16, __fastcall, ECX=stream reader)
- **Instruction**: `MOV AX, [ESI+EAX]` (4 bytes: 66 8B 04 06) at 0x006CF628
- **Exception**: Read AV at 0x00000021 (ESI=0 buffer ptr, EAX=0x21 position)
- **Root cause**: Stream reader this+0x1C (buffer pointer) is NULL while this+0x20 (size) is >= 35, allowing bounds check to pass. The NULL buffer then dereferences at offset 0x21.
- **How buffer becomes NULL**: FUN_006b8530 returns *(source+0x04) as buffer ptr and *(source+0x08) as size. If source has NULL data ptr but non-zero size field, stream reader Init sets buffer=NULL, size=N. All reads crash.
- **Alternative**: Buffer corruption during multi-read sequence (pos advanced to 0x21 = 33 bytes already read). Prior reads succeeded (FUN_006cf540, FUN_006cf580, FUN_006cf670, FUN_006cf6b0 all dereference this+0x1C). Something may zero +0x1C between the last successful read and this one.
- **Caller**: FUN_005b21c0 (ship network state update receiver) at 0x005B2619 (return addr on stack)
- **Caller chain**: Stack shows 0x005B2619 -> 0x005B22BA -> 0x005B7314
- **Frequency**: Every network state update frame for each ship object = potentially high frequency
- **Fix**: Code cave at 0x006CF625 (7 bytes: `8B 71 1C 66 8B 04 06`). Check ESI (buffer ptr) for NULL after loading, return 0 if NULL. Same safe behavior as existing out-of-bounds error path.
- **Status**: NEW - needs code cave implementation

### FUN_006cf600 disassembly (complete):
```
006CF600: 56              PUSH ESI
006CF601: 8B 71 20        MOV ESI, [ECX+0x20]    ; size
006CF604: 8B 41 24        MOV EAX, [ECX+0x24]    ; position
006CF607: 8D 50 02        LEA EDX, [EAX+2]       ; pos+2
006CF60A: 3B D6           CMP EDX, ESI            ; (pos+2) vs size
006CF60C: 7E 17           JLE 0x006CF625          ; if in-bounds, goto read
; --- error path ---
006CF60E: 8B 41 04        MOV EAX, [ECX+0x04]
006CF611: 5E              POP ESI
006CF612: C7 00 FC FF FF FF MOV [EAX], 0xFFFFFFFC  ; error code -4
006CF618: 8B 41 24        MOV EAX, [ECX+0x24]
006CF61B: 83 C0 02        ADD EAX, 2
006CF61E: 89 41 24        MOV [ECX+0x24], EAX    ; advance position
006CF621: 66 33 C0        XOR AX, AX             ; return 0
006CF624: C3              RET
; --- success path ---
006CF625: 8B 71 1C        MOV ESI, [ECX+0x1C]    ; buffer ptr (NULL at crash)
006CF628: 66 8B 04 06     MOV AX, [ESI+EAX]      ; read uint16 (CRASH)
006CF62C: 89 51 24        MOV [ECX+0x24], EDX    ; store pos+2
006CF62F: 5E              POP ESI
006CF630: C3              RET
; --- padding ---
006CF631-006CF63F: NOP (15 bytes alignment)
```

## 0x00507F83 - Subtitle Pane NULL this (FUN_00507f80, "AddSubtitleFromText")
- **Function**: FUN_00507f80 (__thiscall, param_1=text ptr, RET 4)
- **Instruction**: `MOV AL, [ESI+0x50]` at 0x507F83 (ESI = copy of ECX = this)
- **Exception**: Read AV at 0x00000050 (NULL+0x50)
- **Root cause**: FUN_0050e1b0(DAT_009878cc, 5) returns NULL because subtitle pane (type 5) never created in dedicated server mode. Caller FUN_0055c810 passes NULL as ECX without checking.
- **Trigger**: NewPlayerInGame (opcode 0x2A) notification "New Player (X) has entered the game."
- **Call chain**: Network opcode 0x2A -> notification queued -> FUN_007008e0 (event scheduler, ret 0x00700975) -> FUN_0055c810 (subtitle callback, ret 0x0055C83A) -> FUN_00507f80 CRASH
- **Related functions**: FUN_0055c810, FUN_0055c860, FUN_0055c890 all call FUN_0050e1b0(DAT_009878cc, 5) -> NULL -> crash
- **Fix**: PatchHeadlessCrashSites (RET patch) must be enabled for ALL modes, not just headless. Also add FUN_0055c890 (0x56 first byte) to patch list.
- **Key insight**: "Real renderer = valid UI panes" is FALSE. Dedicated server skips normal menu flow regardless of renderer mode.
- **Status**: Fix recommended (re-enable PatchHeadlessCrashSites unconditionally + add 0x0055c890)

## UI Pane Lookup System
- **FUN_0050e1b0(this, type)**: Iterates linked list at this+0x34, matches element+0x4C == type
- **DAT_009878cc**: Pane manager object. In headless=zeroed dummy. In hybrid=real but INCOMPLETE (no subtitle pane).
- **Type 4**: Used by FUN_005032d0 and multiplayer code (0x006a3b70 etc.) -- different pane
- **Type 5**: Subtitle/notification pane -- never created in dedicated server mode
- **Type 8**: Used by multiplayer chat code
- **0x0099C478**: Memory pool allocator (static global, NOT related to subtitle pane)

## 0x006D20E0 - NiStream base class fclose on invalid FILE* (STATUS_INVALID_HANDLE)
- **Function**: FUN_006d20e0 (__fastcall, ECX=NiStream base object)
- **Instruction**: `CALL FUN_0085a047` (fclose) on `*(this+0x08)` which is non-NULL but invalid
- **Exception**: STATUS_INVALID_HANDLE (0xC0000008) raised by ntdll during NtClose
- **Root cause**: TGNetworkStream object's base class +0x08 (FILE*) field is non-NULL but contains an invalid/stale file handle. The base constructor zeros this field, so it must be corrupted after construction -- likely stack reuse overlap with NiStream file-loader, heap corruption, or double-destroy scenario.
- **Call chain**: FUN_005b21c0 (network state update) -> TGNetworkStream destructor FUN_006cf120 -> FUN_006cf1c0 (derived cleanup) -> FUN_006d2050 (base dtor) -> FUN_006d20e0 (file close) -> FUN_0085a047 (fclose) -> ntdll STATUS_INVALID_HANDLE
- **Stack evidence**: EDI="r.py" (Python filename fragment), ESP+10="Miss" (Mission), file descriptor 0x9D at ESP+08
- **SEH cascade**: STATUS_INVALID_HANDLE unhandled -> SEH chain walk -> hits 0xFFFFFFFF sentinel -> access violation -> nested exception -> stack overflow
- **RET patch at 0x006CF1DC is NOT the cause**: That patch affects dead-marker write at *(this+0x04), completely separate from FILE* at +0x08
- **Fix**: Code cave at 0x006D20E0 to validate FILE* pointer before fclose (check range, skip close if pointer is in .text/.rdata). Or: find and fix the corruption that puts a non-NULL invalid value in +0x08.
- **Status**: NEW - needs defensive fix at FUN_006d20e0

## Previously documented sites:
- 0x006D1E10 - TGL::FindEntry NULL+0x1C (FIXED: code cave PatchTGLFindEntry)
- 0x005b1d57 - Network update NULL lists (FIXED: code cave PatchNetworkUpdateNullLists)
- 0x005b22b5 - Subsystem hash check (FIXED: code cave PatchSubsystemHashCheck)
- 0x006d2eb0/0x006d2fd0 - Compressed vector read (FIXED: PatchCompressedVectorRead)
- 0x00419963 - AsteroidField ctor (addressed by renderer pipeline restoration)
- 0x004360CB - GetBoundingBox (addressed by renderer pipeline restoration)
