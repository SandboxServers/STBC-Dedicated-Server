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

## 0x005b22b5 - Subsystem hash check jump misalignment
- **Function:** `PatchSubsystemHashCheck` code cave in `src/proxy/ddraw_main/binary_patches_and_python_bridge.inc.c`
- **Instruction:** `JNE .call_real` (opcode `75 07` in the reported log, meant to skip the `MOV ECX,EDI` + `ADD ESP,4` + `JMP 0x005b22c7` block)
- **Exception:** Access violation at `EIP=0x00000000` recorded by `game/server/ddraw_proxy.log` (00:24:22.079, VEH[2]) with `EDI=0x005B22BA`, `ESI=0x0D10F390`, `EDX=0xC000000D`.
- **Root cause:** When `[ESI+0x284]` is non-NULL (valid subsystem list), the branch target should land at `.call_real` (the jump to `FUN_005b5eb0`). With the old `0x07` displacement the CPU jumps into the middle of the `ADD`/`JMP` sequence (offset 19 inside the cave) and begins executing garbage bytes, eventually attempting to execute `CALL [0x0]` and crashing with `EIP=0`. The decompiled context around `FUN_005b21c0` shows the hash comparison and the need for a stable hash return path.
- **Fix:** Update the displacement to `0x0A` so the branch skips the entire `MOV ECX,EDI`, `ADD ESP,4`, and `JMP 0x005b22c7` and lands cleanly at `.call_real`. This change matches the documented cave and the current source tree.
- **Validation:** Reproduce the scenario with real subsystem data (non-headless ship objects). Confirm no new VEH entry at `0x005b22b5`, and check `game/server/ddraw_proxy.log` for the “Valid subsystem list” debug line produced by `PatchSubsystemHashCheck`. Grep the built binary to ensure the `JNE` byte is `0x0A` and that the new branch executes instead of the crash path.

## 0x005B1EDB - Null subsystem handler in state update loop
- **Function**: Part of the state update subsystem iteration (inside `FUN_005b17f0`/`FUN_005b21c0` network update path). `EDI` points to the current ship object and `[EDI+0x30]` is the subsystem/weapon node being advanced.
- **Instruction**: `MOV EAX,[ECX]` at 0x005B1EDB (vtable load before invoking the subsystem update handler at `CALL [EAX+0x70]`).
- **Exception**: Read AV at `0x00000000` because `ECX` is zero; the preceding branch zeroes `ECX` when `[EDI+0x30] == NULL` but execution still hits the dereference instead of jumping past the call.
- **Root cause**: Headless server ships have no subsystems/weapons, so the linked-list head at `[ship+0x30]` stays `NULL`. The loop does not skip the vtable call in this case and dereferences the null pointer when trying to advance to the next subsystem. This race only happens during the per-frame NET state serialization loop that sets bits `0x20`/`0x80`.
- **Status**: Patch was previously documented (VEH/EIP skip at `0x005b1edb`/`0x005b1f82`) but is missing in this build. Crash occurs immediately after a client joins because the server is running without subsystem data.
- **Fix plan**: Insert a VEH/EIP skip or direct jump over the vtable call when `[EDI+0x30] == NULL`, mirroring the previously approved patch addresses. This is a low-risk fix (no state changes) that restores the early-out guarding branch and prevents dereferencing null.

## 0x005AF4E7 - FUN_005af4a0 null `param_2` dereference (`FLD [ESI+0x30]`)
- **Function**: `FUN_005af4a0` (called from `FUN_005afd70` aggregation loop)
- **Instruction**: `FLD DWORD PTR [ESI+0x30]` at `0x005AF4E7`
- **Exception**: Read AV at `0x00000030` with `ESI=0` (`0x00000000 + 0x30`)
- **Call chain evidence**:
- `game/server/crash_dump.log` raw stack includes return addresses `0x005AFE49` and `0x005AFC84`
- `0x005AFE44` is `CALL 0x005AF4A0` and `0x005AFE49` is post-call `FADD`
- `FUN_005afd70` loop loads `pvVar4 = (void*)*piVar3` and calls `FUN_005af4a0(this, pvVar4, ...)` without checking `pvVar4`
- **Root cause**: Candidate node list contains a NULL payload pointer (`*piVar3 == 0`), but `FUN_005af4a0` assumes non-NULL and dereferences immediately. Decompiler wrapper `FUN_005af5f0` already contains a NULL guard, confirming NULL should map to safe no-op return.
- **Low-risk mitigation**:
- Add null guard at `FUN_005afd70` call site (`0x005AFE36` path): if `EAX==0`, issue `FLDZ` then continue to `0x005AFE49` so FPU contract remains valid.
- Alternative: add entry guard in `FUN_005af4a0` returning `_DAT_00888b54` when stack arg `param_2` is NULL.
- **Status**: New crash site identified from 2026-02-12 01:10:40 logs; patch not yet implemented.
## 0x005054C7 - FUN_005054b0 MP Status Pane NULL child vtable call
- **Function**: FUN_005054b0 (UI status update, updates MP chat/status pane)
- **Instruction**: `MOV EAX,[ECX]` at 0x005054C7 — vtable load on NULL ECX
- **Exception**: Read AV at 0x00000000 (ECX=0)
- **Root cause**: FUN_0050e1b0(DAT_009878cc, 8) returns valid type-8 pane (vtable 0x0088E74C), but pane+0x60 (child sub-object) is NULL. No NULL check on +0x60 before vtable deref.
- **Object type**: MP status/chat pane (vtable 0x0088E74C, written by FUN_00504390 ctor and FUN_005587f0 ctor)
- **Why +0x60 is NULL**: Dedicated server never runs full UI initialization that populates child widgets
- **Callers**: FUN_006a5df0 (0x006a6112, "Server Found"/ObjCreate handler), FUN_006a3ea0 (0x006a404e, file receive), FUN_00504890 (2 sites), FUN_00504d30, FUN_00504f10, FUN_006a4c10
- **All callers use cdecl**: PUSH param / CALL / ADD ESP,4
- **Frequency**: 2x per server boot (during checksum/file transfer phase), FATAL
- **Fix**: RET patch (0xC3) at 0x005054b0 entry. Function is purely cosmetic (UI text update). No return value used by callers. cdecl clean, bare RET is safe.
- **Status**: NEW - needs 1-byte RET patch at 0x005054b0

## 0x006B569C - FUN_006b55b0 (TGNetwork::SendStateUpdates) corrupt peer array entry
- **Function**: FUN_006b55b0 (__fastcall, ECX=WSN ptr) -- serializes pending messages for each peer
- **Instruction**: `MOV DWORD PTR [ESI+0xAC], 0` (10 bytes: C7 86 AC 00 00 00 00 00 00 00)
- **Exception**: Write AV at 0x75625D20 (kernel32.dll memory)
- **Root cause**: Peer array (WSN+0x2C) element[0] contains 0x75625C74 (kernel32 address) instead of valid peer object. Corruption likely caused by VEH-recovered code execution at EIP=WSN+0x31 (0x0CCA8281) -- executing WSN data bytes as x86 code corrupts arbitrary memory.
- **ESI load site**: 0x006B5619: `MOV ESI, [EDX + EDI*4]` loads peer ptr from array
- **VEH precursor**: 9 repeating exceptions at EIP=0x0CCA8281 (WSN+0x31) with ECX=NULL every tick. This is a NULL-this vtable call that jumps into WSN data. VEH recovery allows data-as-code execution causing cascading corruption.
- **WSN layout for peer iteration**: WSN+0x2C = peer array ptr (param_1[0xb]), WSN+0x30 = peer count (param_1[0xc]), WSN+0x34 = peer array capacity
- **Peer object size**: 0xC0 bytes (allocated by FUN_006b7410). Key fields: +0x18=playerID, +0x1C=refID, +0x7C/+0x98/+0xB4=list counts, +0x9C/+0x80/+0x64=list head ptrs, +0xAC/+0x90/+0x74=iterator indices, +0xBC=flag byte
- **Callers of FUN_006b55b0**: FUN_006b4060 (at 0x006b4115), FUN_006b4560/TGNetwork_Update (at 0x006b4669, 0x006b4766)
- **Fix**: Find and fix the NULL-this vtable call that produces EIP=WSN+0x31. Also add defensive peer pointer validation at 0x006B5619.
- **Status**: NEW - needs root cause fix for the NULL-this call + defensive validation

## 0x0CCA8281 (dynamic, WSN+0x31) - Code execution inside WSN data object
- **Not a function**: EIP is inside the WSN data object (WSN=0x0CCA8250, offset +0x31)
- **Exception**: Read AV with ECX=0x00000000 (NULL this ptr dereference during data-as-code execution)
- **Registers**: ECX=0, EAX=0xF0E78519, EBP=0, EDX=0, ESI=0x0CE92344, EDI=1
- **Pattern**: Fires every tick (~50ms) after InitNetwork(2). 9 occurrences before fatal crash.
- **Root cause**: A NULL-this vtable call resolves to WSN+0x31 and the CPU executes WSN data bytes as x86 instructions. The VEH handler recovers but allows corrupt execution to continue, eventually corrupting the peer array.
- **Upstream cause**: Unknown -- need to identify which object has a NULL 'this' and which vtable offset maps to WSN+0x31. Likely in TGNetwork_Update call chain or a per-frame callback with a dangling/NULL object pointer.
- **Status**: NEW - root cause of the 0x006B569C crash. Needs investigation to find the NULL-this caller.

## Previously documented sites:
- 0x006D1E10 - TGL::FindEntry NULL+0x1C (FIXED: code cave PatchTGLFindEntry)
- 0x005b1d57 - Network update NULL lists (FIXED: code cave PatchNetworkUpdateNullLists)
- 0x005b22b5 - Subsystem hash check (FIXED: code cave PatchSubsystemHashCheck)
- 0x006d2eb0/0x006d2fd0 - Compressed vector read (FIXED: PatchCompressedVectorRead)
- 0x00419963 - AsteroidField ctor (addressed by renderer pipeline restoration)
- 0x004360CB - GetBoundingBox (addressed by renderer pipeline restoration)
