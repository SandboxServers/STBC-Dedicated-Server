> [docs](../README.md) / [analysis](README.md) / tgl-lookup-crash-analysis.md

# TGL Lookup Crash: Client AV at FUN_006f56f0 on Player Join

Reverse-engineered from stbc.exe via Ghidra decompilation and crash dump analysis.
Confidence: **High** (verified against decompiled functions, stack trace, and register snapshot).

## Summary

When a second client joins an OpenBC server with one client already connected, **both clients crash** at EIP=0x006F56F4 — a NULL dereference inside FUN_006f56f0 (WString-to-ASCII converter). The crash chain starts in `NewPlayerInGameHandler` (LAB_006a1590), an event-system callback that fires on each client when a new player joins. The handler loads `data/TGL/Multiplayer.tgl`, looks up the `"New Player"` localized string, and passes the result to the WString converter without validation.

### Key Discovery

Initial crash analysis identified the caller as FUN_006a1420 (opcode 0x18 DeletePlayerAnim handler), but **the actual crash originates from LAB_006a1590 (NewPlayerInGameHandler)** — an event-system callback, not an opcode handler. Return address 0x006A16A8 on the raw stack falls within the undefined code region at LAB_006a1590, which references `"data/TGL/Multiplayer.tgl"` at 0x006a16aa and `"New Player"` at 0x006a16bd.

The OpenBC server sends only opcode 0x2A (NewPlayerInGame), not 0x18 (DeletePlayerAnim), during player join — confirming the crash is in the event handler, not the opcode handler.

---

## Crash Chain

```
CLIENT EVENT SEQUENCE:
  Server sends opcode 0x2A (NewPlayerInGame) to existing client
    └─ Client's C++ dispatcher calls FUN_006a1e70 (opcode 0x2A handler)
       └─ FUN_006a1e70 creates ET_NEW_PLAYER_IN_GAME event
          └─ Event system dispatches to NewPlayerInGameHandler (LAB_006a1590)
             ├─ TGLManager_LoadFile("data/TGL/Multiplayer.tgl")  → returns TGLFile*
             ├─ TGLFile_FindEntry(tglFile, "New Player")         → returns 4 (BAD)
             └─ FUN_006f56f0(4)                                  → AV at 0x0000000C
```

### Why FindEntry Returns 4

TGLFile_FindEntry (FUN_006d1e10) found case:
```c
return *(int *)((int)this + 0x14) + 4 + uVar1 * 0x18;
//     ^^^^^^^^^^^^^^^^^^^^^^^^    ^   ^^^^^^^^^^^^^^
//     entryArray ptr = NULL (0)   |   index 0 × stride = 0
//                                 |
//                              header offset = 4
//
//     Result: 0 + 4 + 0 = 4
```

The TGLFile object exists (non-NULL `this`), and the binary search (FUN_006d1ea0) finds the entry name at index 0 — but the `entryArray` pointer at `this+0x14` is NULL. The calculation produces `NULL + 4 = 4`, a near-NULL invalid pointer.

### Why the WString Converter Crashes

FUN_006f56f0 receives `param_1 = 4`:
```c
iVar1 = *(int *)(param_1 + 8);    // *(4 + 8) = *(0x0C) → ACCESS VIOLATION
```

The function has **no null/range check** on `param_1`. Any near-NULL input is fatal.

---

## Affected Functions

### LAB_006a1590 — NewPlayerInGameHandler (CRASH SOURCE)

**Address**: 0x006a1590 (undefined in Ghidra — only visible as a function pointer stored by event registration)
**Registration**: FUN_0069efe0 registers this as `"MultiplayerGame::NewPlayerInGameHandler"`
**Trigger**: ET_NEW_PLAYER_IN_GAME event, fired when opcode 0x2A is received

This is NOT a Ghidra-defined function, so it cannot be directly decompiled. From xref analysis:
- At 0x006a16aa: references `s_data_TGL_Multiplayer_tgl_008e1900` (loads TGL file)
- At 0x006a16bd: references `s_New_Player_0095a340` (looks up "New Player" entry)
- Contains a call to FUN_006f56f0 (WString-to-ASCII) that crashes when FindEntry returns 4
- The return address `0x006A16A8` on the crash stack is the return from the `TGLManager_LoadFile` call inside this handler

**Structure mirrors FUN_006a1420** — both load the same TGL file and call FUN_006f56f0 with the result. LAB_006a1590 looks up `"New Player"` (join notification), FUN_006a1420 looks up `"Delete Player"` (disconnect notification).

### FUN_006a1420 — Opcode 0x18 DeletePlayerAnim Handler (SAME VULNERABILITY)

**Address**: 0x006a1420 – 0x006a1580
**Xref**: Single caller from `MultiplayerGame_ReceiveMessage` at 0x0069f4bc (case 0x18)

```c
void FUN_006a1420(void *param_1)
{
    // ... read player name from message stream ...

    pvVar2 = TGLManager_LoadFile("data/TGL/Multiplayer.tgl", 0x01);
    iVar1 = TGLFile_FindEntry(pvVar2, "Delete Player");
    FUN_006d04f0(&DAT_00997fd8, pvVar2);  // release TGL ref

    pbVar3 = FUN_006f56f0(iVar1);   // <--- CRASH IF iVar1 == 4 (bad ptr)

    // ... format "Player X has left" text ...
    // ... create floating text animation (5.0 seconds, 1.25 alpha) ...
}
```

**Key disassembly** (0x006a1488 – 0x006a14b6):
```asm
006a1488: PUSH 0x1                     ; param_2: loadFlags
006a148a: PUSH 0x8e1900                ; "data/TGL/Multiplayer.tgl"
006a148f: MOV  ECX,0x997fd8            ; TGLManager global
006a1494: CALL 0x006d03d0              ; TGLManager_LoadFile
006a1499: MOV  ESI,EAX                 ; ESI = TGLFile*
006a149b: PUSH 0x95a330                ; "Delete Player"
006a14a0: MOV  ECX,ESI                 ; ECX = TGLFile* (this)
006a14a2: CALL 0x006d1e10              ; TGLFile_FindEntry
006a14a7: PUSH ESI                     ; release param
006a14a8: MOV  ECX,0x997fd8            ; TGLManager global
006a14ad: MOV  EDI,EAX                 ; EDI = FindEntry result (4 if bad)
006a14af: CALL 0x006d04f0              ; TGLManager_Release
006a14b4: MOV  ECX,EDI                 ; ECX = FindEntry result
006a14b6: CALL 0x006f56f0              ; WString-to-ASCII (CRASH)
```

This handler is identical in vulnerability to LAB_006a1590. It has **not been observed crashing** because opcode 0x18 is only sent at disconnect time, and no disconnect trace has been captured. However, it will crash the same way if the TGL data is invalid.

### FUN_006a1360 — Opcode 0x17 DeletePlayerUI Handler (NOT AFFECTED)

**Address**: 0x006a1360 – 0x006a1411
**Xref**: Single caller at 0x0069f4a8 (case 0x17)

This is a pure event-system handler: creates a TGEvent, posts it to the event queue. **Does NOT load any TGL files** and **does NOT call FUN_006f56f0**. Confirmed safe.

### FUN_006f56f0 — WString-to-ASCII Converter (CRASH SITE)

**Address**: 0x006f56f0
**Convention**: `__fastcall(ECX=wstring_ptr)`, returns `char*`
**Xrefs**: 93 callers across the codebase

```c
void __fastcall FUN_006f56f0(int param_1)
{
    int iVar1 = *(int *)(param_1 + 8);          // length (CRASH: param_1=4 → read 0xC)
    int iVar2 = NiAlloc(iVar1 + 1);             // allocate ASCII buffer
    int iVar5 = 0;
    if (0 < iVar1) {
        do {
            ushort *puVar4;
            if (*(int *)(param_1 + 4) == 0) {   // wchar data ptr
                puVar4 = &DAT_00888b44;          // fallback empty wchar
            } else {
                puVar4 = (ushort *)(*(int *)(param_1 + 4) + iVar5 * 2);
            }
            ushort uVar3 = *puVar4;
            if (0xff < uVar3) uVar3 = 1;        // non-ASCII → substitute
            *(char *)(iVar5 + iVar2) = (char)uVar3;
            iVar5++;
        } while (iVar5 < iVar1);
    }
    *(char *)(iVar2 + iVar1) = 0;               // null-terminate
}
```

**No validation** on `param_1`. Any NULL or near-NULL value causes immediate AV.

### FUN_006d1e10 — TGLFile_FindEntry (EXISTING PATCH — SERVER ONLY)

```asm
006d1e10: MOV EAX,[ESP+4]      ; param_1 (entry name)
006d1e14: PUSH ESI
006d1e15: TEST EAX,EAX         ; NULL name check
006d1e17: MOV ESI,ECX          ; ESI = this (TGL object)
006d1e19: JNZ 0x006d1e22
006d1e1b: LEA EAX,[ESI+0x1c]   ; DEFAULT: return this+0x1c
006d1e1e: POP ESI
006d1e1f: RET 0x4
006d1e22: PUSH EAX
006d1e23: MOV ECX,ESI
006d1e25: CALL 0x006d1ea0       ; Binary search for name
006d1e2a: CMP EAX,-0x1
006d1e2d: JNZ 0x006d1e36
006d1e2f: LEA EAX,[ESI+0x1c]   ; NOT FOUND: return this+0x1c
006d1e32: POP ESI
006d1e33: RET 0x4
006d1e36: MOV ECX,[ESI+0x14]   ; FOUND: entryArray ptr
006d1e39: LEA EAX,[EAX+EAX*2]  ; idx * 3
006d1e3c: POP ESI
006d1e3d: LEA EAX,[ECX+EAX*8+4]; entryArray + idx*0x18 + 4
006d1e41: RET 0x4
```

**Existing proxy DLL patch** (PatchTGLFindEntry): adds `TEST ECX,ECX / JZ return_null` at function entry. When `this == NULL` (TGL file failed to load), returns NULL instead of `0x1C`.

**Limitation**: This patch only runs on the **server** (where the proxy DLL is loaded). Clients have unpatched code.

---

## TGL System Architecture

### TGL File Format

TGL files are localization/resource lookup tables stored in `data/TGL/`. The multiplayer system uses `Multiplayer.tgl` for UI text strings.

**TGLFile object structure** (0x2C bytes):
```
+0x00: byte   flags
+0x04: ptr    unknown1
+0x08: ptr    unknown2
+0x0C: ???
+0x10: uint   entryCount    (number of named entries)
+0x14: ptr    entryArray    (each entry = 0x18 bytes)
+0x18: ???
+0x1C: struct DEFAULT_ENTRY (fallback returned when name not found)
```

### TGL Loading Path

```
TGLManager_LoadFile (0x006d03d0)
  └─ TGLManager_LoadOrCache (0x006d11d0 / 0x006d03f0)
     ├─ Check cache: FUN_006d03f0(name)
     │   └─ If cached, return existing TGLFile*
     └─ If not cached:
         ├─ Allocate 0x2C bytes
         ├─ FUN_006d17e0: fopen + parse TGL file
         │   ├─ Success: populate entryCount, entryArray, entries
         │   └─ Failure: free memory, return NULL
         └─ Add to cache, return pointer
```

### Known TGL Lookup Sites in Multiplayer Code

| Caller | TGL File | Entry Name | Purpose |
|--------|----------|------------|---------|
| LAB_006a1590 | Multiplayer.tgl | "New Player" | Join notification text |
| FUN_006a1420 | Multiplayer.tgl | "Delete Player" | Disconnect notification text |
| FUN_00504f10 | Multiplayer.tgl | "Connection_Completed" | Connection complete text |
| FUN_004fe560 | Options.tgl | "Sensor_Interference" | Sensor interference label |
| FUN_0050d550 | Options.tgl | "Bad_Connection" | Bad connection label |

### Failure Mode: NULL Data Array

The crash occurs when the TGLFile object is successfully loaded (non-NULL `this`), but the internal `entryArray` at `this+0x14` is NULL. The binary search (FUN_006d1ea0) still reports finding the entry at index 0 — possibly because `entryCount` is non-zero while `entryArray` is uninitialized.

FindEntry computes: `NULL + 4 + 0 * 0x18 = 4` and returns 4. This value passes all downstream NULL checks (it's non-zero) but causes an access violation when FUN_006f56f0 reads `*(4 + 8) = *(0x0C)`.

---

## Crash Trigger Analysis

### Why Both Clients Crash

When the second client joins:

1. Server sends **opcode 0x2A** (NewPlayerInGame) to the first client
2. First client's MultiplayerGame_ReceiveMessage dispatches to FUN_006a1e70 (0x2A handler)
3. FUN_006a1e70 creates an ET_NEW_PLAYER_IN_GAME event and posts it
4. Event system fires **NewPlayerInGameHandler** (LAB_006a1590) on the first client
5. Handler loads Multiplayer.tgl → gets bad TGLFile → FindEntry returns 4 → FUN_006f56f0(4) → **AV**

The second client crashes because the server also sends 0x2A to it (or the same event fires locally as part of join processing). Both clients hit the same code path.

### Why This Doesn't Crash on Stock Servers

On a stock dedicated server:
- `data/TGL/Multiplayer.tgl` exists and parses correctly
- The `entryArray` is populated with valid entries
- FindEntry returns a valid pointer to the entry data
- FUN_006f56f0 successfully converts the WString to ASCII

On the OpenBC server, one of these conditions fails:
- The TGL file may be missing from the server's game directory
- The TGL file may be corrupt or in an unexpected format
- The TGLFile parse may fail silently, leaving entryArray as NULL while still returning the object

---

## Sibling Function Comparison

Both NewPlayerInGameHandler and DeletePlayerAnim follow the exact same pattern:

| Property | LAB_006a1590 (New Player) | FUN_006a1420 (Delete Player) |
|----------|--------------------------|------------------------------|
| Trigger | ET_NEW_PLAYER_IN_GAME event | Opcode 0x18 from C++ dispatcher |
| TGL file | data/TGL/Multiplayer.tgl | data/TGL/Multiplayer.tgl |
| Entry name | "New Player" (0x0095a340) | "Delete Player" (0x0095a330) |
| TGL ref string | 0x006a16aa | 0x006a148a |
| Entry ref string | 0x006a16bd | 0x006a149b |
| Calls FUN_006f56f0 | Yes | Yes (at 0x006a14b6) |
| Crash risk | **Active** (fires on every join) | Latent (fires only on disconnect) |
| Observed crash | **Yes** (this analysis) | Not yet (no disconnect observed) |

---

## Register Snapshot (from crash dump)

```
EIP = 0x006F56F4    ; inside FUN_006f56f0, first memory read
EDI = 0x00000004    ; FindEntry result (bad pointer)
Reading address: 0x0000000C = EDI + 8 = 4 + 8 = 0x0C

Raw stack includes:
  0x006A16A8        ; return address in NewPlayerInGameHandler
```

---

## Fix Guidance

### For OpenBC Reimplementation

1. **Validate TGL lookup results** before passing to string conversion functions. Check for NULL and near-NULL (< 0x1000) pointers.

2. **Validate TGLFile objects** after loading. Check that `entryArray != NULL` before allowing FindEntry to return computed pointers.

3. **Both handlers need protection**: NewPlayerInGameHandler (join) and DeletePlayerAnim handler (disconnect) use the same vulnerable pattern.

4. **Consider graceful degradation**: If the TGL entry is missing, use a hardcoded fallback string (e.g., `"Player joined"` / `"Player left"`) rather than crashing.

### For Proxy DLL (Server-Side)

The existing `PatchTGLFindEntry` only guards against `this == NULL`. The crash observed here has `this != NULL` but `this->entryArray == NULL`. The server-side patch does not protect clients.

A client-side fix would require either:
- Patching FUN_006f56f0 to check `param_1 < 0x1000` and return an empty string
- Patching the individual callers (LAB_006a1590, FUN_006a1420) to check FindEntry results
- Ensuring `data/TGL/Multiplayer.tgl` exists and is valid in the game installation

---

## Key Addresses

| Address | Function | Role |
|---------|----------|------|
| 0x006a1590 | NewPlayerInGameHandler | Event callback — crash source |
| 0x006a1420 | DeletePlayerAnim (opcode 0x18) | Opcode handler — same vulnerability |
| 0x006a1360 | DeletePlayerUI (opcode 0x17) | Event-only handler — NOT affected |
| 0x006f56f0 | WString-to-ASCII converter | Crash site — no input validation |
| 0x006d1e10 | TGLFile_FindEntry | Returns 4 when entryArray is NULL |
| 0x006d03d0 | TGLManager_LoadFile | Loads/caches TGL file objects |
| 0x006d1ea0 | TGLFile_BinarySearch | Finds entry by name |
| 0x0069f2a0 | ReceiveMessageHandler | Dispatches opcode 0x18 to FUN_006a1420 |
| 0x006a1e70 | NewPlayerInGame (opcode 0x2A) | Posts event that triggers LAB_006a1590 |
| 0x008e1900 | string: "data/TGL/Multiplayer.tgl" | TGL file path |
| 0x0095a330 | string: "Delete Player" | TGL entry for disconnect text |
| 0x0095a340 | string: "New Player" | TGL entry for join text |
| 0x00997fd8 | DAT_00997fd8 | TGLManager global instance |

---

## Related Documents

- [../networking/disconnect-flow.md](../networking/disconnect-flow.md) — Disconnect cleanup sequence (sends 0x14, 0x17, 0x18)
- [tgl-null-crash.md](../../.claude/agent-memory/game-reverse-engineer/tgl-null-crash.md) — Earlier TGL NULL analysis (Phase 2 boot context)
- [../protocol/game-opcodes.md](../protocol/game-opcodes.md) — Full opcode table
