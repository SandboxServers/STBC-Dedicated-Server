# Phase 2 Boot Crash Analysis: 0x1C as Pointer

## Root Cause: TGL Load Failure -> Sentinel Value Used as Pointer

### The TGL System
- `FUN_006D03D0(path, flag)` loads a TGL file (Totally Games Layout - UI descriptor)
- `FUN_006D1E10(tgl, name)` looks up a named entry in the TGL by hash (binary search)
- On lookup FAILURE (or NULL param), returns `this + 0x1C` as a "default/empty" sentinel
- If `this == NULL` (load failed), the sentinel = `0 + 0x1C = 0x1C`

### The Crash Chain in FUN_00504F10 (CreateMultiplayerGame)
1. `FUN_006D03D0("data/TGL/Multiplayer.tgl", 1)` -> returns TGL object (or NULL on fail)
2. `FUN_006D1E10(tglObj, "Connection Completed")` -> if tglObj==NULL, returns 0x1C
3. Result (0x1C) passed to `FUN_006F4EE0(local_str, 0x1C)` -> reads [0x1C+8]=0x24 -> CRASH
4. Also passed to `FUN_005054B0()` which navigates scene graph and creates animations

### Why TGL Load Might Fail Headlessly
- `FUN_006D17E0` opens the file with fopen -- file must exist at game path
- If file exists, the parse functions `FUN_006D18B0` / `FUN_006D1980` process it
- A missing or corrupt data/TGL/Multiplayer.tgl causes NULL return

### Crash Sites (all from same 0x1C sentinel)
1. **0x006F4DA1** - `MOV ECX,[EBP+8]` in FUN_006F4D90 (wstring assign) - EBP=0x1C, reads 0x24 -> AV
2. **0x006F4EEC** - `MOV EAX,[EBX+8]` in FUN_006F4EE0 (wstring assign, non-null-checking variant)
3. **0x00731D43** - `MOV EAX,[EDI+8]` in FUN_00731D20 (TGAnimAction init)

All three are eliminated by PatchTGLFindEntry which returns NULL instead of 0x1C sentinel.

### Class Hierarchy at 0x00731D20
- `FUN_00731D20` = TGAnimAction::Init (init method, not constructor)
- `FUN_00731BB0` = TGAnimAction constructor (calls FUN_0072DE00 base ctor + Init)
- `FUN_0072DE00` = base class ctor (vtable PTR_FUN_00897C14)
- `FUN_0072FC20` = intermediate base ctor
- `FUN_006D8F90` = NiExtraData-derived base (vtable PTR_FUN_00896044)
- The object is 0x94 bytes, allocated by FUN_00717B70 (pool alloc)

### FUN_006D1E10 Default Sentinel Explanation
```c
int __thiscall FUN_006d1e10(void *this, char *name) {
    if (name == NULL) return (int)this + 0x1C;     // default entry
    idx = binary_search(this, name);
    if (idx == 0xFFFFFFFF) return (int)this + 0x1C; // not found
    return *(int*)(this + 0x14) + 4 + idx * 0x18;   // found entry
}
```
- `this + 0x1C` is a "null/empty" TGL entry embedded in the TGL object header
- When this==NULL, it becomes 0x1C -- a non-NULL but invalid pointer

### Fix Applied: PatchTGLFindEntry
Code cave at 0x006D1E10 adds `TEST ECX,ECX / JZ return_null` at function entry.
When this==NULL (TGL database failed to load), returns NULL instead of garbage
pointer this+0x1C. This single-point fix eliminates ALL downstream 0x1C crashes
across dozens of callers.
