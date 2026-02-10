# Renderer Pipeline Crash: ProxyDevice7 Heap Over-Read (2026-02-09)

## Root Cause
NI engine code in FUN_007d1ff0 copies 59 DWORDs (236 bytes) from the IDirect3DDevice7
object pointer, treating it as a raw data block. This is because real D3D7 device objects
have internal state at known offsets that NI reads directly.

Our ProxyDevice7 is only 20 bytes (5 DWORDs). The copy reads 216 bytes past the allocation,
copying heap garbage into the texture format manager object (0x1E8-byte object from FUN_007d2230).

## Crash Chain
1. FUN_007c09c0 (NiDX7Renderer::Create) allocates renderer (0x2AC bytes, FUN_007bfe40)
2. FUN_007c3480 creates pipeline objects:
   a. Calls D3D7::CreateDevice -> stores ProxyDevice7* at renderer+0x18
   b. Calls FUN_007d4950 (pipeline caps manager) -- uses adapter data, NOT our Device7
   c. Calls FUN_007d2230 (texture format manager) -- passes Device7 as param_1
   d. FUN_007d2230 -> FUN_007d1ff0: copies 236 bytes FROM Device7 into texture mgr
   e. Garbage data becomes vtable pointers, capability flags, surface pointers
   f. Calls FUN_007ccd10 (render state manager)
   g. FUN_007ccd10 -> FUN_007cbe60: stores Device7 at this[0], copies caps to this+4
   h. FUN_007ccd10 -> FUN_007ce9c0: massive vtable-call function using corrupted data
3. Eventually a vtable call through corrupted data hits EIP=0x0

## Evidence: "Both AddRef to D3D7" Mystery EXPLAINED
In FUN_007ccd10 at 007ccdbe-007ccdca:
- `[ESI]` = piVar1[0] was set by FUN_007cbe60 to Device7 (at 007cc0f6)
- FUN_007cb2c0 calls AddRef on `[ESI]` (param2 = Device7) and on local_14 (param1 = D3D7)
- Both showed D3D7::AddRef because ProxyDevice7's lpVtbl was OVERWRITTEN by the
  FUN_007d1ff0 over-read propagating back through heap corruption or aliasing

## Fix Applied: PatchDeviceCapsRawCopy
Instead of enlarging ProxyDevice7, we zero the REP MOVSD count at 0x007d2119.
This prevents the 236-byte raw copy entirely. NI gets zeroed caps data which
means "no features supported" — safe for headless operation where we don't
actually render anything.

## Affected Functions
- FUN_007d1ff0 (texture format manager init): copies 59 DWORDs from Device7
- FUN_007d5080 (pipeline caps manager): reads Device7[0x21], [0x22], [0x17], [0]
  BUT this one gets adapter sub-object NOT our Device7 -- SAFE
- FUN_007cbe60 (render state manager): stores Device7 as pointer only, copies CAPS
  (not Device7 data) for bulk copy -- SAFE

## Key Addresses
| Address | Function | Role |
|---------|----------|------|
| 0x007d1ff0 | TextureFmtMgr init | OVER-READ: copies 236 bytes from Device7 |
| 0x007cbe60 | RenderStateMgr ctor | Stores Device7 ptr; copies from caps (safe) |
| 0x007ccd10 | RenderStateMgr create | Calls FUN_007cbe60 then FUN_007ce9c0 |
| 0x007ce9c0 | Texture validation | Massive vtable-call function; crashes on corrupted data |
| 0x007c3480 | Pipeline setup | Orchestrates all pipeline object creation |
| 0x007c09c0 | NiDX7Renderer::Create | Top-level renderer factory |
| 0x007cb2c0 | D3D7Wrapper ctor | Stores D3D7+Device7 ptrs, calls AddRef on both |
