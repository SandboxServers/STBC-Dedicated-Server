# Renderer Pipeline Restoration Analysis (2026-02-09)

## Architecture Decision: Let NiDX7Renderer Pipeline Build Fully

### Problem (RESOLVED)
PatchSkipRendererSetup was removed. Pipeline objects now build via proxy COM.
PatchDeviceCapsRawCopy prevents the raw 236-byte memcpy crash in FUN_007d1ff0.

### Required Proxy Changes
1. **Dev_EnumTextureFormats** - Must enumerate real pixel formats (R5G6B5, A1R5G5B5, A8R8G8B8, X8R8G8B8)
   - FUN_007c3480 uses callback FUN_007c3da0 to populate three format arrays at this+0x38/0x58/0x78
   - Empty arrays cause pipeline object creation to fail
2. **Dev_GetCaps** - Already implemented, but verify bits 0x1 (bStack_41c) and 0x8 (bStack_418) pass
3. Keep all draw calls as no-ops (already done)

### Active Renderer Patches
- PatchDeviceCapsRawCopy - prevents raw 236-byte memcpy from Device7
- PatchRendererMethods - stubs 3 vtable methods that access NULL state
- PatchSkipDeviceLost - always skip device-lost recreation path
- PatchRenderTick - JMP skip render work (no GPU cost)
- PatchTGLFindEntry - safety net for missing TGL files (unrelated to renderer)
- PatchHeadlessCrashSites - RET at entry of UI functions (unrelated to renderer)
- PatchNetworkUpdateNullLists - clears SUB/WPN flags when lists NULL

### Key Engine Architecture Facts
- NIF loading (NiStream::Load) is DECOUPLED from renderer - creates scene graph from file data
- NiBound computed by CPU-side NiAVObject::UpdateWorldBound() from NiTriShapeData vertices
- NiAVObject transforms (m_kLocal, m_kWorld) are pure data, no renderer needed
- Subsystems/weapons come from Python hardpoint scripts (ships/Hardpoints/*.py), NOT from NIF scene graph
- loadspacehelper.CreateShip: LoadModel() -> ShipClass_Create -> LoadPropertySet -> SetupProperties
- NIF provides geometry + named nodes; hardpoint files provide subsystem definitions
- SetupProperties (C++) creates subsystem objects from property set, populates linked lists

### FUN_007c3480 Pipeline Objects
- this+0xc4: Geometry accumulator (FUN_007d4950) - geometry batching
- this+0xb8: Texture manager (FUN_007d2230) - texture resource management
- this+0xbc: Render state manager (FUN_007ccd10)
- this+0xc0: Shader/effect manager (FUN_007d11a0)
All four must be non-NULL for NIF loading to produce complete scene graphs.

### Risk: Dev_EnumTextureFormats is make-or-break
If renderer can't enumerate any formats, texture manager at this+0xb8 fails to create,
and the pipeline build aborts at the nested if-chain, returning false.
Same outcome as current skip, just through different path.
