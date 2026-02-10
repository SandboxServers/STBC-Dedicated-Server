# Renderer Pipeline Restoration Analysis (2026-02-09)

## Architecture Decision: Let NiDX7Renderer Pipeline Build Fully

### Problem
PatchSkipRendererSetup (JMP at 0x007C39CF -> 0x007C3D75) skips pipeline object creation.
This leaves this+0xb8, 0xbc, 0xc0, 0xc4 NULL in the renderer, which cascades into:
- NIF loading producing incomplete geometry (no NiTriShapeData / no vertices)
- NiAVObject::Update() never computes valid NiBound from vertex data
- GetWorldBound() returning zero/NULL -> GetBoundingBox crash at FUN_004360c0
- FUN_005b17f0 state update packets with garbage data -> client sees ship as dead
- Subsystem/weapon linked lists empty -> VEH loop skips needed at 0x005b1edb/0x005b1f82

### Solution
Remove PatchSkipRendererSetup. Let FUN_007c3480 run fully. Fix proxy to support it.

### Required Proxy Changes
1. **Dev_EnumTextureFormats** - Must enumerate real pixel formats (R5G6B5, A1R5G5B5, A8R8G8B8, X8R8G8B8)
   - FUN_007c3480 uses callback FUN_007c3da0 to populate three format arrays at this+0x38/0x58/0x78
   - Empty arrays cause pipeline object creation to fail
2. **Dev_GetCaps** - Already implemented, but verify bits 0x1 (bStack_41c) and 0x8 (bStack_418) pass
3. Keep all draw calls as no-ops (already done)

### Patches to REMOVE after fix
- PatchSkipRendererSetup (0x007C39CF JMP)
- PatchNetworkUpdateNullLists (code cave at 0x005b1d57) - IF subsys/weapon lists populate
- VEH 0x005b1edb / 0x005b1f82 subsystem/weapon loop skips
- VEH 0x004360c0 GetBoundingBox crash handler

### Patches to KEEP
- PatchSkipDeviceLost (device-lost recreation path still dangerous)
- PatchTGLFindEntry (TGL UI data unrelated to renderer)
- PatchHeadlessCrashSites (UI crash sites unrelated)
- PatchRendererMethods (specific method stubs may still be needed)

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
