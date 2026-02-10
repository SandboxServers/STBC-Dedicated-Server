# Renderer Pipeline Analysis (2026-02-09)

## FUN_007c3480 (NiDX7Renderer Setup)
- Called from renderer wrapper constructor (FUN_007e7af0 creates the 0x224-byte object first)
- PatchSkipRendererSetup jumps from 0x007C39CF to 0x007C3D75, skipping pipeline creation

### What the Pipeline Creates
| Offset | Created By | Purpose |
|--------|-----------|---------|
| 0x34 | FUN_007c9e50 | D3D device context (DirectDraw surface wrapper) |
| 0x18 | D3D caps check | D3D device pointer (from device context) |
| 0xC4 | FUN_007d4950 | Texture/pixel format manager |
| 0xB8 | FUN_007d2230 | Depth/stencil buffer manager |
| 0xBC | FUN_007ccd10 | Multi-sample/swap chain manager |
| 0xC0 | FUN_007d11a0 | Dynamic texture manager |
| 0xC8 | FUN_007cb2c0 | Vertex declaration cache |
| 0x2A4 | Flags byte | Capability flags (T&L, stencil, etc.) |

### Key Insight: NIF Loading Does NOT Use Pipeline Objects
- NiStream::Load is pure binary deserialization (file I/O only)
- NiNode, NiTriShape, NiGeometry, NiBound created from NIF binary data
- No D3D calls during NIF load
- D3D only needed when RENDERING scene graph (BeginScene/DrawPrimitive/EndScene)
- Texture conversion (NIF texture -> D3D surface) uses renderer texture manager
  but this is only needed for display, not for collision/networking

### Caps Check at Pipeline Entry
```
bStack_418 & 1  -- needs DRAWPRIMITIVES2EX
bStack_41c & 8  -- needs stencil ops
```
These come from Dev_GetCaps output. Current proxy sets these caps.

## Why Ship Subsystems Are Missing (NOT Renderer Related)
1. Ship creation is CLIENT-SIDE in STBC multiplayer
2. Client creates ship locally, sends creation data to server
3. Server must deserialize + run AddToSet("Scene Root", prop)
4. AddToSet needs NIF model loaded (for NiNode "Scene Root")
5. NIF model loading is FILE I/O, not renderer-dependent
6. Stock host has NO player ships (GetPlayer()=None)
7. Server never loads NIF models for remote players' ships

## Assessment: Removing PatchSkipRendererSetup
- Would create valid pipeline objects (0xB8/BC/C0/C4)
- Would NOT give ships subsystems (wrong causal chain)
- Would NOT fix client disconnect (that's missing object replication)
- MIGHT reduce BoundingBox VEH crashes (only if some objects get valid NiBound)
- PatchSkipDeviceLost still needed (device-lost checker always triggers)
- All other patches still needed (UI, TGL, Python, etc.)
- Net benefit: marginal. Risk: low-moderate.
