# Headless Server Approaches Analysis (2026-02-09)

## Key Finding: NI 3.1 Has No Headless Mode
- No NiNullRenderer, NiHeadlessRenderer, or server mode in STBC binary
- NiHeadlessRenderer introduced in Gamebryo 2.3+ (circa 2005-2006)
- Only one renderer class: NiDX7Renderer (vtable PTR_LAB_0089902c, 0x224 bytes)

## NIF Loading Does NOT Need Renderer
- NiStream::Load (FUN_008176b0) is pure data deserialization
- Reads block type names, looks up class factory at DAT_009a2b98, instantiates
- NiTriShapeData computes local bounding sphere from vertices (CPU math)
- NiSourceTexture post-load stores NULL texture handle if no renderer (does not crash)
- DX7 vertex buffers created lazily on first render, not during load

## NiBound Computation Chain
- NiAVObject::Update() -> UpdateWorldData() -> UpdateWorldBound()
- For NiTriShape: transforms local bounding sphere by world transform
- Local bound computed during NiTriShapeData creation from vertex data
- World bound requires Update() to have been called after loading
- GetBoundingBox (FUN_004360c0) reads vtable+0xe4 (GetWorldBound) return value
- NULL return = Update() was never called OR NiAVObject base not initialized

## Current Approach: Proxy COM with Targeted Patches
- Pipeline objects at renderer+0xB8/0xBC/0xC0/0xC4 build via proxy COM
- PatchDeviceCapsRawCopy prevents the raw 236-byte memcpy from Device7
- PatchRendererMethods stubs 3 specific vtable methods that access NULL state
- Dev_EnumTextureFormats enumerates pixel formats for pipeline creation
- Proxy returns D3D_OK for all COM calls, pipeline objects construct successfully

## Pipeline Constructor Audit TODO
1. FUN_007d4950 (geometry accumulator -> this+0xC4)
2. FUN_007d2230 (texture manager -> this+0xB8)
3. FUN_007ccd10 (render state manager -> this+0xBC)
4. FUN_007d11a0 (shader/effect manager -> this+0xC0)

## Fallback: Hook Bounds Injection (8d)
- After ship creation, manually write NiBound at NiAVObject offset
- center[3] = ship position, radius = 100.0f
- Bypasses entire Update() chain
- Surgical but fragile, need to find exact NiBound offset in STBC NiAVObject layout

## NiDX7Renderer Layout (0x224 bytes)
- [0x00]: vtable (PTR_LAB_0089902c, ~90 methods)
- [0x14]: IDirect3D7*
- [0x18]: z-buffer surface ptr
- [0x34]: D3D adapter info struct
- [0x38-0x97]: 3x 32-byte pixel format arrays
- [0x98-0xB7]: Z-buffer caps, depth info
- [0xB8]: Texture manager
- [0xBC]: Render state manager
- [0xC0]: Shader/effect manager
- [0xC4]: Geometry accumulator
- [0xC8]: Render target manager (FUN_007cb2c0 result)
- [0x14C-0x1A7]: Camera/frustum matrices
- [0x2A0-0x2A4]: Capability flags
