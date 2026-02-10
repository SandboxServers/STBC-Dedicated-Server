# Bounding Box Crash Analysis (0x004360c0 / 0x00419960)

## Two Crash Sites, One Root Cause

### 0x004360CB (GetBoundingBox)
- FUN_004360c0, vtable offset 0xE8 in NiAVObject hierarchy
- `__thiscall(float* minOut, float* maxOut)` with `RET 0x8`
- Calls vtable[0xE4] (GetModelBound) then reads returned NiBound*
- Crash: `FLD [EAX+0xC]` when EAX=0 (GetModelBound returned NULL)
- In 23 vtables (DATA xrefs); Ship class overrides at 0x005abc30

### 0x00419963 (GetModelBound)
- Address 0x00419960, vtable offset 0xE4
- NOT in Ghidra function DB (too small, auto-analysis missed it)
- In 23 vtables, base implementation for all NiAVObject-derived types
- Crash: `MOV EAX, [ECX+0x0]` when ECX=0 (this pointer is NULL)
- Called BY GetBoundingBox with same this pointer

## Class Hierarchy (via constructor chain)
1. NiObject (0x006f0a70) - refcount
2. NiObjectNET (0x006f31a0) - +0x08
3. NiAVObject (0x006f2590) - +0x0C
4. TGObject (0x006d8f90) - +0x10
5. TGModelObject (0x004308e0) - +0x18 = NiTriShape geometry ptr
6. Intermediate (0x00435030) - +0x58, vtable PTR_FUN_00889950
7. AsteroidField (0x004196d0) - vtable PTR_FUN_00888b84

## Vtable Layout (AsteroidField at 0x00888b84)
| Offset | Addr in vtable | Target | Purpose |
|--------|---------------|--------|---------|
| 0x00 | 0x00888b84 | 0x00419a30 | destructor |
| 0xE4 | 0x00888c68 | 0x00419960 | GetModelBound |
| 0xE8 | 0x00888c6c | 0x004360c0 | GetBoundingBox |

## Why It Fires ~100/sec
- Scene graph update loop runs every frame
- NiNode::Update propagates transforms + recomputes world bounds
- Calls GetBoundingBox on every child node
- In headless mode, objects may have NULL/invalid geometry
- Without a targeted patch, this crashes on every frame for every affected object

## Fix: Code Cave at 0x004360c0
- Patch 5 bytes at function entry (SUB ESP,0x18 / MOV EAX,[ECX])
- JMP to code cave that:
  1. Tests ECX (this) for NULL -> skip
  2. Calls GetModelBound normally
  3. Tests EAX (return) for NULL -> zero bounding box
  4. Otherwise continues to original code at 0x004360CB
- Eliminates BOTH crash sites with one patch
- Currently addressed by renderer pipeline restoration (objects get valid geometry)
