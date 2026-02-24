> [docs](../README.md) / [engine](README.md) / netimmerse-vtables.md

# NetImmerse 3.1 Vtable Map (stbc.exe)

## Summary

Systematic mapping of vtable addresses and virtual method slots for key NetImmerse 3.1
classes in stbc.exe. Derived from constructor chain analysis, cross-referencing with
Gamebryo 1.2 source headers, and behavioral decompilation of individual vtable entries.

## Constructor Chain

Each constructor calls its parent, initializes fields, then writes its own vtable pointer.
The final vtable written is the one used at runtime.

```
FUN_007d87a0 (NiObject ctor)      -> vtable 0x00898b94
  FUN_007dac80 (NiObjectNET ctor) -> vtable 0x00898c48
    FUN_007dc0c0 (NiAVObject ctor) -> vtable 0x00898ca8
      NiNode path:
        NiNode factory FUN_007e5450 -> vtable 0x00898f2c
      NiGeometry path:
        FUN_007edd10 (NiGeometry ctor) -> vtable 0x00899164
          FUN_007ef260 (NiTriShape ctor) -> vtable 0x00899264
```

## Vtable Addresses and Sizes

| Class | Vtable Address | Slots | Size (bytes) | Constructor | Factory |
|-------|---------------|-------|--------------|-------------|---------|
| NiObject | 0x00898b94 | 12 (0-11) | 0x30 | FUN_007d87a0 | FUN_007d8650 (RTTI reg) |
| NiObjectNET | 0x00898c48 | 12 (0-11) | 0x30 | FUN_007dac80 | FUN_007dab30 (RTTI reg) |
| NiAVObject | 0x00898ca8 | 39 (0-38) | 0x9C | FUN_007dc0c0 | FUN_007dbf70 (RTTI reg) |
| NiNode | 0x00898f2c | 43 (0-42) | 0xAC | (via factory) | FUN_007e5450 |
| NiGeometry | 0x00899164 | 64 (0-63) | 0x100 | FUN_007edd10 | (abstract) |
| NiTriShape | 0x00899264 | 68 (0-67) | 0x110 | FUN_007ef260 | FUN_007f31f0 |

### Notes
- NiObjectNET adds NO new virtual methods over NiObject (same 12 slots)
- NiAVObject adds 27 new virtuals over NiObjectNET (slots 12-38)
- NiNode adds 4 new virtuals over NiAVObject (slots 39-42)
- NiGeometry adds 25 new virtuals over NiAVObject (slots 39-63)
- NiTriShape adds 4 new virtuals over NiGeometry (slots 64-67)
- Gamebryo 1.2 source says NiNode adds 5 (AttachChild, DetachChild, DetachChildAt, SetAt, UpdateUpwardPass); NI 3.1 has 4, suggesting UpdateUpwardPass may not exist yet or is merged

## Key Constants

- `__purecall` stub: 0x00859a0b (used in vtable entries for pure virtual methods)
- NiObject RTTI data: 0x009a1468
- NiObject global counter: 0x009a1478 (incremented in NiObject constructor)
- RTTI factory hash table: 0x009a2b98

## NiObject Vtable (0x00898b94) - 12 slots

All NiObject-derived classes share these first 12 slots in the same order.

| Slot | Offset | NiObject Impl | NiObjectNET Impl | Name (NI 3.1) | Evidence |
|------|--------|---------------|-------------------|---------------|----------|
| 0 | +0x00 | 0x00458770 | 0x007dba40 | **GetRTTI** | SaveBinary (slot 7) calls `vtable[0]()` and uses result->name as string; slot 0 refs NiRTTI at 0x009a1468 |
| 1 | +0x04 | 0x00458780 | 0x007dae00 | **CreateClone** | Overridden in every derived class; base is likely no-op or abstract |
| 2 | +0x08 | 0x00438ff0 | FUN_007db060 | **ProcessClone** | NiObjectNET impl clones ExtraData (this+0x10) |
| 3 | +0x0C | 0x00439000 | FUN_007db080 | **PostLinkObject** | NiObjectNET impl processes TimeController (this+0xC) |
| 4 | +0x10 | FUN_007d8820 | FUN_007db5f0 | **RegisterStreamables** | Manipulates stream hash table via FUN_00817170; registers object for save |
| 5 | +0x14 | FUN_007d8930 | FUN_007db630 | **LoadBinary** | NiObject base is empty `return;` (no data to load); NiObjectNET reads name + extras |
| 6 | +0x18 | FUN_007d8940 | FUN_007db6c0 | **LinkObject** | Calls FUN_00817170 (stream hash insert); resolves object references post-load |
| 7 | +0x1C | FUN_007d8a40 | FUN_007db700 | **SaveBinary** | Calls GetRTTI (slot 0), writes RTTI name string then object index to stream |
| 8 | +0x20 | FUN_007d8a70 | FUN_007db740 | **IsEqual** | Compares RTTI names (calls slot 0 on both objects, strcmp) |
| 9 | +0x24 | FUN_007d8ae0 | FUN_007db860 | **AddViewerStrings** | Adds "m_iRefCount" string (NiObject); NiObjectNET adds name/controllers/extradata |
| 10 | +0x28 | 0x007d87c0 | FUN_007dba50 | **scalar_deleting_dtor** | Pattern: call real dtor, then `if (param & 1) free(this)`. Identified by matching vtable 0x00898bc4 |
| 11 | +0x2C | 0x0040da50 | 0x0040da50 | **GetViewerStrings** (or no-op) | NEVER overridden in any class (NiObject=NiObjectNET=NiAVObject=NiNode=0x0040da50) |

### Slot Order vs Gamebryo 1.2

NI 3.1 vtable order differs significantly from Gamebryo 1.2 headers:

| NI 3.1 Slot | NI 3.1 Method | Gb 1.2 Slot | Notes |
|-------------|---------------|-------------|-------|
| 0 | GetRTTI | 1 | Moved to slot 0 (no dtor at slot 0!) |
| 1 | CreateClone | 2 | |
| 2 | ProcessClone | 10 | Moved MUCH earlier |
| 3 | PostLinkObject | 11 | Moved MUCH earlier |
| 4 | RegisterStreamables | 5 | |
| 5 | LoadBinary | 3 | |
| 6 | LinkObject | 4 | |
| 7 | SaveBinary | 6 | |
| 8 | IsEqual | 7 | |
| 9 | AddViewerStrings | 9 | Same! |
| 10 | scalar_deleting_dtor | 0 | MSVC dtor moved to slot 10! |
| 11 | (no-op, never overridden) | 8? | Possibly GetViewerStrings (base impl) |

**CRITICAL FINDING**: The MSVC scalar deleting destructor is at slot 10, NOT slot 0.
GetRTTI occupies slot 0 instead. This is the opposite of the Gamebryo 1.2 layout.

## NiAVObject Vtable (0x00898ca8) - 39 slots

Slots 0-11 are inherited from NiObject (overridden as needed).
Slots 12-38 are NiAVObject-specific additions.

| Slot | Offset | Function | Name (Proposed) | Evidence |
|------|--------|----------|-----------------|----------|
| 0 | +0x00 | 0x007ddf90 | GetRTTI | Override returns NiAVObject RTTI |
| 1 | +0x04 | 0x007dd2b0 | CreateClone | |
| 2 | +0x08 | FUN_007dd3e0 | ProcessClone | |
| 3 | +0x0C | FUN_007dd3f0 | PostLinkObject | |
| 4 | +0x10 | FUN_007dd480 | RegisterStreamables | |
| 5 | +0x14 | FUN_007dd5f0 | LoadBinary | |
| 6 | +0x18 | FUN_007dd630 | LinkObject | |
| 7 | +0x1C | FUN_007dd6a0 | SaveBinary | |
| 8 | +0x20 | FUN_007dd7b0 | IsEqual | |
| 9 | +0x24 | FUN_007dda10 | AddViewerStrings | |
| 10 | +0x28 | FUN_007ddfa0 | scalar_deleting_dtor | |
| 11 | +0x2C | 0x0040da50 | (no-op/GetViewerStrings) | Never overridden |
| 12 | +0x30 | 0x004341b0 | UpdateControllers? | Small stub, part of update pipeline |
| 13 | +0x34 | 0x004341c0 | UpdateNodeBound? | Small stub |
| 14 | +0x38 | 0x00434240 | ApplyTransform? | |
| 15 | +0x3C | 0x00434250 | GetObjectByName? | |
| 16 | +0x40 | 0x00434260 | SetSelectiveUpdateFlags? | |
| 17 | +0x44 | 0x00434270 | UpdateDownwardPass? | |
| 18 | +0x48 | 0x00434280 | UpdateSelectedDownwardPass? | |
| 19 | +0x4C | 0x00434290 | UpdateRigidDownwardPass? | |
| 20 | +0x50 | 0x00434180 | UpdatePropertiesDownward? | |
| 21 | +0x54 | 0x004341a0 | UpdateEffectsDownward? | |
| 22 | +0x58 | NiAVObject__GetObjectByName | **GetObjectByName** | Confirmed: strcmp(this->name, searchName), returns this if match. NiNode override recurses children. |
| 23 | +0x5C | 0x00434210 | UpdateWorldBound? | |
| 24 | +0x60 | 0x00434220 | Display? | |
| 25 | +0x64 | FUN_007dc5f0 | PurgeRendererData? | |
| 26 | +0x68 | 0x00456e90 | (unknown) | |
| 27 | +0x6C | 0x007dc7a0 | (unknown) | |
| 28 | +0x70 | 0x007dca60 | (unknown) | |
| 29 | +0x74 | FUN_007dc780 | (unknown) | |
| 30 | +0x78 | FUN_007dca40 | (unknown) | |
| 31 | +0x7C | 0x004341e0 | (unknown) | |
| 32 | +0x80 | 0x004341f0 | (unknown) | |
| 33 | +0x84 | 0x00434200 | (unknown) | |
| 34 | +0x88 | 0x00434230 | (unknown) | |
| 35 | +0x8C | FUN_007dcb50 | (unknown) | |
| 36 | +0x90 | FUN_007dcb70 | (unknown) | |
| 37 | +0x94 | FUN_008201a0 | (unknown) | |
| 38 | +0x98 | 0x004341d0 | (unknown) | |

### Notes on NiAVObject slots 12-38
- Many small stubs (0x0043xxxx range) are base implementations that return quickly
- NI 3.1 has 27 NiAVObject-specific virtuals; Gamebryo 1.2 declares ~14 NiAVObject virtuals
- This means NI 3.1 has ~13 additional virtuals not present in Gamebryo 1.2
- These extra slots may include: collision, picking, sorting, visibility, and BC-specific extensions

## NiNode Vtable (0x00898f2c) - 43 slots

Slots 0-38 inherited from NiAVObject (many overridden).
Slots 39-42 are NiNode-specific additions.

| Slot | Offset | Function | Name | Evidence |
|------|--------|----------|------|----------|
| 0 | +0x00 | 0x004e3640 | GetRTTI | Override returns NiNode RTTI |
| 1 | +0x04 | FUN_007e4f30 | CreateClone | |
| 2 | +0x08 | FUN_007e5180 | ProcessClone | Iterates children |
| 3 | +0x0C | FUN_007e53e0 | PostLinkObject | |
| 4 | +0x10 | FUN_007e5630 | RegisterStreamables | Registers self + children |
| 5 | +0x14 | FUN_007e57d0 | LoadBinary | Reads child count, loads children |
| 6 | +0x18 | FUN_007e58d0 | LinkObject | Links children by index |
| 7 | +0x1C | FUN_007e5940 | SaveBinary | Writes child array to stream |
| 8 | +0x20 | FUN_007e5a00 | IsEqual | |
| 9 | +0x24 | FUN_007e5b30 | AddViewerStrings | |
| 10 | +0x28 | FUN_007e67d0 | scalar_deleting_dtor | |
| 11 | +0x2C | 0x0040da50 | (no-op) | Never overridden |
| 12 | +0x30 | 0x007e3e30 | UpdateControllers | NiNode override iterates children |
| 13 | +0x34 | 0x004341c0 | (stub) | Inherited from NiAVObject |
| 14 | +0x38 | NiNode__ApplyTransform | **ApplyTransform** | NiNode override |
| 15 | +0x3C | NiNode__vfn15_IterateChildren | **(unknown)** | Iterates children calling +0x3C; purpose unclear in NI 3.1 |
| 16 | +0x40 | NiNode__SetSelectiveUpdateFlags | **SetSelectiveUpdateFlags** | NiNode override |
| 17 | +0x44 | NiNode__UpdateDownwardPass | **UpdateDownwardPass** | NiNode override iterates children |
| 18 | +0x48 | NiNode__UpdateSelectedDownwardPass | **UpdateSelectedDownwardPass** | NiNode override |
| 19 | +0x4C | NiNode__UpdateRigidDownwardPass | **UpdateRigidDownwardPass** | NiNode override |
| 20 | +0x50 | 0x00434180 | (inherited) | Same as NiAVObject |
| 21 | +0x54 | 0x004341a0 | (inherited) | Same as NiAVObject |
| 22 | +0x58 | NiNode__GetObjectByName | **GetObjectByName** | Calls NiAVObject base (name check), then recurses children |
| 23 | +0x5C | NiNode__UpdateWorldBound | **UpdateWorldBound** | NiNode override |
| 24 | +0x60 | NiNode__Display | **Display** | NiNode override iterates children |
| 25 | +0x64 | FUN_007e3ff0 | PurgeRendererData | NiNode override |
| 26 | +0x68 | 0x004d5170 | (override) | |
| 27 | +0x6C | NiNode__UpdatePropertiesDownward | **UpdatePropertiesDownward** | NiNode override |
| 28 | +0x70 | NiNode__UpdateEffectsDownward | **UpdateEffectsDownward** | NiNode override |
| 29 | +0x74 | FUN_007dc780 | (inherited) | Same as NiAVObject |
| 30 | +0x78 | FUN_007dca40 | (inherited) | Same as NiAVObject |
| 31 | +0x7C | FUN_007e46f0 | (override) | |
| 32 | +0x80 | FUN_007e4b00 | (override) | Picks/intersects children recursively using vtable+0x80 |
| 33 | +0x84 | FUN_007e4bd0 | (override) | |
| 34 | +0x88 | FUN_007e4d30 | (override) | |
| 35 | +0x8C | FUN_007dcb50 | (inherited) | Same as NiAVObject |
| 36 | +0x90 | FUN_007dcb70 | (inherited) | Same as NiAVObject |
| 37 | +0x94 | FUN_008201a0 | (inherited) | Same as NiAVObject |
| 38 | +0x98 | 0x007e4170 | (override) | NiAVObject base=0x4341d0, NiNode overrides |
| **39** | **+0x9C** | **FUN_007e39b0** | **AttachChild** | Takes (this, NiAVObject*, bool atEnd); sets parent ptr, adds to child array |
| **40** | **+0xA0** | **FUN_007e3b30** | **DetachChild(NiAVObject*)** | Iterates children looking for match, removes |
| **41** | **+0xA4** | **FUN_007e3a30** | **DetachChildAt(uint)** | Removes child at index, clears parent ptr |
| **42** | **+0xA8** | **FUN_007e3c50** | **SetAt(uint, NiAVObject*)** | Replaces child at index |

### Shared vs Overridden Slots (NiAVObject -> NiNode)

| Category | Slots |
|----------|-------|
| Inherited unchanged | 11, 13, 20, 21, 29, 30, 35, 36, 37 |
| Overridden by NiNode | 0-10, 12, 14-19, 22-28, 31-34, 38 |
| New in NiNode | 39-42 |

## NiGeometry Vtable (0x00899164) - 64 slots

NiGeometry adds 25 new virtual methods over NiAVObject's 39 (slots 39-63).
This is substantially more than Gamebryo 1.2 documents, suggesting NI 3.1 had
more geometry-specific virtuals that were later consolidated or removed.

Selected entries:

| Slot | Offset | Function | Notes |
|------|--------|----------|-------|
| 0 | +0x00 | 0x007eeaa0 | GetRTTI |
| 1 | +0x04 | 0x007ee660 | CreateClone |
| 2 | +0x08 | FUN_007ee6a0 | ProcessClone |
| 3 | +0x0C | FUN_007dd3f0 | PostLinkObject (inherited from NiAVObject!) |
| ... | ... | ... | ... |
| 45 | +0xB4 | FUN_007ef050 | (NiGeometry-specific) |
| 46 | +0xB8 | 0x0040da50 | (no-op) |
| 47 | +0xBC | 0x007eda70 | |
| 48 | +0xC0 | 0x007eda80 | |
| 49 | +0xC4 | 0x00859a0b | **__purecall** (pure virtual!) |
| 50 | +0xC8 | 0x004fb450 | |
| 51 | +0xCC | 0x007ef080 | |
| 52 | +0xD0 | 0x007ef090 | |
| ... | ... | ... | ... |

Note: Slot 49 is __purecall, confirming NiGeometry IS abstract (cannot be instantiated).

## NiTriShape Vtable (0x00899264) - 68 slots

NiTriShape adds 4 new virtuals over NiGeometry's 64 (slots 64-67).

Selected entries:

| Slot | Offset | Function | Notes |
|------|--------|----------|-------|
| 0 | +0x00 | 0x007f1220 | GetRTTI |
| 1 | +0x04 | 0x007f0d00 | CreateClone |
| 2 | +0x08 | FUN_007f0d40 | ProcessClone |
| 3 | +0x0C | FUN_007dd3f0 | PostLinkObject (inherited from NiAVObject!) |

## Vtable Offset Quick Reference

For code that uses `vtable[offset]` patterns:

| Offset | Method (NiObject slots) |
|--------|------------------------|
| +0x00 | GetRTTI() |
| +0x04 | CreateClone() |
| +0x08 | ProcessClone() |
| +0x0C | PostLinkObject() |
| +0x10 | RegisterStreamables() |
| +0x14 | LoadBinary() |
| +0x18 | LinkObject() |
| +0x1C | SaveBinary() |
| +0x20 | IsEqual() |
| +0x24 | AddViewerStrings() |
| +0x28 | scalar_deleting_dtor() |
| +0x2C | (no-op, never overridden) |

For NiNode-specific calls:
| Offset | Method |
|--------|--------|
| +0x9C | AttachChild(NiAVObject*, bool) |
| +0xA0 | DetachChild(NiAVObject*) |
| +0xA4 | DetachChildAt(uint) |
| +0xA8 | SetAt(uint, NiAVObject*) |

For calls via `vtable[0x80]` (seen in NiNode slot 32):
- This is slot 32 in NiAVObject/NiNode = a picking/intersection test method

For calls via `vtable[0x28]`:
- This is slot 10 = scalar_deleting_destructor (called as `(*vtable[0x28])(1)` to delete)

## Object Sizes (from allocations in factories)

| Class | Size (hex) | Size (dec) |
|-------|-----------|------------|
| NiObject | 0x08 | 8 | vtable + refcount |
| NiObjectNET | 0x14 | 20 | + name + timeController + extraData |
| NiAVObject | 0xC4 | 196 | + transforms, bounds, flags, properties |
| NiNode | 0xE8 | 232 | + child array (NiTArray) + effects list |
| NiGeometry | 0xE0 | 224 | + geometry data, skin, shader |
| NiTriShape | 0xE4 | 228 | + triangle-specific data |

## NiRTTI Data Addresses

| Class | NiRTTI Global | String Address |
|-------|---------------|----------------|
| NiObject | 0x009a1468 | 0x009780D8 |
| NiObjectNET | (via RTTI reg) | 0x00978228 |
| NiAVObject | (via RTTI reg) | 0x0095B050 |
| NiNode | (via RTTI reg) | 0x00978500 |
| NiGeometry | (via RTTI reg) | 0x00978770 |
| NiTriShape | (via RTTI reg) | 0x009787EC |

## Methodology

1. **Constructor chain tracing**: Starting from known NiNode factory (FUN_007e5450),
   traced __fastcall constructor calls down to NiObject base. Each constructor writes
   its class vtable as `*this = &vtable_addr`.

2. **Vtable boundary detection**: For each vtable address, checked if nearby addresses
   are used as vtable pointers by other constructors (via get_xrefs_to). When an address
   N bytes after a vtable start is used as another class's vtable, the first vtable ends
   before that address.

3. **Slot identification**: Decompiled individual vtable entry functions and matched
   behavior to known NiObject virtual method semantics (GetRTTI returns RTTI pointer,
   SaveBinary writes to stream, IsEqual compares RTTI names, etc.)

4. **Cross-class verification**: Confirmed that slot 11 (0x0040da50) is identical across
   NiObject, NiObjectNET, NiAVObject, and NiNode (never overridden), while other slots
   differ (overridden at each level).
