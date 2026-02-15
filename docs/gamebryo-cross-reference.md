# Gamebryo 1.2 Source Cross-Reference

Cross-reference of 129 NetImmerse 3.1 classes found in stbc.exe against Gamebryo 1.2 source
(`engine/gamebyro-1.2-source/`), MWSE reverse-engineered headers (`engine/mwse/`),
and niftools NIF format specification (`engine/nif.xml`).

## Summary

| Metric | Count | % |
|--------|-------|---|
| NI classes in stbc.exe | 129 | 100% |
| **Match in Gamebryo 1.2** | **87** | **67%** |
| NI 3.1-only (no Gb 1.2 source) | 42 | 33% |
| — with nif.xml field definitions | 21 | 50% of 42 |
| — runtime-only (no serialization) | 21 | 50% of 42 |
| Renamed (audio) | 3 | — |

## Compatibility Notes

### NiObjectNET: ExtraData System Changed
- **NI 3.1 (stbc.exe)**: Single `NiExtraData*` pointer (linked list via `m_pNext`)
- **Gamebryo 1.2**: Array `NiExtraData** m_ppkExtra` + `m_uiExtraDataSize` + `m_uiMaxSize`
- **Impact**: All offsets in NiObjectNET and derived classes shift by +8 bytes in Gb 1.2
- **Confirmed by**: nif.xml field `Extra Data` (single Ref, `since="3.0" until="4.2.2.0"`) vs `Extra Data List` (array, `since="10.0.1.0"`)

### NiAVObject: CollisionObject Added
- **NI 3.1**: No `m_spCollisionObject` member
- **Gamebryo 1.2**: Added `NiCollisionObjectPtr m_spCollisionObject`
- **Impact**: +4 bytes shift at end of NiAVObject
- **Confirmed by**: nif.xml field `Collision Object` has `since="10.0.1.0"` (absent in 3.1)

### NiAVObject: Velocity Field Present in V3.1
- nif.xml: `Velocity` field (Vector3) has `until="4.2.2.0"` — **present** in V3.1
- nif.xml: `Has Bounding Volume` + `Bounding Volume` have `since="3.0" until="4.2.2.0"` — **present** in V3.1
- These fields were removed in later versions, explaining some offset differences

### NiTimeController: V3.1-Specific Field
- nif.xml: `Unknown Integer` (uint) has `until="3.1"` — present only in V3.1 and earlier
- nif.xml: `Target` (Ptr to NiObjectNET) has `since="3.3.0.13"` — **absent** in V3.1 (stored differently)

### Core Hierarchy Offset Comparison

| Class | NI 3.1 (BC) Size | MWSE (NI 4.0) Size | Gb 1.2 Size | Delta vs Gb 1.2 |
|-------|-------------------|---------------------|-------------|-----------------|
| NiRefObject | 0x08 | 0x08 | 0x08 | same |
| NiObject | 0x08 | 0x08 | 0x08 | same |
| NiObjectNET | **0x14** | **0x14** | 0x1C | +8 (extra data array) |
| NiAVObject | **0x90** | **0x90** | ~0x9C | +12 (ExtraData+CollisionObj) |
| NiNode | **0xB0** | **0xB0** | ~0xC0+ | +12+ |

*NI 3.1 sizes confirmed via MWSE `static_assert` checks (identical to NI 4.0.0.2).
MWSE struct layouts are the best reference for NI 3.1 field offsets.*

---

## Matched Classes (87) — Source Available

### Core Hierarchy
| Binary Class | Gb 1.2 Source | Notes |
|-------------|---------------|-------|
| NiObject | CoreLibs/NiMain/NiObject.h | Base identical |
| NiObjectNET | CoreLibs/NiMain/NiObjectNET.h | ExtraData changed (see above) |
| NiAVObject | CoreLibs/NiMain/NiAVObject.h | CollisionObject added in Gb 1.2 |
| NiNode | CoreLibs/NiMain/NiNode.h | API matches, offsets shifted |
| NiRefObject | CoreLibs/NiMain/NiRefObject.h | Identical |

### Scene Graph Nodes
| Binary Class | Gb 1.2 Source |
|-------------|---------------|
| NiBillboardNode | CoreLibs/NiMain/NiBillboardNode.h |
| NiBSPNode | CoreLibs/NiMain/NiBSPNode.h |
| NiLODNode | CoreLibs/NiMain/NiLODNode.h |
| NiSortAdjustNode | CoreLibs/NiMain/NiSortAdjustNode.h |
| NiSwitchNode | CoreLibs/NiMain/NiSwitchNode.h |

### Geometry
| Binary Class | Gb 1.2 Source |
|-------------|---------------|
| NiGeometry | CoreLibs/NiMain/NiGeometry.h |
| NiGeometryData | CoreLibs/NiMain/NiGeometryData.h |
| NiTriBasedGeom | CoreLibs/NiMain/NiTriBasedGeom.h |
| NiTriBasedGeomData | CoreLibs/NiMain/NiTriBasedGeomData.h |
| NiTriShape | CoreLibs/NiMain/NiTriShape.h |
| NiTriShapeData | CoreLibs/NiMain/NiTriShapeData.h |
| NiTriShapeDynamicData | CoreLibs/NiMain/NiTriShapeDynamicData.h |
| NiTriStrips | CoreLibs/NiMain/NiTriStrips.h |
| NiTriStripsData | CoreLibs/NiMain/NiTriStripsData.h |
| NiLines | CoreLibs/NiMain/NiLines.h |
| NiLinesData | CoreLibs/NiMain/NiLinesData.h |
| NiScreenPolygon | CoreLibs/NiMain/NiScreenPolygon.h |

### Properties (Render State)
| Binary Class | Gb 1.2 Source |
|-------------|---------------|
| NiProperty | CoreLibs/NiMain/NiProperty.h |
| NiAlphaProperty | CoreLibs/NiMain/NiAlphaProperty.h |
| NiDitherProperty | CoreLibs/NiMain/NiDitherProperty.h |
| NiFogProperty | CoreLibs/NiMain/NiFogProperty.h |
| NiMaterialProperty | CoreLibs/NiMain/NiMaterialProperty.h |
| NiShadeProperty | CoreLibs/NiMain/NiShadeProperty.h |
| NiSpecularProperty | CoreLibs/NiMain/NiSpecularProperty.h |
| NiStencilProperty | CoreLibs/NiMain/NiStencilProperty.h |
| NiVertexColorProperty | CoreLibs/NiMain/NiVertexColorProperty.h |
| NiWireframeProperty | CoreLibs/NiMain/NiWireframeProperty.h |
| NiZBufferProperty | CoreLibs/NiMain/NiZBufferProperty.h |

### Lights
| Binary Class | Gb 1.2 Source |
|-------------|---------------|
| NiLight | CoreLibs/NiMain/NiLight.h |
| NiDynamicEffect | CoreLibs/NiMain/NiDynamicEffect.h |
| NiAmbientLight | CoreLibs/NiMain/NiAmbientLight.h |
| NiDirectionalLight | CoreLibs/NiMain/NiDirectionalLight.h |
| NiPointLight | CoreLibs/NiMain/NiPointLight.h |
| NiSpotLight | CoreLibs/NiMain/NiSpotLight.h |
| NiTextureEffect | CoreLibs/NiMain/NiTextureEffect.h |

### Controllers / Animation (matched subset)
| Binary Class | Gb 1.2 Source |
|-------------|---------------|
| NiTimeController | CoreLibs/NiMain/NiTimeController.h |
| NiAlphaController | CoreLibs/NiAnimation/NiAlphaController.h |
| NiFlipController | CoreLibs/NiAnimation/NiFlipController.h |
| NiFloatController | CoreLibs/NiAnimation/NiFloatController.h |
| NiLightColorController | CoreLibs/NiAnimation/NiLightColorController.h |
| NiLookAtController | CoreLibs/NiAnimation/NiLookAtController.h |
| NiMaterialColorController | CoreLibs/NiAnimation/NiMaterialColorController.h |
| NiPathController | CoreLibs/NiAnimation/NiPathController.h |
| NiRollController | CoreLibs/NiAnimation/NiRollController.h |
| NiVisController | CoreLibs/NiAnimation/NiVisController.h |

### Animation Data (matched subset)
| Binary Class | Gb 1.2 Source |
|-------------|---------------|
| NiFloatData | CoreLibs/NiAnimation/NiFloatData.h |
| NiColorData | CoreLibs/NiAnimation/NiColorData.h |
| NiPosData | CoreLibs/NiAnimation/NiPosData.h |

### Extra Data
| Binary Class | Gb 1.2 Source |
|-------------|---------------|
| NiExtraData | CoreLibs/NiMain/NiExtraData.h |
| NiStringExtraData | CoreLibs/NiMain/NiStringExtraData.h |
| NiVertWeightsExtraData | CoreLibs/NiMain/NiVertWeightsExtraData.h |
| NiTextKeyExtraData | CoreLibs/NiAnimation/NiTextKeyExtraData.h |

### Physics / Collision
| Binary Class | Gb 1.2 Source |
|-------------|---------------|
| NiGravity | CoreLibs/NiOldParticle/NiGravity.h |
| NiParticleBomb | CoreLibs/NiOldParticle/NiParticleBomb.h |
| NiSphericalCollider | CoreLibs/NiOldParticle/NiSphericalCollider.h |
| NiPlanarCollider | CoreLibs/NiOldParticle/NiPlanarCollider.h |
| NiParticleSystemController | CoreLibs/NiOldParticle/NiParticleSystemController.h |

### Rendering
| Binary Class | Gb 1.2 Source |
|-------------|---------------|
| NiCamera | CoreLibs/NiMain/NiCamera.h |
| NiAccumulator | CoreLibs/NiMain/NiAccumulator.h |
| NiAlphaAccumulator | CoreLibs/NiMain/NiAlphaAccumulator.h |

### Math / Utility
| Binary Class | Gb 1.2 Source |
|-------------|---------------|
| NiPoint2 | CoreLibs/NiMain/NiPoint2.h |
| NiPoint3 | CoreLibs/NiMain/NiPoint3.h |
| NiColor | CoreLibs/NiMain/NiColor.h |
| NiColorA | CoreLibs/NiMain/NiColor.h |
| NiFrustum | CoreLibs/NiMain/NiFrustum.h |

### Template Containers (implementation in headers)
| Binary Class | Gb 1.2 Source |
|-------------|---------------|
| NiTArray | CoreLibs/NiMain/NiTArray.h |
| NiTList | CoreLibs/NiMain/NiTList.h |
| NiTMap | CoreLibs/NiMain/NiTMap.h |

---

## NI 3.1-Only Classes (42) — No Gamebryo 1.2 Source

These classes exist in stbc.exe but were removed/renamed/reorganized before Gamebryo 1.2.
21 of 42 have serialization-level field definitions in nif.xml; the remaining 21 are
runtime-only classes (renderers, audio) that never appear in NIF files.

### Bezier Patch System (11 classes) — Entire subsystem removed
| Class | nif.xml | Notes |
|-------|---------|-------|
| NiBezierMesh | **Yes** (line 5333) | Full struct: triangle refs, vertex arrays, count fields |
| NiBezierPatch | No | Probably abstract base, never serialized |
| NiBezierRectangle | No | Not in file format |
| NiBezierRectangle2 | No | Not in file format |
| NiBezierRectangle3 | No | Not in file format |
| NiBezierTriangle | No | Only NiBezierTriangle4 documented |
| NiBezierTriangle2 | No | Not in file format |
| NiBezierTriangle3 | No | Not in file format |
| NiBezierTriangle4 | **Yes** (line 5319) | Full struct: 6 uints, matrix33, vectors, shorts, bytes |
| NiBezierCylinder | No | Not in file format |
| NiBezierSkinController | No | Not in file format |

*Gb 1.2 moved to tessellation-based approach. These are genuine NI 3.x legacy.*

### Old Animation System (8 classes) — Architecture reorganized
| Class | nif.xml | Gb 1.2 Replacement |
|-------|---------|-------------------|
| NiKeyframeController | **Yes** (line 3651) | NiTransformController. Data ref to NiKeyframeData |
| NiKeyframeData | **Yes** (line 4327) | NiTransformData. **Full struct**: rotation keys (quaternion/XYZ), translations, scales |
| NiMorphController | **Yes** (line 3637) | NiGeomMorpherController. Refs NiMorphData |
| NiMorpherController | **Yes** (line 3641) | NiGeomMorpherController. Refs NiMorphData |
| NiMorphData | **Yes** (line 4375) | Partially kept. Full struct: num morphs, vertices, relative targets |
| NiSkinController | No | NiSkinningMeshModifier. Runtime-only |
| NiTriShapeSkinController | **Yes** (line 5085) | Removed. Full struct: bone count, vertex weights, bone refs (Ptr to NiBone) |
| NiVisData | **Yes** (line 5411) | NiBoolData. Keys array (num + key data) |
| NiAnimBlender | No | NiBlendInterpolator. Runtime-only |

### Old Texture Properties (5 classes) — Merged into NiTexturingProperty
| Class | nif.xml | Notes |
|-------|---------|-------|
| NiTextureProperty | **Yes** (line 5221) | Flags (ushort) + NiImage ref |
| NiTextureModeProperty | **Yes** (line 5204) | Flags (ushort) + PS2 L/K shorts (since 3.1) |
| NiMultiTextureProperty | **Yes** (line 5272) | Inherits NiTexturingProperty (no new fields) |
| NiTransparentProperty | **Yes** (line 3520) | 6 unknown bytes |
| NiCorrectionProperty | No | Removed entirely, never in file format |

### Old Rendering / DirectDraw (8 classes) — Abstraction changed
| Class | nif.xml | Notes |
|-------|---------|-------|
| NiRender | No | Runtime-only (renderer base class) |
| NiD3DRender | No | Runtime-only (D3D renderer) |
| NiImage | **Yes** (line 5212) | UseExternal, FileName, ImageData ref, unknown int, unknown float (since 3.1) |
| NiRawImageData | **Yes** (line 5435) | Width, height, image type, RGB/RGBA pixel data arrays |
| NiDDImage | No | Runtime-only (DirectDraw surface wrapper) |
| NiDDBufferImage | No | Runtime-only (DirectDraw buffer) |
| NiClusterAccumulator | No | Runtime-only (rendering accumulator) |
| NiForce | No | Moved/renamed in particle system |

### NI 3.1-Specific Nodes (3 classes) — Domain-specific
| Class | nif.xml | Notes |
|-------|---------|-------|
| NiBone | **Yes** (line 4392) | Inherits NiNode, no new fields. Used as skeleton bone marker |
| NiCollisionSwitch | **Yes** (line 4396) | Inherits NiNode, no new fields. Found in Munch's Oddysee |
| NiFltAnimationNode | No | MultiGen Flight format support, never in NIF files |

### Audio System (4 classes) — Renamed
| NI 3.1 Class | nif.xml | Gb 1.2 Class |
|-------------|---------|-------------|
| NiSoundSystem | No | NiAudioSystem (runtime-only) |
| NiSource | No | NiAudioSource (runtime-only) |
| NiListener | No | NiAudioListener (runtime-only) |
| NiProvider_Info | No | Removed (runtime-only) |

### Misc (5 classes)
| Class | nif.xml | Notes |
|-------|---------|-------|
| NiBinaryVoxelData | **Yes** (line 4059) | `until="V3_1"`. Full struct: shorts, 7 floats, byte grid, vectors, bytes, 5 ints |
| NiBinaryVoxelExtraData | **Yes** (line 4054) | `until="V3_1"`. Ref to NiBinaryVoxelData |
| NiCloneExtraData | No | Removed or renamed |
| NiSequenceStreamHelper | **Yes** (line 5057) | Inherits NiObjectNET, no new fields. Animation .kf root |
| NiKeyframeManager | No | Replaced by NiControllerManager. Runtime-only |

---

## NIF Format Version-Conditional Fields (V3.1-specific)

nif.xml uses `since` / `until` attributes to tag fields by NIF version. Key V3.1-specific
observations (fields that exist at V3.1 but were changed or removed later):

### NiObjectNET
| Field | Type | Version Range | Notes |
|-------|------|---------------|-------|
| Name | string | always | |
| Extra Data | Ref (NiExtraData) | 3.0 — 4.2.2.0 | **Single linked-list pointer** (not array) |
| Controller | Ref (NiTimeController) | 3.0+ | |

### NiAVObject
| Field | Type | Version Range | Notes |
|-------|------|---------------|-------|
| Flags | ushort | 3.0+ (BSVER<=26) | |
| Translation | Vector3 | always | |
| Rotation | Matrix33 | always | |
| Scale | float | always | |
| **Velocity** | **Vector3** | **until 4.2.2.0** | **Present in V3.1** — removed in Gb 1.2+ |
| Num Properties | uint | NI+BS<=FO3 | |
| Properties | Ref[] (NiProperty) | NI+BS<=FO3 | |
| **Has Bounding Volume** | **bool** | **3.0 — 4.2.2.0** | **Present in V3.1** |
| **Bounding Volume** | **BoundingVolume** | **3.0 — 4.2.2.0** | Conditional on Has Bounding Volume |
| Collision Object | Ref | 10.0.1.0+ | **Absent in V3.1** |

### NiTimeController
| Field | Type | Version Range | Notes |
|-------|------|---------------|-------|
| Next Controller | Ref (NiTimeController) | always | |
| Flags | TimeControllerFlags | always | |
| Frequency | float | always | |
| Phase | float | always | |
| Start Time | float | always | |
| Stop Time | float | always | |
| Target | Ptr (NiObjectNET) | 3.3.0.13+ | **Absent in V3.1** |
| **Unknown Integer** | **uint** | **until 3.1** | **V3.1-only** — replaced by Target ptr |

### NiDynamicEffect
| Field | Type | Version Range | Notes |
|-------|------|---------------|-------|
| Num Affected Nodes | uint | until 4.0.0.2 | Present in V3.1 |
| Affected Nodes | Ptr[] (NiNode) | until 3.3.0.13 | Present in V3.1 (Ptr, not Ref) |

### NiParticleSystemController (V3.1-specific fields)
| Field | Type | Version Range | Notes |
|-------|------|---------------|-------|
| **Old Speed** | **uint** | **until 3.1** | Replaced by float Speed in 3.3+ |
| **Old Emit Rate** | **uint** | **until 3.1** | Replaced by float Birth Rate in 3.3+ |
| **Particle Velocity** | **Vector3** | **until 3.1** | Per-particle data |
| **Particle Unknown Vector** | **Vector3** | **until 3.1** | |
| **Particle Lifetime** | **float** | **until 3.1** | Per-particle |
| **Particle Link** | **Ref (NiObject)** | **until 3.1** | Per-particle chain |
| **Particle Timestamp** | **uint** | **until 3.1** | |
| **Particle Unknown Short** | **ushort** | **until 3.1** | |
| **Particle Vertex Id** | **ushort** | **until 3.1** | Index |
| **Color Data** | **Ref (NiColorData)** | **until 3.1** | |
| **Unknown Float 1** | **float** | **until 3.1** | |
| **Unknown Floats 2** | **float[]** | **until 3.1** | Length = Particle Unknown Short |

### NiFlipController (V3.1-specific)
| Field | Type | Version Range | Notes |
|-------|------|---------------|-------|
| Images | Ref[] (NiImage) | until 3.1 | Replaced by NiSourceTexture refs in 3.3+ |

### TexDesc (NiTexturingProperty::Map)
| Field | Type | Version Range | Notes |
|-------|------|---------------|-------|
| Image | Ref (NiImage) | until 3.1 | Replaced by NiSourceTexture in 3.3+ |

---

## Additional Engine Sources Evaluated

### MWSE (Morrowind Script Extender) — Best Struct Layout Reference

MWSE (`engine/mwse/`) contains **reverse-engineered C++ headers** for Morrowind's NI 4.0.0.2
engine. Despite being one minor version later than BC's NI 3.1.1, the struct sizes are
**identical** — confirmed by `static_assert` checks in the MWSE headers:

| Class | MWSE Size | BC (NI 3.1) Size | Match? |
|-------|-----------|-------------------|--------|
| NiObject | 0x08 | 0x08 | **Yes** |
| NiObjectNET | 0x14 | 0x14 | **Yes** |
| NiAVObject | 0x90 | 0x90 | **Yes** |
| NiNode | 0xB0 | 0xB0 | **Yes** |

Key MWSE fields confirmed for BC:
- NiObjectNET: `name` (+0x08), `extraData` (+0x0C, single ptr), `controllers` (+0x10)
- NiAVObject: `flags` (+0x14), `parentNode` (+0x18), `worldBound` (+0x1C), `localRotation` (+0x2C), `localTranslate` (+0x30), `localScale` (+0x3C), `worldTransform` (+0x40), `velocities` (+0x74), `modelABV` (+0x78), `worldABV` (+0x7C), `collideCallback` (+0x80), `propertyNode` (+0x88)
- NiNode: `children` TArray (+0x90), `effectList` (+0xA8)

**Vtable divergence**: MWSE NI 4.0.0.2 has destructor at vtable slot 0, getRTTI at slot 1.
BC's NI 3.1.1 has GetRTTI at slot 0, destructor at slot 10. Struct data layouts match
but vtable ordering does not — use `docs/netimmerse-vtables.md` for BC vtable slots.

### niftools nif.xml — NIF File Format Specification

The NIF format spec (`engine/nif.xml`) from [niftools/nifxml](https://github.com/niftools/nifxml)
covers all NIF versions from 2.3 through 20.6. It explicitly lists BC:
- `V3_0` (num="3.0"): "Star Trek: Bridge Commander"
- `V3_1` (num="3.1"): "Dark Age of Camelot, Star Trek: Bridge Commander"

Both versions are marked `supported="false"` (NifSkope cannot open them), but the XML still
documents serialized fields with version-conditional `since`/`until` attributes.

**What nif.xml provides:**
- Serialization-level field definitions for **21 of our 42** NI 3.1-only classes
- Version-conditional field tags that precisely identify V3.1-specific fields (removed in later versions)
- Confirmation of NI 3.1 architectural differences (single ExtraData ptr, no CollisionObject, Velocity field on NiAVObject)
- NiParticleSystemController has 12 V3.1-only fields not present in any later version

**What nif.xml does NOT provide:**
- Runtime-only class layouts (renderers, audio, accumulators)
- C++ class member offsets (it documents serialization order, not memory layout)
- Virtual method tables or function signatures

### Gamebryo 2.6 SDK — Diverged Further from NI 3.1

Gb 2.6 (`engine/gamebyro-2.6-source/`) is a massive expansion (625 → 2,487 headers) that
moved **away** from NI 3.1, making it less useful than Gb 1.2 for stbc.exe annotation:

- Core NI classes preserved but marked **DEPRECATED** (NiGeometry, NiParticles, etc.)
- Modern replacements: NiMesh, NiRenderObject, NiPSParticleSystem
- Virtual method counts are higher than NI 3.1 (more evolution, not convergence)
- **NiBezierMesh, NiBezierTriangle, NiScreenPolygon: absent** — confirms these are NI 3.1-only
- NiRTTI factory system: identical pattern across all versions

**Key confirmation:** The 42 "NI 3.1-only" classes were not re-added in Gb 2.6.
They are genuinely unique to NI 3.x.

---

## Practical Usage Guide

### For Ghidra Annotation
1. **Use MWSE headers for field offsets** — identical struct sizes, directly applicable to BC
2. **Use Gb 1.2 source for method implementations** — algorithm logic, virtual method names
3. **Do NOT trust Gb 1.2 struct offsets** — shifted by +8/+12 due to NiObjectNET/NiAVObject changes
4. **Use nif.xml for NI 3.1-only class fields** — 21 of 42 classes have serialization-level field defs
5. **Use BC vtable maps** (`docs/netimmerse-vtables.md`) — MWSE/Gb 1.2 vtable slot ordering differs
6. **For the 21 runtime-only classes, use Ghidra decompilation** — no external reference available

### Reference Priority (best to worst for struct annotation)
1. **MWSE headers** — identical struct sizes, field names, offset comments
2. **nif.xml** — version-conditional field definitions (serialization order, not memory layout)
3. **Gb 1.2 source** — full implementation but shifted offsets
4. **Ghidra binary** — ground truth, but requires decompilation effort

### Key Source Files for Reference
```
engine/mwse/MWSE/NIObject.h      — NiObject struct + vtable (0x08, 11 vslots)
engine/mwse/MWSE/NIObjectNET.h   — NiObjectNET struct (0x14)
engine/mwse/MWSE/NIAVObject.h    — NiAVObject struct + vtable (0x90, 26 vslots)
engine/mwse/MWSE/NINode.h        — NiNode struct + vtable (0xB0, 5 new vslots)
engine/nif.xml                    — NIF format spec (8563 lines, all versions)
engine/gamebyro-1.2-source/CoreLibs/NiMain/     — Core scene graph, properties
engine/gamebyro-1.2-source/CoreLibs/NiAnimation/ — Animation system
engine/gamebyro-1.2-source/CoreLibs/NiOldParticle/ — Legacy particles (best NI 3.1 match)
engine/gamebyro-1.2-source/SDK/Win32/Include/    — Combined headers (1,014 files)
```

### What Each Source Tells Us About BC's Engine
| Source | Struct Offsets | Method Names | Algorithms | Field Names | Version-Specific |
|--------|---------------|-------------|------------|-------------|-----------------|
| MWSE | **Exact** | Some | No | **Yes** | NI 4.0 ≈ NI 3.1 |
| nif.xml | Serialization order | No | No | **Yes** | **Precise V3.1 tags** |
| Gb 1.2 | Shifted (+8/+12) | **Yes** | **Yes** | Yes | No (Gb 1.2 only) |
| Ghidra | **Exact** | Must RE | Must RE | Must RE | **Ground truth** |
