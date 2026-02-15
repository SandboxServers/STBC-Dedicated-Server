# Gamebryo 1.2 Source Cross-Reference

Cross-reference of 129 NetImmerse 3.1 classes found in stbc.exe against Gamebryo 1.2 source
(`engine/gamebyro-1.2-source/`). Generated from RTTI extraction + source tree analysis.

## Summary

| Metric | Count | % |
|--------|-------|---|
| NI classes in stbc.exe | 129 | 100% |
| **Match in Gamebryo 1.2** | **87** | **67%** |
| NI 3.1-only (no Gb 1.2 source) | 42 | 33% |
| Renamed (audio) | 3 | — |

## Compatibility Notes

### NiObjectNET: ExtraData System Changed
- **NI 3.1 (stbc.exe)**: Single `NiExtraData*` pointer (linked list via `m_pNext`)
- **Gamebryo 1.2**: Array `NiExtraData** m_ppkExtra` + `m_uiExtraDataSize` + `m_uiMaxSize`
- **Impact**: All offsets in NiObjectNET and derived classes shift by +8 bytes in Gb 1.2

### NiAVObject: CollisionObject Added
- **NI 3.1**: No `m_spCollisionObject` member
- **Gamebryo 1.2**: Added `NiCollisionObjectPtr m_spCollisionObject`
- **Impact**: +4 bytes shift at end of NiAVObject

### Core Hierarchy Offset Comparison (estimated)

| Class | NI 3.1 (BC) Size | Gb 1.2 Size | Delta |
|-------|-------------------|-------------|-------|
| NiRefObject | 0x08 | 0x08 | same |
| NiObject | 0x08 | 0x08 | same |
| NiObjectNET | 0x14 | 0x1C | +8 (extra data array) |
| NiAVObject | ~0x90 | ~0x9C | +12 (ExtraData+CollisionObj) |
| NiNode | ~0xAC+ | ~0xC0+ | +12+ |

*NI 3.1 sizes need verification from binary; Gb 1.2 sizes from source.*

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
They must be reconstructed purely from binary analysis.

### Bezier Patch System (11 classes) — Entire subsystem removed
| Class | Notes |
|-------|-------|
| NiBezierMesh | Bezier mesh container |
| NiBezierPatch | Base bezier patch |
| NiBezierRectangle | Rectangular patch |
| NiBezierRectangle2 | Variant 2 |
| NiBezierRectangle3 | Variant 3 |
| NiBezierTriangle | Triangular patch |
| NiBezierTriangle2 | Variant 2 |
| NiBezierTriangle3 | Variant 3 |
| NiBezierTriangle4 | Variant 4 |
| NiBezierCylinder | Cylindrical patch |
| NiBezierSkinController | Bezier skinning |

*Gb 1.2 moved to tessellation-based approach. These are genuine NI 3.x legacy.*

### Old Animation System (8 classes) — Architecture reorganized
| Class | Gb 1.2 Replacement |
|-------|-------------------|
| NiKeyframeController | NiTransformController (interpolator-based) |
| NiKeyframeData | NiTransformData |
| NiMorphController | NiGeomMorpherController |
| NiMorpherController | NiGeomMorpherController |
| NiMorphData | NiMorphData (partially kept) |
| NiSkinController | NiSkinningMeshModifier |
| NiTriShapeSkinController | Removed |
| NiVisData | NiBoolData |
| NiAnimBlender | NiBlendInterpolator |

### Old Texture Properties (5 classes) — Merged into NiTexturingProperty
| Class | Notes |
|-------|-------|
| NiTextureProperty | Replaced by NiTexturingProperty |
| NiTextureModeProperty | Merged into NiTexturingProperty |
| NiMultiTextureProperty | Merged into NiTexturingProperty |
| NiTransparentProperty | Absorbed by NiAlphaProperty |
| NiCorrectionProperty | Removed entirely |

### Old Rendering / DirectDraw (8 classes) — Abstraction changed
| Class | Notes |
|-------|-------|
| NiRender | Replaced by NiRenderer |
| NiD3DRender | Replaced by NiDX8Renderer/NiDX9Renderer |
| NiImage | Replaced by NiTexture/NiSourceTexture |
| NiRawImageData | Replaced by NiPixelData |
| NiDDImage | DirectDraw-specific, removed |
| NiDDBufferImage | DirectDraw-specific, removed |
| NiClusterAccumulator | Removed (cluster rendering deprecated) |
| NiForce | Moved/renamed in particle system |

### NI 3.1-Specific Nodes (3 classes) — Domain-specific
| Class | Notes |
|-------|-------|
| NiBone | Became NiNode with bone flag? |
| NiCollisionSwitch | Collision logic reorganized |
| NiFltAnimationNode | MultiGen Flight format support removed |

### Audio System (4 classes) — Renamed
| NI 3.1 Class | Gb 1.2 Class |
|-------------|-------------|
| NiSoundSystem | NiAudioSystem |
| NiSource | NiAudioSource |
| NiListener | NiAudioListener |
| NiProvider_Info | Removed |

### Misc (3 classes)
| Class | Notes |
|-------|-------|
| NiBinaryVoxelData | Removed (voxel support dropped) |
| NiBinaryVoxelExtraData | Removed |
| NiCloneExtraData | Removed or renamed |
| NiSequenceStreamHelper | Animation streaming helper, reorganized |
| NiKeyframeManager | Replaced by NiControllerManager |

---

## Practical Usage Guide

### For Ghidra Annotation
1. **Use Gb 1.2 headers for method signatures** — virtual method names, parameter types, return types
2. **Do NOT trust Gb 1.2 struct offsets** — verify each offset against the binary due to NiObjectNET/NiAVObject changes
3. **Focus annotation on matched 87 classes first** — these give reliable method names
4. **For the 42 missing classes, use Ghidra decompilation** — no external reference available

### Key Gb 1.2 Source Files for Reference
```
CoreLibs/NiMain/         — Core scene graph, properties, rendering
CoreLibs/NiAnimation/    — Animation system (reorganized from NI 3.1)
CoreLibs/NiCollision/    — Collision system
CoreLibs/NiOldParticle/  — Legacy particle system (matches NI 3.1 better)
CoreLibs/NiSystem/       — Platform abstraction
SDK/Win32/Include/       — Combined headers (1,014 files)
```

### What Gb 1.2 Source Tells Us About BC's Engine
Even where offsets differ, the source reveals:
- **Virtual method ordering** (vtables are likely similar, just with additions at end)
- **Algorithm implementations** (math, scene graph traversal, rendering pipeline)
- **Design patterns** (factory registration, RTTI system, smart pointers, reference counting)
- **Template implementations** (NiTArray, NiTList, NiTMap — these are header-only and likely identical)
