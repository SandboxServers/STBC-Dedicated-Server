> [docs](../README.md) / [engine](README.md) / nirtti-factory-catalog.md

# NiRTTI Factory Registration Catalog - stbc.exe

Complete mapping of all classes registered in the NiRTTI factory hash table at `DAT_009a2b98`.
Each entry maps: **class name** -> **factory function** -> **registration function** -> **guard flag address**.

Generated from exhaustive Ghidra decompilation of all 234 xrefs to `DAT_009a2b98`.

## Architecture Overview

### Hash Table Structure
- **Global pointer**: `DAT_009a2b98` (initialized to NULL, created on first registration)
- **Hash table object**: 0x10 bytes
  - `[+0x00]` = vtable pointer (`PTR_FUN_0088b7c4`)
  - `[+0x04]` = entry count
  - `[+0x08]` = bucket count (always 0x25 = 37)
  - `[+0x0C]` = bucket array pointer (0x94 bytes = 37 * 4)
- **Vtable operations** at `PTR_FUN_0088b7c4`:
  - `[+0x04]` = hash(className) -> bucket index
  - `[+0x08]` = compare(className, nodeClassName) -> bool
  - `[+0x0C]` = setEntry(node, className, factoryFn)
  - `[+0x10]` = deleteEntry(node) -- clears node fields

### Hash Node Structure
- 0x0C bytes per node (linked list in each bucket):
  - `[+0x00]` = className string pointer
  - `[+0x04]` = factory function pointer
  - `[+0x08]` = next node pointer (NULL = end of chain)

### Registration Pattern (identical for ALL 115 classes)
```c
// Example: NiNode registration (FUN_007e3670)
undefined4 RegisterNiNode(void) {
    if (DAT_009a18a0 != '\0') return 0;  // guard: already registered
    DAT_009a18a0 = 1;                     // set guard

    if (DAT_009a2b98 == NULL) {
        // Create hash table (first registration only)
        piVar2 = NiAlloc(0x10);
        piVar2->vtable = &PTR_LAB_0088b7d8;  // temp vtable
        piVar2->count = 0;
        piVar2->bucket_count = 0x25;          // 37 buckets
        piVar2->buckets = NiAlloc(0x94);      // 37 * 4 bytes
        memset(piVar2->buckets, 0, 0x94);
        piVar2->vtable = &PTR_FUN_0088b7c4;  // final vtable
        DAT_009a2b98 = piVar2;
    }

    bucket_idx = vtable->hash("NiNode");
    node = buckets[bucket_idx];
    while (node != NULL) {
        if (vtable->compare("NiNode", node->className)) {
            vtable->deleteEntry(node);
            vtable->setEntry(node, "NiNode", FUN_007e5450);
            return 1;  // replaced existing
        }
        node = node->next;
    }
    // Not found: create new node
    newNode = NiAlloc(0x0C);
    vtable->setEntry(newNode, "NiNode", FUN_007e5450);
    newNode->next = buckets[bucket_idx];
    buckets[bucket_idx] = newNode;  // insert at head
    count++;
    return 1;
}
```

### Consumer Functions (NIF Loader)
| Address | Function | Role |
|---------|----------|------|
| `FUN_008176b0` | NiStream::LoadObject | Reads class name from NIF, looks up factory, calls it. Error: "NiStream: Unable to find loader for..." |
| `FUN_00818150` | NiStream::LoadObjectAlt | Alternative load path (same lookup pattern) |
| `0x00816c40` | (standalone read) | Reads DAT_009a2b98 (purpose unclear, may be cleanup) |

### Memory Allocator
- `FUN_00718cb0` = NiAlloc (malloc with 4-byte size header, small pool for <= 0x80 bytes)

---

## Complete Factory Registration Table (115 entries)

Sorted by registration function address (code order in binary).

### TG Framework Classes (2 entries)

| # | Class Name | String Addr | Factory Fn | Registration Fn | Guard Flag |
|---|-----------|-------------|-----------|----------------|------------|
| 1 | TGDimmerController | 0x008DAED4 | `FUN_00455320` | `FUN_00455060` | `DAT_0098d298` |
| 2 | TGFuzzyTriShape | 0x008DAEE8 | `FUN_00456980` | `FUN_00456740` | `DAT_0098d29c` |

### Ni Classes - Audio (4 entries)

| # | Class Name | String Addr | Factory Fn | Registration Fn | Guard Flag |
|---|-----------|-------------|-----------|----------------|------------|
| 3 | NiListener | 0x00975E98 | `FUN_0078d250` | `FUN_0078cbd0` | `DAT_009a0c40` |
| 4 | NiSoundSystem | 0x00975EA4 | `LAB_0078e6e0` | `FUN_0078d760` | `DAT_009a0c44` |
| 5 | NiSource | 0x00975EB4 | `FUN_007904c0` | `FUN_0078f230` | `DAT_009a0d64` |

### Ni Classes - Voxel Data (2 entries)

| # | Class Name | String Addr | Factory Fn | Registration Fn | Guard Flag |
|---|-----------|-------------|-----------|----------------|------------|
| 6 | NiBinaryVoxelData | 0x008DD2A8 | `FUN_004a57f0` | `FUN_004a56a0` | `DAT_0098e478` |
| 7 | NiBinaryVoxelExtraData | 0x008DD2BC | `FUN_004ac150` | `FUN_004ac000` | `DAT_0098e47c` |

### Ni Classes - Animation Data (7 entries)

| # | Class Name | String Addr | Factory Fn | Registration Fn | Guard Flag |
|---|-----------|-------------|-----------|----------------|------------|
| 8 | NiKeyframeData | 0x00975F20 | `FUN_00792260` | `FUN_00791e40` | `DAT_009a0db4` |
| 9 | NiKeyframeController | 0x00975F64 | `FUN_007932e0` | `FUN_00792b40` | `DAT_009a0e3c` |
| 10 | NiFlipController | 0x00975F7C | `FUN_00793f20` | `FUN_007938d0` | `DAT_009a0ebc` |
| 11 | NiFloatController | 0x00975F90 | `DAT_00794bc0` | `FUN_00794810` | `DAT_009a0f38` |
| 12 | NiFloatData | 0x00975FA4 | `FUN_00795250` | `FUN_00795010` | `DAT_009a0f40` |
| 13 | NiAlphaController | 0x00975FBC | `FUN_00795ae0` | `FUN_00795830` | `DAT_009a0fc0` |
| 14 | NiTextKeyExtraData | 0x00976044 | `FUN_00796f10` | `FUN_00796c50` | `DAT_009a0fcc` |

### Ni Classes - Animation Blending & Color (2 entries)

| # | Class Name | String Addr | Factory Fn | Registration Fn | Guard Flag |
|---|-----------|-------------|-----------|----------------|------------|
| 15 | NiAnimBlender | 0x00976058 | `FUN_0079a630` | `FUN_00797660` | `DAT_009a0fd4` |
| 16 | NiColorData | 0x00976070 | `FUN_0079da20` | `FUN_0079d860` | `DAT_009a10b0` |

### Ni Classes - Physics (4 entries)

| # | Class Name | String Addr | Factory Fn | Registration Fn | Guard Flag |
|---|-----------|-------------|-----------|----------------|------------|
| 17 | NiForce | 0x0097607C | `DAT_0079e510` | `FUN_0079e370` | `DAT_009a10b8` |
| 18 | NiGravity | 0x00976084 | `FUN_0079ecd0` | `FUN_0079e6c0` | `DAT_009a1100` |
| 19 | NiParticleBomb | 0x00976090 | `FUN_0079f760` | `FUN_0079f110` | `DAT_009a1108` |
| 20 | NiSphericalCollider | 0x009760A0 | `FUN_007a02e0` | `FUN_0079fc00` | `DAT_009a1148` |

### Ni Classes - Collision & Managers (3 entries)

| # | Class Name | String Addr | Factory Fn | Registration Fn | Guard Flag |
|---|-----------|-------------|-----------|----------------|------------|
| 21 | NiPlanarCollider | 0x009760B4 | `FUN_007a0fc0` | `FUN_007a06d0` | `DAT_009a1188` |
| 22 | NiKeyframeManager | 0x009760CC | `FUN_007a3f80` | `FUN_007a14a0` | `DAT_009a11c8` |
| 23 | NiPosData | 0x009761D0 | `FUN_007a5ea0` | `FUN_007a5ce0` | `DAT_009a1350` |

### Ni Classes - Light & Look-At Controllers (3 entries)

| # | Class Name | String Addr | Factory Fn | Registration Fn | Guard Flag |
|---|-----------|-------------|-----------|----------------|------------|
| 24 | NiLightColorController | 0x009761DC | `FUN_007a6b80` | `FUN_007a64f0` | `DAT_009a1358` |
| 25 | NiLookAtController | 0x009761F4 | `FUN_007a7dc0` | `FUN_007a7670` | `DAT_009a13d8` |
| 26 | NiMorphController | 0x00976208 | `FUN_007a8dd0` | `FUN_007a8350` | `DAT_009a1458` |

### Ni Classes - Morph & Material (4 entries)

| # | Class Name | String Addr | Factory Fn | Registration Fn | Guard Flag |
|---|-----------|-------------|-----------|----------------|------------|
| 27 | NiMorphData | 0x0097621C | `FUN_007aa2e0` | `FUN_007a9ec0` | `DAT_009a1460` |
| 28 | NiMorpherController | 0x00976250 | `FUN_007ab390` | `FUN_007aacc0` | `DAT_009a14e0` |
| 29 | NiMaterialColorController | 0x0097626C | `FUN_007ac620` | `FUN_007ac020` | `DAT_009a1560` |
| 30 | NiPathController | 0x009762B0 | `FUN_007ae150` | `FUN_007acb80` | `DAT_009a15e0` |

### Ni Classes - Particle System & Sequences (4 entries)

| # | Class Name | String Addr | Factory Fn | Registration Fn | Guard Flag |
|---|-----------|-------------|-----------|----------------|------------|
| 31 | NiParticleSystemController | 0x009762C4 | `FUN_007b2320` | `FUN_007ae9d0` | `DAT_009a1660` |
| 32 | NiRollController | 0x009762E0 | `FUN_007b4020` | `FUN_007b3d10` | `DAT_009a1748` |
| 33 | NiSequenceStreamHelper | 0x009762F4 | `FUN_007b4650` | `FUN_007b4500` | `DAT_009a1750` |
| 34 | NiVisData | 0x0097630C | `FUN_007b5db0` | `FUN_007b5ba0` | `DAT_009a1758` |

### Ni Classes - Visibility Controller (1 entry)

| # | Class Name | String Addr | Factory Fn | Registration Fn | Guard Flag |
|---|-----------|-------------|-----------|----------------|------------|
| 35 | NiVisController | 0x00976328 | `FUN_007b67e0` | `FUN_007b6300` | `DAT_009a17d8` |

### Ni Classes - D3D Renderer (1 entry)

| # | Class Name | String Addr | Factory Fn | Registration Fn | Guard Flag |
|---|-----------|-------------|-----------|----------------|------------|
| 36 | NiD3DRender | 0x00976724 | `FUN_007c4740` | `FUN_007bfcf0` | `DAT_009a1800` |

### Ni Classes - Core Object Hierarchy (7 entries)

| # | Class Name | String Addr | Factory Fn | Registration Fn | Guard Flag |
|---|-----------|-------------|-----------|----------------|------------|
| 37 | NiObject | 0x009780D8 | `DAT_007d8810` | `FUN_007d8650` | `DAT_009a1808` |
| 38 | NiAccumulator | 0x009780F0 | `DAT_007d8f30` | `FUN_007d8d70` | `DAT_009a1810` |
| 39 | NiExtraData | 0x00978100 | `FUN_007d9450` | `FUN_007d9070` | `DAT_009a1818` |
| 40 | NiTimeController | 0x00978118 | `DAT_007da450` | `FUN_007d9a10` | `DAT_009a1820` |
| 41 | NiObjectNET | 0x00978228 | `DAT_007db5e0` | `FUN_007dab30` | `DAT_009a18a8` |
| 42 | NiProperty | 0x0097823C | `DAT_007dbcc0` | `FUN_007dbb00` | `DAT_009a18b0` |
| 43 | NiAVObject | 0x0095B050 | `DAT_007dd470` | `FUN_007dbf70` | `DAT_009a1930` |

### Ni Classes - Images & Raw Data (2 entries)

| # | Class Name | String Addr | Factory Fn | Registration Fn | Guard Flag |
|---|-----------|-------------|-----------|----------------|------------|
| 44 | NiRawImageData | 0x00978330 | `FUN_007e0320` | `FUN_007de090` | `DAT_009a19b0` |
| 45 | NiImage | 0x009783DC | `LAB_007e1630` | `FUN_007e0990` | `DAT_009a1a30` |

### Ni Classes - Dynamic Effects & Renderer (2 entries)

| # | Class Name | String Addr | Factory Fn | Registration Fn | Guard Flag |
|---|-----------|-------------|-----------|----------------|------------|
| 46 | NiDynamicEffect | 0x009784D8 | `DAT_007e2530` | `FUN_007e20b0` | `DAT_009a1a38` |
| 47 | NiRender | 0x009784F4 | `DAT_007e31b0` | `FUN_007e2a40` | `DAT_009a1a40` |

### Ni Classes - Scene Graph Core (2 entries)

| # | Class Name | String Addr | Factory Fn | Registration Fn | Guard Flag |
|---|-----------|-------------|-----------|----------------|------------|
| 48 | NiNode | 0x00978500 | `FUN_007e5450` | `FUN_007e3670` | `DAT_009a18a0` |
| 49 | NiScreenPolygon | 0x00978520 | `FUN_007e6ed0` | `FUN_007e68f0` | `DAT_009a1ac0` |

### Ni Classes - Camera & Accumulators (4 entries)

| # | Class Name | String Addr | Factory Fn | Registration Fn | Guard Flag |
|---|-----------|-------------|-----------|----------------|------------|
| 50 | NiCamera | 0x0097856C | `FUN_007ea2e0` | `FUN_007e79a0` | `DAT_009a1b40` |
| 51 | NiClusterAccumulator | 0x009785F4 | `FUN_007eb850` | `FUN_007eb2f0` | `DAT_009a1bc0` |
| 52 | NiAlphaAccumulator | 0x0097860C | `FUN_007ebd80` | `FUN_007ebb90` | `DAT_009a1bc8` |
| 53 | NiAlphaProperty | 0x00978620 | `FUN_007ec3c0` | `FUN_007ec080` | `DAT_009a1bd0` |

### Ni Classes - Geometry Core (4 entries)

| # | Class Name | String Addr | Factory Fn | Registration Fn | Guard Flag |
|---|-----------|-------------|-----------|----------------|------------|
| 54 | NiGeometryData | 0x0097873C | `DAT_007ed190` | `FUN_007ec9f0` | `DAT_009a1c50` |
| 55 | NiGeometry | 0x00978770 | `DAT_007ee6b0` | `FUN_007edb70` | `DAT_009a1cd0` |
| 56 | NiTriBasedGeomData | 0x0097877C | `DAT_007eed00` | `FUN_007eeb20` | `DAT_009a1cd8` |
| 57 | NiTriBasedGeom | 0x009787A0 | `DAT_007f0d50` | `FUN_007ef0e0` | `DAT_009a1ce0` |

### Ni Classes - Triangle Mesh (3 entries)

| # | Class Name | String Addr | Factory Fn | Registration Fn | Guard Flag |
|---|-----------|-------------|-----------|----------------|------------|
| 58 | NiTriShapeData | 0x009787BC | `FUN_007f1860` | `FUN_007f12b0` | `DAT_009a1d60` |
| 59 | NiTriShape | 0x009787EC | `FUN_007f31f0` | `FUN_007f1ef0` | `DAT_009a1de0` |
| 60 | NiLight | 0x009787F8 | `DAT_007f38e0` | `FUN_007f3650` | `DAT_009a1e60` |

### Ni Classes - Lights (2 entries)

| # | Class Name | String Addr | Factory Fn | Registration Fn | Guard Flag |
|---|-----------|-------------|-----------|----------------|------------|
| 61 | NiAmbientLight | 0x00978824 | `FUN_007f4130` | `FUN_007f3e70` | `DAT_009a1ee0` |
| 62 | NiParticlesData | 0x00978848 | `FUN_007f4830` | `FUN_007f45a0` | `DAT_009a1f60` |

### Ni Classes - Particles (4 entries)

| # | Class Name | String Addr | Factory Fn | Registration Fn | Guard Flag |
|---|-----------|-------------|-----------|----------------|------------|
| 63 | NiParticles | 0x00978860 | `FUN_007f52d0` | `FUN_007f4e00` | `DAT_009a1f68` |
| 64 | NiAutoNormalParticlesData | 0x00978870 | `FUN_007f5970` | `FUN_007f5780` | `DAT_009a1fe8` |
| 65 | NiAutoNormalParticles | 0x00978890 | `FUN_007f60f0` | `FUN_007f5d50` | `DAT_009a1ff0` |
| 66 | NiBillboardNode | 0x009788A8 | `FUN_007f6cf0` | `FUN_007f65b0` | `DAT_009a2070` |

### Ni Classes - Skeletal (2 entries)

| # | Class Name | String Addr | Factory Fn | Registration Fn | Guard Flag |
|---|-----------|-------------|-----------|----------------|------------|
| 67 | NiBone | 0x00978908 | `FUN_007f7990` | `FUN_007f72c0` | `DAT_009a20f0` |
| 68 | NiBSPNode | 0x00978910 | `FUN_007f8590` | `FUN_007f7d50` | `DAT_009a2170` |

### Ni Classes - Collision & Properties (4 entries)

| # | Class Name | String Addr | Factory Fn | Registration Fn | Guard Flag |
|---|-----------|-------------|-----------|----------------|------------|
| 69 | NiCollisionSwitch | 0x0097893C | `FUN_007f8f90` | `FUN_007f8d00` | `DAT_009a21f0` |
| 70 | NiCorrectionProperty | 0x00978960 | `FUN_007f97d0` | `FUN_007f94b0` | `DAT_009a2270` |
| 71 | NiDirectionalLight | 0x00978984 | `FUN_007f9fb0` | `FUN_007f9c20` | `DAT_009a22f0` |
| 72 | NiDitherProperty | 0x00978998 | `FUN_007fa760` | `FUN_007fa440` | `DAT_009a2370` |

### Ni Classes - Env-Mapped Geometry (2 entries)

| # | Class Name | String Addr | Factory Fn | Registration Fn | Guard Flag |
|---|-----------|-------------|-----------|----------------|------------|
| 73 | NiEnvMappedTriShapeData | 0x009789B8 | `FUN_007fad70` | `FUN_007fab60` | `DAT_009a23f0` |
| 74 | NiEnvMappedTriShape | 0x009789D0 | `FUN_007fb610` | `FUN_007fb0d0` | `DAT_009a23f8` |

### Ni Classes - Switch & Animation Nodes (2 entries)

| # | Class Name | String Addr | Factory Fn | Registration Fn | Guard Flag |
|---|-----------|-------------|-----------|----------------|------------|
| 75 | NiSwitchNode | 0x009789E4 | `FUN_007fc850` | `FUN_007fbae0` | `DAT_009a2478` |
| 76 | NiFltAnimationNode | 0x00978A24 | `FUN_007fd230` | `FUN_007fcf30` | `DAT_009a24f8` |

### Ni Classes - Fog & Lines (3 entries)

| # | Class Name | String Addr | Factory Fn | Registration Fn | Guard Flag |
|---|-----------|-------------|-----------|----------------|------------|
| 77 | NiFogProperty | 0x00978A50 | `FUN_007fdc70` | `FUN_007fd8d0` | `DAT_009a2500` |
| 78 | NiLinesData | 0x00978AC8 | `FUN_007fe4c0` | `FUN_007fe230` | `DAT_009a2508` |
| 79 | NiLines | 0x00978AE0 | `FUN_007fec90` | `FUN_007fe990` | `DAT_009a2510` |

### Ni Classes - LOD & Material (2 entries)

| # | Class Name | String Addr | Factory Fn | Registration Fn | Guard Flag |
|---|-----------|-------------|-----------|----------------|------------|
| 80 | NiLODNode | 0x00978AE8 | `FUN_007ffd00` | `FUN_007ff120` | `DAT_009a2518` |
| 81 | NiMaterialProperty | 0x00978B40 | `FUN_00800ae0` | `FUN_00800680` | `DAT_009a2520` |

### Ni Classes - Texture Properties (2 entries)

| # | Class Name | String Addr | Factory Fn | Registration Fn | Guard Flag |
|---|-----------|-------------|-----------|----------------|------------|
| 82 | NiTextureModeProperty | 0x00978B74 | `FUN_00801490` | `FUN_00801120` | `DAT_009a2528` |
| 83 | NiMultiTextureProperty | 0x00978D2C | `FUN_00802630` | `FUN_00801d30` | `DAT_009a2530` |

### Ni Classes - Point Light & Shade (2 entries)

| # | Class Name | String Addr | Factory Fn | Registration Fn | Guard Flag |
|---|-----------|-------------|-----------|----------------|------------|
| 84 | NiPointLight | 0x00978E24 | `FUN_00803ad0` | `FUN_008037a0` | `DAT_009a2538` |
| 85 | NiShadeProperty | 0x00978E58 | `FUN_00804400` | `FUN_008040e0` | `DAT_009a2540` |

### Ni Classes - Skin Controller (1 entry)

| # | Class Name | String Addr | Factory Fn | Registration Fn | Guard Flag |
|---|-----------|-------------|-----------|----------------|------------|
| 86 | NiSkinController | 0x00978E74 | `DAT_00805320` | `FUN_00804850` | `DAT_009a2548` |

### Ni Classes - Sort & Specular (2 entries)

| # | Class Name | String Addr | Factory Fn | Registration Fn | Guard Flag |
|---|-----------|-------------|-----------|----------------|------------|
| 87 | NiSortAdjustNode | 0x00978E88 | `FUN_00805e40` | `FUN_00805a50` | `DAT_009a25c8` |
| 88 | NiSpecularProperty | 0x00978EA4 | `FUN_00806720` | `FUN_00806400` | `DAT_009a25d0` |

### Ni Classes - Spot Light & Stencil (2 entries)

| # | Class Name | String Addr | Factory Fn | Registration Fn | Guard Flag |
|---|-----------|-------------|-----------|----------------|------------|
| 89 | NiSpotLight | 0x00978EC0 | `FUN_00806f10` | `FUN_00806b20` | `DAT_009a2650` |
| 90 | NiStencilProperty | 0x00978EEC | `FUN_00807930` | `FUN_00807570` | `DAT_009a2658` |

### Ni Classes - String Extra Data & Texture Effect (2 entries)

| # | Class Name | String Addr | Factory Fn | Registration Fn | Guard Flag |
|---|-----------|-------------|-----------|----------------|------------|
| 91 | NiStringExtraData | 0x00979064 | `FUN_008085a0` | `FUN_008081f0` | `DAT_009a26d8` |
| 92 | NiTextureEffect | 0x00979084 | `FUN_00809120` | `FUN_00808a60` | `DAT_009a26e0` |

### Ni Classes - Texture & Transparent Properties (2 entries)

| # | Class Name | String Addr | Factory Fn | Registration Fn | Guard Flag |
|---|-----------|-------------|-----------|----------------|------------|
| 93 | NiTextureProperty | 0x0097919C | `FUN_0080a390` | `FUN_00809d20` | `DAT_009a2760` |
| 94 | NiTransparentProperty | 0x009791BC | `FUN_0080ac60` | `FUN_0080a920` | `DAT_009a2768` |

### Ni Classes - Alternative Triangle Types (2 entries)

| # | Class Name | String Addr | Factory Fn | Registration Fn | Guard Flag |
|---|-----------|-------------|-----------|----------------|------------|
| 95 | NiTrianglesData | 0x009791F0 | `FUN_0080b4b0` | `FUN_0080b170` | `DAT_009a254c` |
| 96 | NiTriangles | 0x00979200 | `FUN_0080bde0` | `FUN_0080b8c0` | `DAT_009a25b0` |

### Ni Classes - Dynamic & Skin Mesh (2 entries)

| # | Class Name | String Addr | Factory Fn | Registration Fn | Guard Flag |
|---|-----------|-------------|-----------|----------------|------------|
| 97 | NiTriShapeDynamicData | 0x0097920C | `FUN_0080c4b0` | `FUN_0080c290` | `DAT_009a25d8` |
| 98 | NiTriShapeSkinController | 0x0097924C | `FUN_0080ccd0` | `FUN_0080c960` | `DAT_009a262c` |

### Ni Classes - Triangle Strips (5 entries)

| # | Class Name | String Addr | Factory Fn | Registration Fn | Guard Flag |
|---|-----------|-------------|-----------|----------------|------------|
| 99 | NiTriStripData | 0x00979268 | `FUN_0080d590` | `FUN_0080d000` | `DAT_009a2650` |
| 100 | NiTriStrip | 0x00979278 | `FUN_0080df90` | `FUN_0080da40` | `DAT_009a26b8` |
| 101 | NiTriStripsData | 0x00979284 | `FUN_0080e6b0` | `FUN_0080e490` | `DAT_009a26dc` |
| 102 | NiTriStrips | 0x009792C4 | `FUN_0080f220` | `FUN_0080ec30` | `DAT_009a274c` |
| 103 | NiVertexColorProperty | 0x009792D0 | `FUN_0080fa30` | `FUN_0080f6d0` | `DAT_009a277c` |

### Ni Classes - Vertex & Wireframe Properties (3 entries)

| # | Class Name | String Addr | Factory Fn | Registration Fn | Guard Flag |
|---|-----------|-------------|-----------|----------------|------------|
| 104 | NiVertWeightsExtraData | 0x00979368 | `FUN_00810310` | `FUN_0080ffa0` | `DAT_009a279c` |
| 105 | NiWireframeProperty | 0x00979380 | `FUN_00810a80` | `FUN_00810760` | `DAT_009a27cc` |
| 106 | NiZBufferProperty | 0x009793A4 | `FUN_008111a0` | `FUN_00810e80` | `DAT_009a27fc` |

### Ni Classes - Bezier Geometry (10 entries)

| # | Class Name | String Addr | Factory Fn | Registration Fn | Guard Flag |
|---|-----------|-------------|-----------|----------------|------------|
| 107 | NiBezierMesh | 0x009798A8 | `FUN_00831510` | `FUN_0082e0c0` | `DAT_009b2f64` |
| 108 | NiBezierPatch | 0x00979944 | `DAT_00834570` | `FUN_00832360` | `DAT_009b2fd0` |
| 109 | NiBezierSkinController | 0x00979954 | `FUN_00834ec0` | `FUN_00834c60` | `DAT_009b302c` |
| 110 | NiBezierTriangle | 0x0097996C | `DAT_00838a50` | `FUN_008351f0` | `DAT_009b3094` |
| 111 | NiBezierTriangle2 | 0x00979980 | `FUN_0083a330` | `FUN_00838ea0` | `DAT_009b30e8` |
| 112 | NiBezierTriangle3 | 0x00979994 | `FUN_0083d4d0` | `FUN_0083a7c0` | `DAT_009b3140` |
| 113 | NiBezierTriangle4 | 0x009799A8 | `FUN_00841f90` | `FUN_0083d850` | `DAT_009b3198` |
| 114 | NiBezierRectangle | 0x009799BC | `DAT_00847c90` | `FUN_008422c0` | `DAT_009b3204` |
| 115 | NiBezierRectangle2 | 0x009799D0 | `FUN_00848fe0` | `FUN_00847fe0` | `DAT_009b3254` |
| 116 | NiBezierRectangle3 | 0x009799E4 | `FUN_0084c740` | `FUN_00849350` | `DAT_009b32a0` |
| 117 | NiBezierCylinder | 0x009799F8 | `FUN_00850a30` | `FUN_0084ca60` | `DAT_009b32f0` |

---

## Classes NOT in Factory Table

The following NiRTTI class catalog entries from `docs/rtti-class-catalog.md` do NOT appear
in the factory hash table at `DAT_009a2b98`. These are either:
- Abstract base classes (no factory needed)
- Classes instantiated only through other means (direct constructor calls)
- Classes only referenced through SWIG bindings but never through NIF deserialization

### Notable Absences
- `NiDDImage` / `NiDDBufferImage` -- DirectDraw images (runtime-only, not serialized in NIF)
- `NiCloneExtraData` -- Created at runtime during node cloning
- `NiProvider_Info` -- Audio provider info (runtime enumeration)
- All game-specific classes (Ship*, Weapon*, TG*, ST*, etc.) -- Not NIF-serializable
- All SWIG-only bindings -- Python wrappers, not factory-created

---

## Summary Statistics

| Category | Count |
|----------|-------|
| Total registration functions | 117 |
| Ni* classes | 113 |
| TG* classes | 2 |
| Consumer functions (NIF loaders) | 2 (+1 standalone reader) |
| Hash table buckets | 37 |
| Total xrefs to DAT_009a2b98 | 234 |
| Factory pattern: identical template | YES (100% consistent) |
| TG classes use same hash table | YES (confirmed) |

### Address Ranges
| Component | Range |
|-----------|-------|
| Registration functions | `0x00455060` - `0x0084ca60` |
| Factory functions | `0x00455320` - `0x00850a30` |
| Guard flag variables | `0x0098d298` - `0x009b32f0` |
| Class name strings | `0x008DAED4` - `0x009799F8` |
| Hash table global | `0x009a2b98` |
| Hash table vtable | `PTR_FUN_0088b7c4` |
