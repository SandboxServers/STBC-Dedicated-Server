# Ghidra Jython Script: Annotate NetImmerse 3.1 Vtables (Extended)
# @category STBC
# @description Auto-discovers vtable addresses from all 117 NiRTTI factory
#   functions, names base 12 NiObject slots, constructors, destructors, and
#   vtable labels. Includes hardcoded data for 6 fully-verified core classes.
#
# Discovery pipeline (per class):
#   Factory function -> find CALL targets -> exclude NiAlloc -> constructor
#   Constructor -> find .rdata references -> verify slot 11 noop -> vtable
#   Vtable -> read 12 base slots -> name functions
#
# Data sources: docs/netimmerse-vtables.md, docs/nirtti-factory-catalog.md
# Run from Ghidra Script Manager with stbc.exe loaded.

from ghidra.program.model.symbol import SourceType
from ghidra.program.model.listing import CodeUnit

# ============================================================================
# NiObject base vtable slots (shared by ALL NiObject-derived classes, 0-11)
# ============================================================================
NI_OBJECT_SLOTS = [
    (0, "GetRTTI"),
    (1, "CreateClone"),
    (2, "ProcessClone"),
    (3, "PostLinkObject"),
    (4, "RegisterStreamables"),
    (5, "LoadBinary"),
    (6, "LinkObject"),
    (7, "SaveBinary"),
    (8, "IsEqual"),
    (9, "AddViewerStrings"),
    (10, "scalar_deleting_dtor"),
    (11, "GetViewerStrings_noop"),  # never overridden, always 0x0040da50
]

# NiAVObject-specific slots (12-38)
NI_AVOBJECT_SLOTS = [
    (12, "UpdateControllers"),
    (13, "UpdateNodeBound"),
    (14, "ApplyTransform"),
    (15, "GetObjectByName"),
    (16, "SetSelectiveUpdateFlags"),
    (17, "UpdateDownwardPass"),
    (18, "UpdateSelectedDownwardPass"),
    (19, "UpdateRigidDownwardPass"),
    (20, "UpdatePropertiesDownward"),
    (21, "UpdateEffectsDownward"),
    (22, "UpdateWorldData"),
    (23, "UpdateWorldBound"),
    (24, "Display"),
    (25, "PurgeRendererData"),
    (26, "vfn26"),
    (27, "vfn27"),
    (28, "vfn28"),
    (29, "vfn29"),
    (30, "vfn30"),
    (31, "vfn31"),
    (32, "FindIntersections"),
    (33, "vfn33"),
    (34, "vfn34"),
    (35, "vfn35"),
    (36, "vfn36"),
    (37, "vfn37"),
    (38, "vfn38"),
]

# NiNode-specific slots (39-42)
NI_NODE_SLOTS = [
    (39, "AttachChild"),
    (40, "DetachChild"),
    (41, "DetachChildAt"),
    (42, "SetAt"),
]

# NiProperty-specific slots (12-13, from Gb 1.2 headers)
NI_PROPERTY_SLOTS = [
    (12, "Type"),
    (13, "Update"),
]

# NiExtraData-specific slots (12-13, from Gb 1.2 headers)
NI_EXTRADATA_SLOTS = [
    (12, "IsStreamable"),
    (13, "IsCloneable"),
]

# NiAccumulator-specific slots (12-14, from Gb 1.2 headers)
NI_ACCUMULATOR_SLOTS = [
    (12, "StartAccumulating"),
    (13, "FinishAccumulating"),
    (14, "RegisterObject"),
]

# ============================================================================
# Known special addresses
# ============================================================================
NOOP_FUNC = 0x0040da50
PURECALL  = 0x00859a0b
KNOWN_ALLOC_FUNCS = set([0x00717840, 0x00718cb0])

# Known constructor addresses -> class name (for parent chain resolution)
KNOWN_CTORS = {
    0x007d87a0: "NiObject",
    0x007dac80: "NiObjectNET",
    0x007dc0c0: "NiAVObject",
    0x007edd10: "NiGeometry",
    0x007ef260: "NiTriShape",
}

# ============================================================================
# Verified VTABLE_DEFS (6 core classes with full slot implementations)
# ============================================================================
VTABLE_DEFS = [
    {
        "name": "NiObject",
        "vtable": 0x00898b94,
        "slots": 12,
        "ctor": 0x007d87a0,
        "size": 0x08,
        "rtti": 0x009a1468,
        "slot_names": NI_OBJECT_SLOTS,
        "slot_impls": {
            0: 0x00458770, 1: 0x00458780, 2: 0x00438ff0, 3: 0x00439000,
            4: 0x007d8820, 5: 0x007d8930, 6: 0x007d8940, 7: 0x007d8a40,
            8: 0x007d8a70, 9: 0x007d8ae0, 10: 0x007d87c0, 11: 0x0040da50,
        },
    },
    {
        "name": "NiObjectNET",
        "vtable": 0x00898c48,
        "slots": 12,
        "ctor": 0x007dac80,
        "size": 0x14,
        "slot_names": NI_OBJECT_SLOTS,
        "slot_impls": {
            0: 0x007dba40, 1: 0x007dae00, 2: 0x007db060, 3: 0x007db080,
            4: 0x007db5f0, 5: 0x007db630, 6: 0x007db6c0, 7: 0x007db700,
            8: 0x007db740, 9: 0x007db860, 10: 0x007dba50, 11: 0x0040da50,
        },
    },
    {
        "name": "NiAVObject",
        "vtable": 0x00898ca8,
        "slots": 39,
        "ctor": 0x007dc0c0,
        "size": 0xC4,
        "slot_names": NI_OBJECT_SLOTS + NI_AVOBJECT_SLOTS,
        "slot_impls": {
            0: 0x007ddf90, 1: 0x007dd2b0, 2: 0x007dd3e0, 3: 0x007dd3f0,
            4: 0x007dd480, 5: 0x007dd5f0, 6: 0x007dd630, 7: 0x007dd6a0,
            8: 0x007dd7b0, 9: 0x007dda10, 10: 0x007ddfa0, 11: 0x0040da50,
            12: 0x004341b0, 13: 0x004341c0, 14: 0x00434240, 15: 0x00434250,
            16: 0x00434260, 17: 0x00434270, 18: 0x00434280, 19: 0x00434290,
            20: 0x00434180, 21: 0x004341a0, 22: 0x007dd230, 23: 0x00434210,
            24: 0x00434220, 25: 0x007dc5f0, 26: 0x00456e90, 27: 0x007dc7a0,
            28: 0x007dca60, 29: 0x007dc780, 30: 0x007dca40, 31: 0x004341e0,
            32: 0x004341f0, 33: 0x00434200, 34: 0x00434230, 35: 0x007dcb50,
            36: 0x007dcb70, 37: 0x008201a0, 38: 0x004341d0,
        },
    },
    {
        "name": "NiNode",
        "vtable": 0x00898f2c,
        "slots": 43,
        "ctor": None,
        "factory": 0x007e5450,
        "size": 0xE8,
        "slot_names": NI_OBJECT_SLOTS + NI_AVOBJECT_SLOTS + NI_NODE_SLOTS,
        "slot_impls": {
            0: 0x004e3640, 1: 0x007e4f30, 2: 0x007e5180, 3: 0x007e53e0,
            4: 0x007e5630, 5: 0x007e57d0, 6: 0x007e58d0, 7: 0x007e5940,
            8: 0x007e5a00, 9: 0x007e5b30, 10: 0x007e67d0, 11: 0x0040da50,
            12: 0x007e3e30, 13: 0x004341c0, 14: 0x007e4900, 15: 0x007e4940,
            16: 0x007e4980, 17: 0x007e49c0, 18: 0x007e4a00, 19: 0x007e4a40,
            20: 0x00434180, 21: 0x004341a0, 22: 0x007e4ee0, 23: 0x007e4a80,
            24: 0x007e4ac0, 25: 0x007e3ff0, 26: 0x004d5170, 27: 0x007e4530,
            28: 0x007e4610, 29: 0x007dc780, 30: 0x007dca40, 31: 0x007e46f0,
            32: 0x007e4b00, 33: 0x007e4bd0, 34: 0x007e4d30, 35: 0x007dcb50,
            36: 0x007dcb70, 37: 0x008201a0, 38: 0x007e4170,
            39: 0x007e39b0, 40: 0x007e3b30, 41: 0x007e3a30, 42: 0x007e3c50,
        },
    },
    {
        "name": "NiGeometry",
        "vtable": 0x00899164,
        "slots": 64,
        "ctor": 0x007edd10,
        "size": 0xE0,
        "slot_names": NI_OBJECT_SLOTS + NI_AVOBJECT_SLOTS,
        "slot_impls": {
            0: 0x007eeaa0, 1: 0x007ee660, 2: 0x007ee6a0, 3: 0x007dd3f0,
        },
    },
    {
        "name": "NiTriShape",
        "vtable": 0x00899264,
        "slots": 68,
        "ctor": 0x007ef260,
        "size": 0xE4,
        "slot_names": NI_OBJECT_SLOTS + NI_AVOBJECT_SLOTS,
        "slot_impls": {
            0: 0x007f1220, 1: 0x007f0d00, 2: 0x007f0d40, 3: 0x007dd3f0,
        },
    },
]

# ============================================================================
# Complete NiRTTI factory table (117 classes, from nirtti-factory-catalog.md)
# Format: (className, factoryFnAddr)
# ============================================================================
FACTORY_TABLE = [
    ("TGDimmerController",        0x00455320),
    ("TGFuzzyTriShape",           0x00456980),
    ("NiListener",                0x0078d250),
    ("NiSoundSystem",             0x0078e6e0),
    ("NiSource",                  0x007904c0),
    ("NiBinaryVoxelData",         0x004a57f0),
    ("NiBinaryVoxelExtraData",    0x004ac150),
    ("NiKeyframeData",            0x00792260),
    ("NiKeyframeController",      0x007932e0),
    ("NiFlipController",          0x00793f20),
    ("NiFloatController",         0x00794bc0),
    ("NiFloatData",               0x00795250),
    ("NiAlphaController",         0x00795ae0),
    ("NiTextKeyExtraData",        0x00796f10),
    ("NiAnimBlender",             0x0079a630),
    ("NiColorData",               0x0079da20),
    ("NiForce",                   0x0079e510),
    ("NiGravity",                 0x0079ecd0),
    ("NiParticleBomb",            0x0079f760),
    ("NiSphericalCollider",       0x007a02e0),
    ("NiPlanarCollider",          0x007a0fc0),
    ("NiKeyframeManager",         0x007a3f80),
    ("NiPosData",                 0x007a5ea0),
    ("NiLightColorController",    0x007a6b80),
    ("NiLookAtController",        0x007a7dc0),
    ("NiMorphController",         0x007a8dd0),
    ("NiMorphData",               0x007aa2e0),
    ("NiMorpherController",       0x007ab390),
    ("NiMaterialColorController", 0x007ac620),
    ("NiPathController",          0x007ae150),
    ("NiParticleSystemController",0x007b2320),
    ("NiRollController",          0x007b4020),
    ("NiSequenceStreamHelper",    0x007b4650),
    ("NiVisData",                 0x007b5db0),
    ("NiVisController",           0x007b67e0),
    ("NiD3DRender",               0x007c4740),
    ("NiObject",                  0x007d8810),
    ("NiAccumulator",             0x007d8f30),
    ("NiExtraData",               0x007d9450),
    ("NiTimeController",          0x007da450),
    ("NiObjectNET",               0x007db5e0),
    ("NiProperty",                0x007dbcc0),
    ("NiAVObject",                0x007dd470),
    ("NiRawImageData",            0x007e0320),
    ("NiImage",                   0x007e1630),
    ("NiDynamicEffect",           0x007e2530),
    ("NiRender",                  0x007e31b0),
    ("NiNode",                    0x007e5450),
    ("NiScreenPolygon",           0x007e6ed0),
    ("NiCamera",                  0x007ea2e0),
    ("NiClusterAccumulator",      0x007eb850),
    ("NiAlphaAccumulator",        0x007ebd80),
    ("NiAlphaProperty",           0x007ec3c0),
    ("NiGeometryData",            0x007ed190),
    ("NiGeometry",                0x007ee6b0),
    ("NiTriBasedGeomData",        0x007eed00),
    ("NiTriBasedGeom",            0x007f0d50),
    ("NiTriShapeData",            0x007f1860),
    ("NiTriShape",                0x007f31f0),
    ("NiLight",                   0x007f38e0),
    ("NiAmbientLight",            0x007f4130),
    ("NiParticlesData",           0x007f4830),
    ("NiParticles",               0x007f52d0),
    ("NiAutoNormalParticlesData", 0x007f5970),
    ("NiAutoNormalParticles",     0x007f60f0),
    ("NiBillboardNode",           0x007f6cf0),
    ("NiBone",                    0x007f7990),
    ("NiBSPNode",                 0x007f8590),
    ("NiCollisionSwitch",         0x007f8f90),
    ("NiCorrectionProperty",      0x007f97d0),
    ("NiDirectionalLight",        0x007f9fb0),
    ("NiDitherProperty",          0x007fa760),
    ("NiEnvMappedTriShapeData",   0x007fad70),
    ("NiEnvMappedTriShape",       0x007fb610),
    ("NiSwitchNode",              0x007fc850),
    ("NiFltAnimationNode",        0x007fd230),
    ("NiFogProperty",             0x007fdc70),
    ("NiLinesData",               0x007fe4c0),
    ("NiLines",                   0x007fec90),
    ("NiLODNode",                 0x007ffd00),
    ("NiMaterialProperty",        0x00800ae0),
    ("NiTextureModeProperty",     0x00801490),
    ("NiMultiTextureProperty",    0x00802630),
    ("NiPointLight",              0x00803ad0),
    ("NiShadeProperty",           0x00804400),
    ("NiSkinController",          0x00805320),
    ("NiSortAdjustNode",          0x00805e40),
    ("NiSpecularProperty",        0x00806720),
    ("NiSpotLight",               0x00806f10),
    ("NiStencilProperty",         0x00807930),
    ("NiStringExtraData",         0x008085a0),
    ("NiTextureEffect",           0x00809120),
    ("NiTextureProperty",         0x0080a390),
    ("NiTransparentProperty",     0x0080ac60),
    ("NiTrianglesData",           0x0080b4b0),
    ("NiTriangles",               0x0080bde0),
    ("NiTriShapeDynamicData",     0x0080c4b0),
    ("NiTriShapeSkinController",  0x0080ccd0),
    ("NiTriStripData",            0x0080d590),
    ("NiTriStrip",                0x0080df90),
    ("NiTriStripsData",           0x0080e6b0),
    ("NiTriStrips",               0x0080f220),
    ("NiVertexColorProperty",     0x0080fa30),
    ("NiVertWeightsExtraData",    0x00810310),
    ("NiWireframeProperty",       0x00810a80),
    ("NiZBufferProperty",         0x008111a0),
    ("NiBezierMesh",              0x00831510),
    ("NiBezierPatch",             0x00834570),
    ("NiBezierSkinController",    0x00834ec0),
    ("NiBezierTriangle",          0x00838a50),
    ("NiBezierTriangle2",         0x0083a330),
    ("NiBezierTriangle3",         0x0083d4d0),
    ("NiBezierTriangle4",         0x00841f90),
    ("NiBezierRectangle",         0x00847c90),
    ("NiBezierRectangle2",        0x00848fe0),
    ("NiBezierRectangle3",        0x0084c740),
    ("NiBezierCylinder",          0x00850a30),
]

# Parent class -> slot names (for inherited slot naming)
# Classes not listed inherit only NI_OBJECT_SLOTS (base 12)
PARENT_SLOT_MAP = {
    "NiAVObject":     NI_OBJECT_SLOTS + NI_AVOBJECT_SLOTS,
    "NiNode":         NI_OBJECT_SLOTS + NI_AVOBJECT_SLOTS + NI_NODE_SLOTS,
    "NiGeometry":     NI_OBJECT_SLOTS + NI_AVOBJECT_SLOTS,
    "NiTriBasedGeom": NI_OBJECT_SLOTS + NI_AVOBJECT_SLOTS,
    "NiTriShape":     NI_OBJECT_SLOTS + NI_AVOBJECT_SLOTS,
    "NiProperty":     NI_OBJECT_SLOTS + NI_PROPERTY_SLOTS,
    "NiExtraData":    NI_OBJECT_SLOTS + NI_EXTRADATA_SLOTS,
    "NiAccumulator":  NI_OBJECT_SLOTS + NI_ACCUMULATOR_SLOTS,
}

# Known parent relationships (className -> parentClassName)
# Used to determine which slot names to apply for derived classes
KNOWN_PARENTS = {
    # Direct NiObject children
    "NiObjectNET": "NiObject",
    "NiAccumulator": "NiObject",
    "NiExtraData": "NiObject",
    "NiScreenPolygon": "NiObject",
    # NiObjectNET children
    "NiProperty": "NiObjectNET",
    "NiTimeController": "NiObjectNET",
    "NiAVObject": "NiObjectNET",
    # NiProperty children (all property classes)
    "NiAlphaProperty": "NiProperty",
    "NiDitherProperty": "NiProperty",
    "NiFogProperty": "NiProperty",
    "NiMaterialProperty": "NiProperty",
    "NiShadeProperty": "NiProperty",
    "NiSpecularProperty": "NiProperty",
    "NiStencilProperty": "NiProperty",
    "NiVertexColorProperty": "NiProperty",
    "NiWireframeProperty": "NiProperty",
    "NiZBufferProperty": "NiProperty",
    "NiCorrectionProperty": "NiProperty",
    "NiTextureModeProperty": "NiProperty",
    "NiMultiTextureProperty": "NiProperty",
    "NiTextureProperty": "NiProperty",
    "NiTransparentProperty": "NiProperty",
    # NiExtraData children
    "NiStringExtraData": "NiExtraData",
    "NiBinaryVoxelExtraData": "NiExtraData",
    "NiTextKeyExtraData": "NiExtraData",
    "NiVertWeightsExtraData": "NiExtraData",
    # NiAccumulator children
    "NiClusterAccumulator": "NiAccumulator",
    "NiAlphaAccumulator": "NiAccumulator",
    # NiAVObject children
    "NiDynamicEffect": "NiAVObject",
    "NiNode": "NiAVObject",
    "NiGeometry": "NiAVObject",
    # NiDynamicEffect children
    "NiLight": "NiDynamicEffect",
    "NiTextureEffect": "NiDynamicEffect",
    # NiLight children
    "NiAmbientLight": "NiLight",
    "NiDirectionalLight": "NiLight",
    "NiPointLight": "NiLight",
    "NiSpotLight": "NiPointLight",
    # NiNode children
    "NiBillboardNode": "NiNode",
    "NiBSPNode": "NiNode",
    "NiBone": "NiNode",
    "NiSortAdjustNode": "NiNode",
    "NiSwitchNode": "NiNode",
    "NiCollisionSwitch": "NiNode",
    "NiFltAnimationNode": "NiNode",
    "NiLODNode": "NiSwitchNode",
    # NiGeometry children
    "NiTriBasedGeom": "NiGeometry",
    "NiLines": "NiGeometry",
    "NiParticles": "NiGeometry",
    # NiTriBasedGeom children
    "NiTriShape": "NiTriBasedGeom",
    "NiTriStrip": "NiTriBasedGeom",
    "NiTriStrips": "NiTriBasedGeom",
    "NiTriangles": "NiTriBasedGeom",
    "NiEnvMappedTriShape": "NiTriBasedGeom",
    # NiTriShape children
    "NiTriShapeDynamicData": "NiTriShape",
    "TGFuzzyTriShape": "NiTriShape",
    # Data classes
    "NiGeometryData": "NiObject",
    "NiTriBasedGeomData": "NiGeometryData",
    "NiTriShapeData": "NiTriBasedGeomData",
    "NiTriStripsData": "NiTriBasedGeomData",
    "NiTriStripData": "NiTriBasedGeomData",
    "NiTrianglesData": "NiTriBasedGeomData",
    "NiEnvMappedTriShapeData": "NiTriBasedGeomData",
    "NiLinesData": "NiGeometryData",
    "NiParticlesData": "NiGeometryData",
    "NiAutoNormalParticlesData": "NiParticlesData",
    # NiParticles children
    "NiAutoNormalParticles": "NiParticles",
    # Animation data
    "NiFloatData": "NiObject",
    "NiColorData": "NiObject",
    "NiPosData": "NiObject",
    "NiKeyframeData": "NiObject",
    "NiMorphData": "NiObject",
    "NiVisData": "NiObject",
    "NiBinaryVoxelData": "NiObject",
    # NiTimeController children
    "NiKeyframeController": "NiTimeController",
    "NiFlipController": "NiTimeController",
    "NiFloatController": "NiTimeController",
    "NiAlphaController": "NiFloatController",
    "NiLightColorController": "NiTimeController",
    "NiLookAtController": "NiTimeController",
    "NiMorphController": "NiTimeController",
    "NiMorpherController": "NiTimeController",
    "NiMaterialColorController": "NiTimeController",
    "NiPathController": "NiTimeController",
    "NiParticleSystemController": "NiTimeController",
    "NiRollController": "NiTimeController",
    "NiVisController": "NiTimeController",
    "NiSkinController": "NiTimeController",
    "NiTriShapeSkinController": "NiSkinController",
    "NiBezierSkinController": "NiSkinController",
    "TGDimmerController": "NiTimeController",
    # Misc
    "NiAnimBlender": "NiObject",
    "NiSequenceStreamHelper": "NiObjectNET",
    "NiKeyframeManager": "NiObjectNET",
    "NiRawImageData": "NiObject",
    "NiImage": "NiObject",
    "NiCamera": "NiAVObject",
    "NiRender": "NiObject",
    "NiD3DRender": "NiRender",
    "NiForce": "NiObject",
    "NiGravity": "NiForce",
    "NiParticleBomb": "NiForce",
    "NiSphericalCollider": "NiObject",
    "NiPlanarCollider": "NiObject",
    "NiListener": "NiObject",
    "NiSoundSystem": "NiObject",
    "NiSource": "NiObject",
    # Bezier classes
    "NiBezierMesh": "NiObject",
    "NiBezierPatch": "NiObject",
    "NiBezierTriangle": "NiBezierPatch",
    "NiBezierTriangle2": "NiBezierPatch",
    "NiBezierTriangle3": "NiBezierPatch",
    "NiBezierTriangle4": "NiBezierPatch",
    "NiBezierRectangle": "NiBezierPatch",
    "NiBezierRectangle2": "NiBezierPatch",
    "NiBezierRectangle3": "NiBezierPatch",
    "NiBezierCylinder": "NiBezierPatch",
}


# ============================================================================
# Discovery helper functions
# ============================================================================

def find_calls_in_function(func_addr, fm, listing):
    """Find all CALL target addresses within a function, in instruction order."""
    func = fm.getFunctionAt(toAddr(func_addr))
    if func is None:
        # Try to create function
        func = createFunction(toAddr(func_addr), None)
        if func is None:
            return []

    calls = []
    try:
        instIter = listing.getInstructions(func.getBody(), True)
        while instIter.hasNext():
            inst = instIter.next()
            if inst.getMnemonicString() == "CALL":
                refs = inst.getReferencesFrom()
                for ref in refs:
                    if ref.getReferenceType().isCall():
                        calls.append(ref.getToAddress().getOffset())
    except:
        pass
    return calls


def find_data_refs_in_function(func_addr, fm, listing, mem):
    """Find all non-CALL, non-JUMP references from a function.
    Returns list of (instruction_offset, target_address) tuples."""
    func = fm.getFunctionAt(toAddr(func_addr))
    if func is None:
        return []

    refs = []
    try:
        instIter = listing.getInstructions(func.getBody(), True)
        while instIter.hasNext():
            inst = instIter.next()
            for ref in inst.getReferencesFrom():
                rt = ref.getReferenceType()
                if not rt.isCall() and not rt.isJump() and not rt.isConditional():
                    target = ref.getToAddress().getOffset()
                    refs.append((inst.getAddress().getOffset(), target))
    except:
        pass
    return refs


def is_niobject_vtable(addr_int, mem):
    """Verify an address is an NiObject-derived vtable by checking slot 11 = noop."""
    try:
        slot11 = mem.getInt(toAddr(addr_int + 0x2C))
        return (slot11 & 0xFFFFFFFF) == NOOP_FUNC
    except:
        return False


def is_valid_code_addr(addr_int):
    """Check if an address is in the code section."""
    return 0x00401000 <= addr_int <= 0x00860000


def discover_ctor_from_factory(factory_addr, fm, listing):
    """Find the constructor call in a factory function.
    Pattern: NiAlloc(size); ctor(ptr); return ptr;
    Returns constructor address or None."""
    calls = find_calls_in_function(factory_addr, fm, listing)
    if not calls:
        return None

    # Find NiAlloc call position, then take the next non-alloc call
    alloc_found = False
    for target in calls:
        if target in KNOWN_ALLOC_FUNCS:
            alloc_found = True
            continue
        if alloc_found:
            return target

    # Fallback: if no NiAlloc found, maybe it's a different pattern.
    # Try the last call that's not an alloc
    non_alloc = [c for c in calls if c not in KNOWN_ALLOC_FUNCS]
    if len(non_alloc) == 1:
        return non_alloc[0]

    return None


def discover_vtable_from_ctor(ctor_addr, fm, listing, mem):
    """Find the vtable address written by a constructor.
    Looks for .rdata references where slot 11 is the noop function."""
    data_refs = find_data_refs_in_function(ctor_addr, fm, listing, mem)
    if not data_refs:
        return None

    # Filter for potential vtable addresses
    candidates = []
    for inst_off, target in data_refs:
        # Vtables are in .rdata, typically 0x0088xxxx - 0x009Cxxxx
        if 0x00880000 <= target <= 0x009C0000:
            if is_niobject_vtable(target, mem):
                candidates.append(target)

    if not candidates:
        return None

    # If multiple candidates, prefer the LAST one (constructor pattern:
    # parent ctor writes parent vtable first, then this class overwrites)
    # But actually, parent vtable writes happen inside the parent ctor CALL,
    # not visible in this function's references. So all candidates should
    # be THIS class's vtable. Multiple candidates might be from conditional
    # paths or from the scalar_deleting_dtor embedded in the same function.
    #
    # Use the MOST COMMON candidate, or the LAST unique one.
    return candidates[-1]


def count_vtable_slots(vtable_addr, all_vtable_addrs, mem):
    """Count vtable slots by reading consecutive function pointers.
    Stops at: non-code-address, known vtable boundary, or safety limit."""
    # Find the next known vtable address after this one
    next_boundary = 0xFFFFFFFF
    for other in all_vtable_addrs:
        if other > vtable_addr and other < next_boundary:
            next_boundary = other

    slots = 0
    max_slots = 200  # safety limit
    addr = vtable_addr
    while slots < max_slots:
        if addr >= next_boundary:
            break
        try:
            entry = mem.getInt(toAddr(addr)) & 0xFFFFFFFF
        except:
            break

        if not is_valid_code_addr(entry) and entry != PURECALL:
            break

        slots += 1
        addr += 4

    return slots


def resolve_slot_names(class_name):
    """Determine which slot names to use for a class based on known parents."""
    # Walk the parent chain to find the most specific slot map
    current = class_name
    for depth in range(20):  # prevent infinite loops
        parent = KNOWN_PARENTS.get(current)
        if parent is None:
            break
        if parent in PARENT_SLOT_MAP:
            return PARENT_SLOT_MAP[parent]
        current = parent

    # Check if the class itself has a slot map
    if class_name in PARENT_SLOT_MAP:
        return PARENT_SLOT_MAP[class_name]

    # Default: base 12 NiObject slots only
    return NI_OBJECT_SLOTS


# ============================================================================
# Main function
# ============================================================================

def main():
    fm = currentProgram.getFunctionManager()
    st = currentProgram.getSymbolTable()
    listing = currentProgram.getListing()
    mem = currentProgram.getMemory()

    vtables_labeled = 0
    funcs_named = 0
    ctors_named = 0
    dtors_named = 0
    discovery_ok = 0
    discovery_fail = 0

    # Track which vtable addresses are known (for slot counting boundaries)
    verified_vtable_addrs = set()
    for vdef in VTABLE_DEFS:
        verified_vtable_addrs.add(vdef["vtable"])

    # ========================================
    # PHASE A: Process verified VTABLE_DEFS
    # ========================================
    println("=" * 60)
    println("PHASE A: Verified vtable definitions (%d classes)" % len(VTABLE_DEFS))
    println("=" * 60)

    # Name universal no-op
    fn = fm.getFunctionAt(toAddr(NOOP_FUNC))
    if fn is not None:
        try:
            fn.setName("NiObject_vtable_noop", SourceType.USER_DEFINED)
        except:
            pass
        listing.setComment(toAddr(NOOP_FUNC), CodeUnit.PLATE_COMMENT,
            "Universal no-op virtual (slot 11 in all NiObject-derived vtables).\n"
            "Never overridden by any class. Possibly GetViewerStrings base impl.")

    # Label __purecall
    try:
        st.createLabel(toAddr(PURECALL), "__purecall", SourceType.USER_DEFINED)
    except:
        pass

    # Process each verified vtable
    for vdef in VTABLE_DEFS:
        name = vdef["name"]
        vtable_addr = vdef["vtable"]
        total_slots = vdef["slots"]

        println("  [verified] %s at 0x%08X (%d slots)" % (name, vtable_addr, total_slots))

        # Label the vtable data
        vt_addr = toAddr(vtable_addr)
        try:
            st.createLabel(vt_addr, "%s_vtable" % name, SourceType.USER_DEFINED)
        except:
            pass
        vtables_labeled += 1

        # Build slot name lookup
        slot_name_map = {}
        for slot_num, slot_name in vdef.get("slot_names", []):
            slot_name_map[slot_num] = slot_name

        # Build vtable comment
        vtable_comment = "%s vtable (%d slots, 0x%X bytes)\n" % (name, total_slots, total_slots * 4)
        vtable_comment += "Object size: 0x%X (%d bytes)\n" % (vdef["size"], vdef["size"])
        if vdef.get("ctor"):
            vtable_comment += "Constructor: 0x%08X\n" % vdef["ctor"]
        if vdef.get("factory"):
            vtable_comment += "Factory: 0x%08X\n" % vdef["factory"]
        vtable_comment += "\nSlot map:\n"
        for i in range(total_slots):
            if i in slot_name_map:
                vtable_comment += "  [%d] +0x%02X = %s\n" % (i, i * 4, slot_name_map[i])
        listing.setComment(vt_addr, CodeUnit.PLATE_COMMENT, vtable_comment)

        # Name functions referenced by vtable slots
        slot_impls = vdef.get("slot_impls", {})
        for slot_num, func_addr_int in slot_impls.items():
            if func_addr_int == NOOP_FUNC or func_addr_int == PURECALL:
                continue

            func_addr = toAddr(func_addr_int)
            slot_name = slot_name_map.get(slot_num, "vfn%d" % slot_num)
            target_name = "%s_%s" % (name, slot_name)

            fn = fm.getFunctionAt(func_addr)
            if fn is not None:
                try:
                    fn.setName(target_name, SourceType.USER_DEFINED)
                    funcs_named += 1
                except:
                    pass
                comment = "%s::%s (vtable slot %d, offset +0x%02X)" % (name, slot_name, slot_num, slot_num * 4)
                listing.setComment(func_addr, CodeUnit.PLATE_COMMENT, comment)

        # Name constructor
        ctor_addr = vdef.get("ctor")
        if ctor_addr:
            fn = fm.getFunctionAt(toAddr(ctor_addr))
            if fn is not None:
                try:
                    fn.setName("%s_ctor" % name, SourceType.USER_DEFINED)
                    ctors_named += 1
                except:
                    pass
                listing.setComment(toAddr(ctor_addr), CodeUnit.PLATE_COMMENT,
                    "%s constructor (__fastcall: ECX=this).\n"
                    "Calls parent ctor, initializes fields, writes vtable pointer at 0x%08X." % (name, vtable_addr))

    # ========================================
    # PHASE B: Auto-discover from factories
    # ========================================
    println("")
    println("=" * 60)
    println("PHASE B: Auto-discovery from %d NiRTTI factories" % len(FACTORY_TABLE))
    println("=" * 60)

    # Build set of class names already handled by VTABLE_DEFS
    verified_names = set()
    for vdef in VTABLE_DEFS:
        verified_names.add(vdef["name"])

    # Pass 1: Discover all constructor and vtable addresses
    discovered = {}  # className -> {"ctor": addr, "vtable": addr}
    println("  Pass 1: Discovering constructors and vtables...")

    for class_name, factory_addr in FACTORY_TABLE:
        if class_name in verified_names:
            continue  # already handled

        ctor = discover_ctor_from_factory(factory_addr, fm, listing)
        vtable = None

        if ctor:
            vtable = discover_vtable_from_ctor(ctor, fm, listing, mem)
            if vtable:
                discovered[class_name] = {"ctor": ctor, "vtable": vtable, "factory": factory_addr}
                verified_vtable_addrs.add(vtable)
                discovery_ok += 1
            else:
                # Try finding vtable directly in factory (inlined ctor)
                vtable = discover_vtable_from_ctor(factory_addr, fm, listing, mem)
                if vtable:
                    discovered[class_name] = {"ctor": None, "vtable": vtable, "factory": factory_addr}
                    verified_vtable_addrs.add(vtable)
                    discovery_ok += 1
                else:
                    println("    FAIL: %s - no vtable found (ctor=0x%08X)" % (class_name, ctor))
                    discovery_fail += 1
        else:
            # No ctor found - try finding vtable directly in factory
            vtable = discover_vtable_from_ctor(factory_addr, fm, listing, mem)
            if vtable:
                discovered[class_name] = {"ctor": None, "vtable": vtable, "factory": factory_addr}
                verified_vtable_addrs.add(vtable)
                discovery_ok += 1
            else:
                println("    FAIL: %s - no ctor or vtable found (factory=0x%08X)" % (class_name, factory_addr))
                discovery_fail += 1

    println("  Discovered: %d OK, %d failed" % (discovery_ok, discovery_fail))

    # Pass 2: Count vtable slots using known boundaries
    println("  Pass 2: Counting vtable slots...")
    all_vtable_addrs = sorted(verified_vtable_addrs)

    for class_name, info in discovered.items():
        vtable = info["vtable"]
        info["slots"] = count_vtable_slots(vtable, all_vtable_addrs, mem)

    # Pass 3: Name everything
    println("  Pass 3: Naming functions...")

    for class_name, info in discovered.items():
        vtable_addr = info["vtable"]
        ctor_addr = info.get("ctor")
        slot_count = info.get("slots", 12)
        factory_addr = info["factory"]

        # Determine slot names based on parent class
        slot_names = resolve_slot_names(class_name)
        slot_name_map = {}
        for slot_num, slot_name in slot_names:
            if slot_num < slot_count:
                slot_name_map[slot_num] = slot_name

        # Label vtable
        vt_addr = toAddr(vtable_addr)
        try:
            st.createLabel(vt_addr, "%s_vtable" % class_name, SourceType.USER_DEFINED)
        except:
            pass
        vtables_labeled += 1

        # Build vtable comment
        vtable_comment = "%s vtable (%d slots, 0x%X bytes)\n" % (class_name, slot_count, slot_count * 4)
        vtable_comment += "Factory: 0x%08X\n" % factory_addr
        if ctor_addr:
            vtable_comment += "Constructor: 0x%08X\n" % ctor_addr
        parent = KNOWN_PARENTS.get(class_name, "?")
        vtable_comment += "Parent: %s\n" % parent
        vtable_comment += "Discovery: auto\n\nSlot map:\n"
        for i in range(min(slot_count, max(slot_name_map.keys()) + 1 if slot_name_map else 12)):
            if i in slot_name_map:
                vtable_comment += "  [%d] +0x%02X = %s\n" % (i, i * 4, slot_name_map[i])
        listing.setComment(vt_addr, CodeUnit.PLATE_COMMENT, vtable_comment)

        # Read and name slot functions (base slots)
        for slot_num in range(min(slot_count, max(slot_name_map.keys()) + 1 if slot_name_map else 12)):
            if slot_num not in slot_name_map:
                continue

            try:
                func_ptr = mem.getInt(toAddr(vtable_addr + slot_num * 4)) & 0xFFFFFFFF
            except:
                continue

            if func_ptr == NOOP_FUNC or func_ptr == PURECALL:
                continue

            if not is_valid_code_addr(func_ptr):
                continue

            slot_name = slot_name_map[slot_num]
            target_name = "%s_%s" % (class_name, slot_name)
            func_addr = toAddr(func_ptr)

            fn = fm.getFunctionAt(func_addr)
            if fn is not None:
                try:
                    fn.setName(target_name, SourceType.USER_DEFINED)
                    funcs_named += 1
                except:
                    pass
                comment = "%s::%s (vtable slot %d, offset +0x%02X)" % (
                    class_name, slot_name, slot_num, slot_num * 4)
                listing.setComment(func_addr, CodeUnit.PLATE_COMMENT, comment)

        # Name constructor
        if ctor_addr:
            fn = fm.getFunctionAt(toAddr(ctor_addr))
            if fn is not None:
                try:
                    fn.setName("%s_ctor" % class_name, SourceType.USER_DEFINED)
                    ctors_named += 1
                except:
                    pass
                listing.setComment(toAddr(ctor_addr), CodeUnit.PLATE_COMMENT,
                    "%s constructor (__fastcall: ECX=this).\n"
                    "Writes vtable pointer at 0x%08X." % (class_name, vtable_addr))

        # Name scalar_deleting_dtor from slot 10
        try:
            dtor_ptr = mem.getInt(toAddr(vtable_addr + 10 * 4)) & 0xFFFFFFFF
            if is_valid_code_addr(dtor_ptr) and dtor_ptr != NOOP_FUNC:
                fn = fm.getFunctionAt(toAddr(dtor_ptr))
                if fn is not None:
                    try:
                        fn.setName("%s_scalar_deleting_dtor" % class_name, SourceType.USER_DEFINED)
                        dtors_named += 1
                    except:
                        pass
                    listing.setComment(toAddr(dtor_ptr), CodeUnit.PLATE_COMMENT,
                        "%s scalar deleting destructor (vtable slot 10).\n"
                        "Pattern: call real_dtor(this); if (flags & 1) NiFree(this);" % class_name)
        except:
            pass

        println("    %s: vtable=0x%08X slots=%d ctor=%s" % (
            class_name, vtable_addr, slot_count,
            ("0x%08X" % ctor_addr) if ctor_addr else "inlined"))

    # ========================================
    # PHASE C: Label RTTI data
    # ========================================
    rtti_labels = {
        0x009a1468: "g_NiRTTI_NiObject",
        0x009a1478: "g_NiObject_instanceCount",
    }
    for addr_int, label in rtti_labels.items():
        try:
            st.createLabel(toAddr(addr_int), label, SourceType.USER_DEFINED)
        except:
            pass

    # ========================================
    # Summary
    # ========================================
    println("")
    println("=" * 60)
    println("Extended Vtable Annotation Complete")
    println("  Verified vtables:        %d" % len(VTABLE_DEFS))
    println("  Auto-discovered:         %d (failed: %d)" % (discovery_ok, discovery_fail))
    println("  Total vtables labeled:   %d" % vtables_labeled)
    println("  Virtual funcs named:     %d" % funcs_named)
    println("  Constructors named:      %d" % ctors_named)
    println("  Destructors named:       %d" % dtors_named)
    println("=" * 60)

main()
