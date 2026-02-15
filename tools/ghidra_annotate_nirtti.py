# Ghidra Jython Script: Annotate NiRTTI Factory Registrations
# @category STBC
# @description Annotates all 117 NiRTTI factory registrations in stbc.exe.
#   Labels factory functions, registration functions, guard flags, and
#   class name strings. Also labels the hash table global and its vtable.
#
# Data source: docs/nirtti-factory-catalog.md (exhaustive Ghidra analysis)
# Run from Ghidra Script Manager with stbc.exe loaded.

from ghidra.program.model.symbol import SourceType
from ghidra.program.model.listing import CodeUnit

# Hash table infrastructure
HASH_TABLE_GLOBAL  = 0x009a2b98  # DAT_009a2b98
HASH_TABLE_VTABLE  = 0x0088b7c4  # PTR_FUN_0088b7c4
HASH_TABLE_TMPVTBL = 0x0088b7d8  # PTR_LAB_0088b7d8 (temp, swapped during init)
NI_ALLOC           = 0x00718cb0  # NiAlloc (malloc with size header)
NI_STREAM_LOAD     = 0x008176b0  # NiStream::LoadObject (main consumer)
NI_STREAM_LOAD_ALT = 0x00818150  # NiStream::LoadObjectAlt

# Complete factory registration table: (className, stringAddr, factoryFn, registrationFn, guardFlag)
FACTORY_TABLE = [
    # TG Framework
    ("TGDimmerController",       0x008DAED4, 0x00455320, 0x00455060, 0x0098d298),
    ("TGFuzzyTriShape",          0x008DAEE8, 0x00456980, 0x00456740, 0x0098d29c),
    # Audio
    ("NiListener",               0x00975E98, 0x0078d250, 0x0078cbd0, 0x009a0c40),
    ("NiSoundSystem",            0x00975EA4, 0x0078e6e0, 0x0078d760, 0x009a0c44),
    ("NiSource",                 0x00975EB4, 0x007904c0, 0x0078f230, 0x009a0d64),
    # Voxel
    ("NiBinaryVoxelData",        0x008DD2A8, 0x004a57f0, 0x004a56a0, 0x0098e478),
    ("NiBinaryVoxelExtraData",   0x008DD2BC, 0x004ac150, 0x004ac000, 0x0098e47c),
    # Animation Data
    ("NiKeyframeData",           0x00975F20, 0x00792260, 0x00791e40, 0x009a0db4),
    ("NiKeyframeController",     0x00975F64, 0x007932e0, 0x00792b40, 0x009a0e3c),
    ("NiFlipController",         0x00975F7C, 0x00793f20, 0x007938d0, 0x009a0ebc),
    ("NiFloatController",        0x00975F90, 0x00794bc0, 0x00794810, 0x009a0f38),
    ("NiFloatData",              0x00975FA4, 0x00795250, 0x00795010, 0x009a0f40),
    ("NiAlphaController",        0x00975FBC, 0x00795ae0, 0x00795830, 0x009a0fc0),
    ("NiTextKeyExtraData",       0x00976044, 0x00796f10, 0x00796c50, 0x009a0fcc),
    # Animation Blending
    ("NiAnimBlender",            0x00976058, 0x0079a630, 0x00797660, 0x009a0fd4),
    ("NiColorData",              0x00976070, 0x0079da20, 0x0079d860, 0x009a10b0),
    # Physics
    ("NiForce",                  0x0097607C, 0x0079e510, 0x0079e370, 0x009a10b8),
    ("NiGravity",                0x00976084, 0x0079ecd0, 0x0079e6c0, 0x009a1100),
    ("NiParticleBomb",           0x00976090, 0x0079f760, 0x0079f110, 0x009a1108),
    ("NiSphericalCollider",      0x009760A0, 0x007a02e0, 0x0079fc00, 0x009a1148),
    # Collision & Managers
    ("NiPlanarCollider",         0x009760B4, 0x007a0fc0, 0x007a06d0, 0x009a1188),
    ("NiKeyframeManager",        0x009760CC, 0x007a3f80, 0x007a14a0, 0x009a11c8),
    ("NiPosData",                0x009761D0, 0x007a5ea0, 0x007a5ce0, 0x009a1350),
    # Light & Look-At Controllers
    ("NiLightColorController",   0x009761DC, 0x007a6b80, 0x007a64f0, 0x009a1358),
    ("NiLookAtController",       0x009761F4, 0x007a7dc0, 0x007a7670, 0x009a13d8),
    ("NiMorphController",        0x00976208, 0x007a8dd0, 0x007a8350, 0x009a1458),
    # Morph & Material
    ("NiMorphData",              0x0097621C, 0x007aa2e0, 0x007a9ec0, 0x009a1460),
    ("NiMorpherController",      0x00976250, 0x007ab390, 0x007aacc0, 0x009a14e0),
    ("NiMaterialColorController",0x0097626C, 0x007ac620, 0x007ac020, 0x009a1560),
    ("NiPathController",         0x009762B0, 0x007ae150, 0x007acb80, 0x009a15e0),
    # Particle & Sequences
    ("NiParticleSystemController",0x009762C4, 0x007b2320, 0x007ae9d0, 0x009a1660),
    ("NiRollController",         0x009762E0, 0x007b4020, 0x007b3d10, 0x009a1748),
    ("NiSequenceStreamHelper",   0x009762F4, 0x007b4650, 0x007b4500, 0x009a1750),
    ("NiVisData",                0x0097630C, 0x007b5db0, 0x007b5ba0, 0x009a1758),
    ("NiVisController",          0x00976328, 0x007b67e0, 0x007b6300, 0x009a17d8),
    # D3D Renderer
    ("NiD3DRender",              0x00976724, 0x007c4740, 0x007bfcf0, 0x009a1800),
    # Core Object Hierarchy
    ("NiObject",                 0x009780D8, 0x007d8810, 0x007d8650, 0x009a1808),
    ("NiAccumulator",            0x009780F0, 0x007d8f30, 0x007d8d70, 0x009a1810),
    ("NiExtraData",              0x00978100, 0x007d9450, 0x007d9070, 0x009a1818),
    ("NiTimeController",         0x00978118, 0x007da450, 0x007d9a10, 0x009a1820),
    ("NiObjectNET",              0x00978228, 0x007db5e0, 0x007dab30, 0x009a18a8),
    ("NiProperty",               0x0097823C, 0x007dbcc0, 0x007dbb00, 0x009a18b0),
    ("NiAVObject",               0x0095B050, 0x007dd470, 0x007dbf70, 0x009a1930),
    # Images & Raw Data
    ("NiRawImageData",           0x00978330, 0x007e0320, 0x007de090, 0x009a19b0),
    ("NiImage",                  0x009783DC, 0x007e1630, 0x007e0990, 0x009a1a30),
    # Dynamic Effects
    ("NiDynamicEffect",          0x009784D8, 0x007e2530, 0x007e20b0, 0x009a1a38),
    ("NiRender",                 0x009784F4, 0x007e31b0, 0x007e2a40, 0x009a1a40),
    # Scene Graph Core
    ("NiNode",                   0x00978500, 0x007e5450, 0x007e3670, 0x009a18a0),
    ("NiScreenPolygon",          0x00978520, 0x007e6ed0, 0x007e68f0, 0x009a1ac0),
    # Camera & Accumulators
    ("NiCamera",                 0x0097856C, 0x007ea2e0, 0x007e79a0, 0x009a1b40),
    ("NiClusterAccumulator",     0x009785F4, 0x007eb850, 0x007eb2f0, 0x009a1bc0),
    ("NiAlphaAccumulator",       0x0097860C, 0x007ebd80, 0x007ebb90, 0x009a1bc8),
    ("NiAlphaProperty",          0x00978620, 0x007ec3c0, 0x007ec080, 0x009a1bd0),
    # Geometry Core
    ("NiGeometryData",           0x0097873C, 0x007ed190, 0x007ec9f0, 0x009a1c50),
    ("NiGeometry",               0x00978770, 0x007ee6b0, 0x007edb70, 0x009a1cd0),
    ("NiTriBasedGeomData",       0x0097877C, 0x007eed00, 0x007eeb20, 0x009a1cd8),
    ("NiTriBasedGeom",           0x009787A0, 0x007f0d50, 0x007ef0e0, 0x009a1ce0),
    # Triangle Mesh
    ("NiTriShapeData",           0x009787BC, 0x007f1860, 0x007f12b0, 0x009a1d60),
    ("NiTriShape",               0x009787EC, 0x007f31f0, 0x007f1ef0, 0x009a1de0),
    ("NiLight",                  0x009787F8, 0x007f38e0, 0x007f3650, 0x009a1e60),
    # Lights
    ("NiAmbientLight",           0x00978824, 0x007f4130, 0x007f3e70, 0x009a1ee0),
    ("NiParticlesData",          0x00978848, 0x007f4830, 0x007f45a0, 0x009a1f60),
    # Particles
    ("NiParticles",              0x00978860, 0x007f52d0, 0x007f4e00, 0x009a1f68),
    ("NiAutoNormalParticlesData",0x00978870, 0x007f5970, 0x007f5780, 0x009a1fe8),
    ("NiAutoNormalParticles",    0x00978890, 0x007f60f0, 0x007f5d50, 0x009a1ff0),
    ("NiBillboardNode",          0x009788A8, 0x007f6cf0, 0x007f65b0, 0x009a2070),
    # Skeletal
    ("NiBone",                   0x00978908, 0x007f7990, 0x007f72c0, 0x009a20f0),
    ("NiBSPNode",                0x00978910, 0x007f8590, 0x007f7d50, 0x009a2170),
    # Collision & Properties
    ("NiCollisionSwitch",        0x0097893C, 0x007f8f90, 0x007f8d00, 0x009a21f0),
    ("NiCorrectionProperty",     0x00978960, 0x007f97d0, 0x007f94b0, 0x009a2270),
    ("NiDirectionalLight",       0x00978984, 0x007f9fb0, 0x007f9c20, 0x009a22f0),
    ("NiDitherProperty",         0x00978998, 0x007fa760, 0x007fa440, 0x009a2370),
    # Env-Mapped Geometry
    ("NiEnvMappedTriShapeData",  0x009789B8, 0x007fad70, 0x007fab60, 0x009a23f0),
    ("NiEnvMappedTriShape",      0x009789D0, 0x007fb610, 0x007fb0d0, 0x009a23f8),
    # Switch & Animation Nodes
    ("NiSwitchNode",             0x009789E4, 0x007fc850, 0x007fbae0, 0x009a2478),
    ("NiFltAnimationNode",       0x00978A24, 0x007fd230, 0x007fcf30, 0x009a24f8),
    # Fog & Lines
    ("NiFogProperty",            0x00978A50, 0x007fdc70, 0x007fd8d0, 0x009a2500),
    ("NiLinesData",              0x00978AC8, 0x007fe4c0, 0x007fe230, 0x009a2508),
    ("NiLines",                  0x00978AE0, 0x007fec90, 0x007fe990, 0x009a2510),
    # LOD & Material
    ("NiLODNode",                0x00978AE8, 0x007ffd00, 0x007ff120, 0x009a2518),
    ("NiMaterialProperty",       0x00978B40, 0x00800ae0, 0x00800680, 0x009a2520),
    # Texture Properties
    ("NiTextureModeProperty",    0x00978B74, 0x00801490, 0x00801120, 0x009a2528),
    ("NiMultiTextureProperty",   0x00978D2C, 0x00802630, 0x00801d30, 0x009a2530),
    # Point Light & Shade
    ("NiPointLight",             0x00978E24, 0x00803ad0, 0x008037a0, 0x009a2538),
    ("NiShadeProperty",          0x00978E58, 0x00804400, 0x008040e0, 0x009a2540),
    # Skin
    ("NiSkinController",         0x00978E74, 0x00805320, 0x00804850, 0x009a2548),
    # Sort & Specular
    ("NiSortAdjustNode",         0x00978E88, 0x00805e40, 0x00805a50, 0x009a25c8),
    ("NiSpecularProperty",       0x00978EA4, 0x00806720, 0x00806400, 0x009a25d0),
    # Spot Light & Stencil
    ("NiSpotLight",              0x00978EC0, 0x00806f10, 0x00806b20, 0x009a2650),
    ("NiStencilProperty",        0x00978EEC, 0x00807930, 0x00807570, 0x009a2658),
    # String Extra & Texture Effect
    ("NiStringExtraData",        0x00979064, 0x008085a0, 0x008081f0, 0x009a26d8),
    ("NiTextureEffect",          0x00979084, 0x00809120, 0x00808a60, 0x009a26e0),
    # Texture & Transparent
    ("NiTextureProperty",        0x0097919C, 0x0080a390, 0x00809d20, 0x009a2760),
    ("NiTransparentProperty",    0x009791BC, 0x0080ac60, 0x0080a920, 0x009a2768),
    # Alt Triangle Types
    ("NiTrianglesData",          0x009791F0, 0x0080b4b0, 0x0080b170, 0x009a254c),
    ("NiTriangles",              0x00979200, 0x0080bde0, 0x0080b8c0, 0x009a25b0),
    # Dynamic & Skin Mesh
    ("NiTriShapeDynamicData",    0x0097920C, 0x0080c4b0, 0x0080c290, 0x009a25d8),
    ("NiTriShapeSkinController", 0x0097924C, 0x0080ccd0, 0x0080c960, 0x009a262c),
    # Triangle Strips
    ("NiTriStripData",           0x00979268, 0x0080d590, 0x0080d000, 0x009a2650),
    ("NiTriStrip",               0x00979278, 0x0080df90, 0x0080da40, 0x009a26b8),
    ("NiTriStripsData",          0x00979284, 0x0080e6b0, 0x0080e490, 0x009a26dc),
    ("NiTriStrips",              0x009792C4, 0x0080f220, 0x0080ec30, 0x009a274c),
    ("NiVertexColorProperty",    0x009792D0, 0x0080fa30, 0x0080f6d0, 0x009a277c),
    # Vertex & Wireframe
    ("NiVertWeightsExtraData",   0x00979368, 0x00810310, 0x0080ffa0, 0x009a279c),
    ("NiWireframeProperty",      0x00979380, 0x00810a80, 0x00810760, 0x009a27cc),
    ("NiZBufferProperty",        0x009793A4, 0x008111a0, 0x00810e80, 0x009a27fc),
    # Bezier Geometry
    ("NiBezierMesh",             0x009798A8, 0x00831510, 0x0082e0c0, 0x009b2f64),
    ("NiBezierPatch",            0x00979944, 0x00834570, 0x00832360, 0x009b2fd0),
    ("NiBezierSkinController",   0x00979954, 0x00834ec0, 0x00834c60, 0x009b302c),
    ("NiBezierTriangle",         0x0097996C, 0x00838a50, 0x008351f0, 0x009b3094),
    ("NiBezierTriangle2",        0x00979980, 0x0083a330, 0x00838ea0, 0x009b30e8),
    ("NiBezierTriangle3",        0x00979994, 0x0083d4d0, 0x0083a7c0, 0x009b3140),
    ("NiBezierTriangle4",        0x009799A8, 0x00841f90, 0x0083d850, 0x009b3198),
    ("NiBezierRectangle",        0x009799BC, 0x00847c90, 0x008422c0, 0x009b3204),
    ("NiBezierRectangle2",       0x009799D0, 0x00848fe0, 0x00847fe0, 0x009b3254),
    ("NiBezierRectangle3",       0x009799E4, 0x0084c740, 0x00849350, 0x009b32a0),
    ("NiBezierCylinder",         0x009799F8, 0x00850a30, 0x0084ca60, 0x009b32f0),
]


def label_or_rename(st, addr, name):
    """Create or replace a label at addr. Returns True on success."""
    for sym in st.getSymbols(name):
        if sym.getAddress() != addr and sym.getSource() == SourceType.USER_DEFINED:
            sym.delete()
    existing = st.getPrimarySymbol(addr)
    if existing is not None and existing.getName() == name:
        return True
    try:
        if existing is not None and existing.getSource() != SourceType.DEFAULT:
            existing.setName(name, SourceType.USER_DEFINED)
        else:
            st.createLabel(addr, name, SourceType.USER_DEFINED)
        return True
    except:
        try:
            ns = currentProgram.getGlobalNamespace()
            st.createLabel(addr, name, ns, SourceType.USER_DEFINED)
            return True
        except:
            return False


def main():
    fm = currentProgram.getFunctionManager()
    st = currentProgram.getSymbolTable()
    listing = currentProgram.getListing()

    # Label infrastructure
    try:
        label_or_rename(st, toAddr(HASH_TABLE_GLOBAL), "g_NiRTTI_FactoryHashTable")
        listing.setComment(toAddr(HASH_TABLE_GLOBAL), CodeUnit.PLATE_COMMENT,
            "NiRTTI factory hash table pointer.\n"
            "37 buckets, 0xC-byte linked-list nodes {className, factoryFn, next}.\n"
            "Consumer: NiStream::LoadObject (0x008176b0)")
    except Exception, e:
        println("  ERROR labeling hash table: %s" % str(e))

    try:
        label_or_rename(st, toAddr(HASH_TABLE_VTABLE), "NiRTTI_HashTable_vtable")
        label_or_rename(st, toAddr(HASH_TABLE_TMPVTBL), "NiRTTI_HashTable_tmpvtable")
    except Exception, e:
        println("  ERROR labeling vtables: %s" % str(e))

    # Label consumer functions
    for addr_int, name in [(NI_STREAM_LOAD, "NiStream_LoadObject"),
                           (NI_STREAM_LOAD_ALT, "NiStream_LoadObjectAlt"),
                           (NI_ALLOC, "NiAlloc")]:
        try:
            fn = fm.getFunctionAt(toAddr(addr_int))
            if fn is not None:
                fn.setName(name, SourceType.USER_DEFINED)
        except Exception, e:
            println("  WARN: could not name 0x%08x as %s: %s" % (addr_int, name, str(e)))

    # Process each factory registration
    factories_named = 0
    regs_named = 0
    guards_labeled = 0
    strings_labeled = 0
    factories_fail = 0
    regs_fail = 0

    for className, strAddr, factoryFn, regFn, guardFlag in FACTORY_TABLE:
        # Name the factory function
        try:
            fn = fm.getFunctionAt(toAddr(factoryFn))
            if fn is not None:
                fn.setName("NiFactory_%s" % className, SourceType.USER_DEFINED)
                listing.setComment(toAddr(factoryFn), CodeUnit.PLATE_COMMENT,
                    "NiRTTI factory: creates %s instance.\n"
                    "Called by NiStream::LoadObject when deserializing NIF files." % className)
                factories_named += 1
            else:
                try:
                    fn = createFunction(toAddr(factoryFn), "NiFactory_%s" % className)
                    if fn is not None:
                        listing.setComment(toAddr(factoryFn), CodeUnit.PLATE_COMMENT,
                            "NiRTTI factory: creates %s instance.\n"
                            "Called by NiStream::LoadObject when deserializing NIF files." % className)
                        factories_named += 1
                    else:
                        factories_fail += 1
                except:
                    factories_fail += 1
        except Exception, e:
            println("  ERROR factory %s at 0x%08x: %s" % (className, factoryFn, str(e)))
            factories_fail += 1

        # Name the registration function
        try:
            fn = fm.getFunctionAt(toAddr(regFn))
            if fn is not None:
                fn.setName("NiRegister_%s" % className, SourceType.USER_DEFINED)
                listing.setComment(toAddr(regFn), CodeUnit.PLATE_COMMENT,
                    "Registers %s in NiRTTI factory hash table.\n"
                    "Guard flag at 0x%08X prevents double registration." % (className, guardFlag))
                regs_named += 1
            else:
                try:
                    fn = createFunction(toAddr(regFn), "NiRegister_%s" % className)
                    if fn is not None:
                        listing.setComment(toAddr(regFn), CodeUnit.PLATE_COMMENT,
                            "Registers %s in NiRTTI factory hash table.\n"
                            "Guard flag at 0x%08X prevents double registration." % (className, guardFlag))
                        regs_named += 1
                    else:
                        regs_fail += 1
                except:
                    regs_fail += 1
        except Exception, e:
            println("  ERROR register %s at 0x%08x: %s" % (className, regFn, str(e)))
            regs_fail += 1

        # Label the guard flag
        try:
            label_or_rename(st, toAddr(guardFlag), "g_bRegistered_%s" % className)
            guards_labeled += 1
        except Exception, e:
            println("  ERROR guard %s: %s" % (className, str(e)))

        # Label the class name string
        try:
            label_or_rename(st, toAddr(strAddr), "s_NiRTTI_%s" % className)
            strings_labeled += 1
        except Exception, e:
            println("  ERROR string %s: %s" % (className, str(e)))

    println("")
    println("=" * 60)
    println("NiRTTI Factory Annotation Complete")
    println("  Total registrations:     %d" % len(FACTORY_TABLE))
    println("  Factory funcs named:     %d / %d" % (factories_named, len(FACTORY_TABLE)))
    if factories_fail > 0:
        println("  Factory funcs FAILED:    %d" % factories_fail)
    println("  Registration funcs named:%d / %d" % (regs_named, len(FACTORY_TABLE)))
    if regs_fail > 0:
        println("  Registration FAILED:     %d" % regs_fail)
    println("  Guard flags labeled:     %d" % guards_labeled)
    println("  Class strings labeled:   %d" % strings_labeled)
    println("=" * 60)

main()
