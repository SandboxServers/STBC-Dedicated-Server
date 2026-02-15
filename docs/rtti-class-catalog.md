# RTTI Class Catalog - stbc.exe

Complete catalog of class type information extracted from the Star Trek: Bridge Commander
executable (`stbc.exe`, 5.9MB, 32-bit PE, base 0x00400000).

## Key Finding: No MSVC RTTI for Game/Engine Classes

stbc.exe was compiled with MSVC RTTI **disabled** (`/GR-`) for all game and engine code.
Only 22 standard MSVC TypeDescriptor structures exist in the binary, and all belong to the
C++ Standard Library (CRT) or `type_info` itself. The one exception is `TGStreamException`.

Instead, the game uses **two custom type information systems**:

1. **NetImmerse NiRTTI** -- A custom factory/registration system where class name strings are
   registered into a hash table (at `DAT_009a2b98`) along with factory functions. Each class
   has a static registration function (e.g., `FUN_007e3670` for NiNode) that runs once.

2. **SWIG 1.x Python Binding Tables** -- Method tables containing `ClassName_MethodName` string
   pairs that register C++ methods as Python callables. These account for the majority of
   class name strings in the binary (thousands of entries).

---

## MSVC RTTI TypeDescriptors (22 entries)

All located in `.data` segment (0x00979A18-0x00979E98). Pattern: `.?AVClassName@@`

| Address | Mangled Name | Demangled |
|---------|-------------|-----------|
| 0x00979A18 | `.?AVios_base@std@@` | std::ios_base |
| 0x00979A38 | `.?AV?$basic_ios@DU?$char_traits@D@std@@@std@@` | std::basic_ios<char> |
| 0x00979A70 | `.?AV?$basic_istream@DU?$char_traits@D@std@@@std@@` | std::basic_istream<char> |
| 0x00979AB0 | `.?AV?$basic_ostream@DU?$char_traits@D@std@@@std@@` | std::basic_ostream<char> |
| 0x00979AF0 | `.?AV?$basic_streambuf@DU?$char_traits@D@std@@@std@@` | std::basic_streambuf<char> |
| 0x00979B30 | `.?AV?$basic_filebuf@DU?$char_traits@D@std@@@std@@` | std::basic_filebuf<char> |
| 0x00979B70 | `.?AV?$basic_ios@GU?$char_traits@G@std@@@std@@` | std::basic_ios<wchar_t> |
| 0x00979BA8 | `.?AV?$basic_istream@GU?$char_traits@G@std@@@std@@` | std::basic_istream<wchar_t> |
| 0x00979BE8 | `.?AV?$basic_ostream@GU?$char_traits@G@std@@@std@@` | std::basic_ostream<wchar_t> |
| 0x00979C28 | `.?AV?$basic_filebuf@GU?$char_traits@G@std@@@std@@` | std::basic_filebuf<wchar_t> |
| 0x00979C68 | `.?AV?$basic_streambuf@GU?$char_traits@G@std@@@std@@` | std::basic_streambuf<wchar_t> |
| 0x00979CA8 | `.?AVexception@@` | exception |
| 0x00979CC0 | `.?AVlogic_error@std@@` | std::logic_error |
| 0x00979CE0 | `.?AVlength_error@std@@` | std::length_error |
| 0x00979D00 | `.?AVout_of_range@std@@` | std::out_of_range |
| 0x00979D28 | `.?AVruntime_error@std@@` | std::runtime_error |
| 0x00979D48 | `.?AVfailure@ios_base@std@@` | std::ios_base::failure |
| 0x00979D70 | `.?AVfacet@locale@std@@` | std::locale::facet |
| 0x00979D90 | `.?AV_Locimp@locale@std@@` | std::locale::_Locimp |
| 0x00979DB8 | `.?AVbad_alloc@std@@` | std::bad_alloc |
| 0x00979E98 | `.?AVtype_info@@` | type_info |

### MSVC Throw Type (`.PAV` pointer-to-class)
| Address | Name |
|---------|------|
| 0x0095AD10 | `.PAVTGStreamException@@` |

This is the only game-specific exception class with MSVC RTTI, used with C++ throw/catch.

---

## NetImmerse 3.1 Classes (129 unique)

These are the core engine classes from the NetImmerse 3.1 SDK. Class name strings are located
primarily in `.data` at 0x00975E98-0x009799F8. Each class registers itself into the NiRTTI
factory hash table via a static initialization function.

Registration pattern (from `FUN_007e3670` -- NiNode registration):
```
push FUN_007e5450          ; factory function
push offset s_NiNode       ; "NiNode" string at 0x00978500
call hash_insert           ; register in DAT_009a2b98
```

For the complete factory registration mapping (all 117 entries with registration function,
factory function, and guard flag addresses), see
[nirtti-factory-catalog.md](nirtti-factory-catalog.md).

### Scene Graph / Node Hierarchy
| Address | Class | Description |
|---------|-------|-------------|
| 0x009780D8 | NiObject | Root of all NiRTTI objects |
| 0x00978228 | NiObjectNET | Named object with time controllers |
| 0x0095B050 | NiAVObject | Audio-Visual object (transform, bounds, properties) |
| 0x00978500 | NiNode | Scene graph interior node (children list) |
| 0x009788A8 | NiBillboardNode | Auto-facing node |
| 0x00978908 | NiBone | Skeletal animation bone |
| 0x00978910 | NiBSPNode | Binary space partition node |
| 0x0097893C | NiCollisionSwitch | Enables/disables collision per-node |
| 0x00978A24 | NiFltAnimationNode | Flight animation node |
| 0x00978AE8 | NiLODNode | Level-of-detail switcher |
| 0x00978E88 | NiSortAdjustNode | Sort order override |
| 0x009789E4 | NiSwitchNode | Child visibility switcher |

### Geometry
| Address | Class | Description |
|---------|-------|-------------|
| 0x00978770 | NiGeometry | Base geometry class |
| 0x0097873C | NiGeometryData | Vertex/normal/UV data |
| 0x0097877C | NiTriBasedGeomData | Triangle-based geometry data |
| 0x009787A0 | NiTriBasedGeom | Triangle-based geometry |
| 0x009787BC | NiTriShapeData | Triangle list data |
| 0x009787EC | NiTriShape | Triangle list mesh |
| 0x0097920C | NiTriShapeDynamicData | Dynamic (mutable) triangle data |
| 0x009789B8 | NiEnvMappedTriShapeData | Environment-mapped mesh data |
| 0x009789D0 | NiEnvMappedTriShape | Environment-mapped mesh |
| 0x009791F0 | NiTrianglesData | Alternative triangle data |
| 0x00979200 | NiTriangles | Alternative triangle mesh |
| 0x00979268 | NiTriStripData | Triangle strip data |
| 0x00979278 | NiTriStrip | Triangle strip mesh |
| 0x00979284 | NiTriStripsData | Multiple triangle strips data |
| 0x009792C4 | NiTriStrips | Multiple triangle strips mesh |
| 0x00978AC8 | NiLinesData | Line geometry data |
| 0x00978AE0 | NiLines | Line geometry |
| 0x00978520 | NiScreenPolygon | 2D screen-space polygon |

### Bezier Geometry (NIF Bezier Patch Support)
| Address | Class |
|---------|-------|
| 0x009798A8 | NiBezierMesh |
| 0x00979944 | NiBezierPatch |
| 0x009799BC | NiBezierRectangle |
| 0x009799D0 | NiBezierRectangle2 |
| 0x009799E4 | NiBezierRectangle3 |
| 0x0097996C | NiBezierTriangle |
| 0x00979980 | NiBezierTriangle2 |
| 0x00979994 | NiBezierTriangle3 |
| 0x009799A8 | NiBezierTriangle4 |
| 0x009799F8 | NiBezierCylinder |
| 0x00979954 | NiBezierSkinController |

### Properties (Render State)
| Address | Class | Description |
|---------|-------|-------------|
| 0x0097823C | NiProperty | Base property |
| 0x00978620 | NiAlphaProperty | Alpha blending |
| 0x00978960 | NiCorrectionProperty | Color correction |
| 0x00978998 | NiDitherProperty | Dithering |
| 0x00978A50 | NiFogProperty | Fog |
| 0x00978B40 | NiMaterialProperty | Material (diffuse, specular, etc.) |
| 0x00978D2C | NiMultiTextureProperty | Multi-texturing |
| 0x00978E58 | NiShadeProperty | Shading model |
| 0x00978EA4 | NiSpecularProperty | Specular highlights |
| 0x00978EEC | NiStencilProperty | Stencil buffer |
| 0x00978B74 | NiTextureModeProperty | Texture filtering/wrapping |
| 0x0097919C | NiTextureProperty | Texture assignment |
| 0x009791BC | NiTransparentProperty | Transparency |
| 0x009792D0 | NiVertexColorProperty | Vertex coloring |
| 0x00979380 | NiWireframeProperty | Wireframe mode |
| 0x009793A4 | NiZBufferProperty | Z-buffer |

### Lights
| Address | Class | Description |
|---------|-------|-------------|
| 0x009787F8 | NiLight | Base light |
| 0x009784D8 | NiDynamicEffect | Dynamic lighting/effects |
| 0x00978824 | NiAmbientLight | Ambient light |
| 0x00978984 | NiDirectionalLight | Directional light |
| 0x00978E24 | NiPointLight | Point light |
| 0x00978EC0 | NiSpotLight | Spot light |
| 0x00979084 | NiTextureEffect | Texture projection effect |

### Controllers / Animation
| Address | Class | Description |
|---------|-------|-------------|
| 0x00978118 | NiTimeController | Base animation controller |
| 0x00975FBC | NiAlphaController | Alpha animation |
| 0x00975F7C | NiFlipController | Flipbook animation |
| 0x00975F90 | NiFloatController | Float value animation |
| 0x00975F64 | NiKeyframeController | Keyframe animation |
| 0x009760CC | NiKeyframeManager | Multi-sequence keyframe manager |
| 0x009761DC | NiLightColorController | Light color animation |
| 0x009761F4 | NiLookAtController | Look-at constraint |
| 0x0097626C | NiMaterialColorController | Material color animation |
| 0x00976208 | NiMorphController | Morph target animation |
| 0x00976250 | NiMorpherController | Alternative morph controller |
| 0x009762B0 | NiPathController | Path following |
| 0x009762C4 | NiParticleSystemController | Particle system driver |
| 0x009762E0 | NiRollController | Roll animation |
| 0x00978E74 | NiSkinController | Skeletal mesh skinning |
| 0x0097924C | NiTriShapeSkinController | Per-shape skin controller |
| 0x00976328 | NiVisController | Visibility animation |

### Animation Data
| Address | Class | Description |
|---------|-------|-------------|
| 0x00975F20 | NiKeyframeData | Keyframe animation data |
| 0x00975FA4 | NiFloatData | Float animation data |
| 0x00976070 | NiColorData | Color animation data |
| 0x0097621C | NiMorphData | Morph target data |
| 0x009761D0 | NiPosData | Position animation data |
| 0x0097630C | NiVisData | Visibility animation data |
| 0x00976058 | NiAnimBlender | Animation blending |

### Extra Data / Metadata
| Address | Class | Description |
|---------|-------|-------------|
| 0x00978100 | NiExtraData | Base extra data |
| 0x008DD2A8 | NiBinaryVoxelData | Binary voxel data |
| 0x008DD2BC | NiBinaryVoxelExtraData | Voxel extra data |
| 0x009797A4 | NiCloneExtraData | Clone tracking data |
| 0x00979064 | NiStringExtraData | String metadata |
| 0x00976044 | NiTextKeyExtraData | Text key markers (animation events) |
| 0x00979368 | NiVertWeightsExtraData | Vertex weight data |
| 0x009762F4 | NiSequenceStreamHelper | Sequence stream helper |

### Physics / Collision
| Address | Class | Description |
|---------|-------|-------------|
| 0x0097607C | NiForce | Base force |
| 0x00976084 | NiGravity | Gravity force |
| 0x00976090 | NiParticleBomb | Particle explosion force |
| 0x009760A0 | NiSphericalCollider | Sphere collision |
| 0x009760B4 | NiPlanarCollider | Plane collision |

### Rendering / Images
| Address | Class | Description |
|---------|-------|-------------|
| 0x009784F4 | NiRender | Base renderer |
| 0x00976724 | NiD3DRender | Direct3D renderer |
| 0x009783DC | NiImage | Image/texture data |
| 0x00978330 | NiRawImageData | Raw pixel data |
| 0x00976EB0 | NiDDImage | DirectDraw image |
| 0x00976EBC | NiDDBufferImage | DirectDraw buffer image |
| 0x0097856C | NiCamera | Camera |
| 0x009785F4 | NiClusterAccumulator | Cluster-based accumulator |
| 0x009780F0 | NiAccumulator | Base rendering accumulator |
| 0x0097860C | NiAlphaAccumulator | Alpha sorting accumulator |

### Audio
| Address | Class | Description |
|---------|-------|-------------|
| 0x00975EA4 | NiSoundSystem | Sound system |
| 0x00975EB4 | NiSource | Audio source |
| 0x00975E98 | NiListener | Audio listener |
| 0x00975EC0 | NiProvider_Info | Audio provider info |

### Math / Data Types
| Address | Class | Description |
|---------|-------|-------------|
| 0x008E3568 | NiPoint2 | 2D point/vector |
| 0x00914967 | NiPoint3 | 3D point/vector |
| 0x008E2DC8 | NiColorA | RGBA color |
| 0x00913B3F | NiColor | RGB color |
| 0x00914513 | NiFrustum | View frustum |

### Template Instantiations
| Address | Class |
|---------|-------|
| 0x00914B83 | NiTList\<ShipSubsystem\> |
| 0x009145B7 | NiTListIterator |

### Smart Pointer Types
| Address | Class |
|---------|-------|
| 0x0091342B | NiSourcePtr |
| 0x00913BD3 | NiCameraPtr |
| 0x0092B94F | NiSourceObj |

### Constants
| Address | Name |
|---------|------|
| 0x00956018 | NiPoint2_UNIT_Y |
| 0x00956028 | NiPoint2_UNIT_X |
| 0x00956038 | NiPoint2_ZERO |
| 0x00956048 | NiColorA_BLACK |
| 0x00956058 | NiColorA_WHITE |
| 0x00956068 | NiColor_BLACK |
| 0x00956078 | NiColor_WHITE |

---

## Totally Games Framework Classes (124 unique)

The TG framework is the game engine layer built on top of NetImmerse. Class name strings are
distributed across `.rdata` (0x008Dxxxx-0x008Exxxx) and `.data` (0x0091xxxx-0x0095xxxx).

### Core Framework
| Address | Class | SWIG Methods | Description |
|---------|-------|-------------|-------------|
| 0x009142B3 | TGObject | 9 | Base game object |
| 0x0091427F | TGEvent | 21 | Event system base |
| 0x009143A3 | TGEventHandlerObject | 7 | Event handler |
| 0x00912C43 | TGEventManager | 5 | Event dispatch |
| 0x0091428B | TGSequence | 8 | Action sequence |
| 0x008DBA14 | TGCondition | 8 | Conditional logic |
| 0x009143E3 | TGPythonInstanceWrapper | 1 | Python-to-C++ bridge |
| 0x0091435F | TGAttrObject | 7 | Attributed object |
| 0x00914473 | TGTemplatedAttrObject | 1 | Templated attributed object |
| 0x008DA004 | TGString | 7 | String class |
| 0x008D9808 | TGPoint3 | 35 | 3D vector (wraps NiPoint3) |
| 0x00913B27 | TGColorA | 21 | RGBA color (wraps NiColorA) |
| 0x009122E3 | TGMatrix3 | 38 | 3x3 matrix |
| 0x009138B3 | TGRect | 24 | Rectangle |
| 0x0091437F | TGdb | -- | Database (unclear) |

### Streaming / Serialization
| Address | Class | SWIG Methods | Description |
|---------|-------|-------------|-------------|
| 0x00912797 | TGStream | -- | Base stream |
| 0x009127B7 | TGBufferStream | 35 | Buffer-based stream |
| 0x00914E37 | TGProfilingInfo | 7 | Performance profiling |

### Actions / Scripting
| Address | Class | SWIG Methods | Description |
|---------|-------|-------------|-------------|
| 0x00913EE3 | TGAction | 20 | Base action |
| 0x009143BB | TGActionManager | 3 | Action scheduler |
| 0x00913EF3 | TGMovieAction | 10 | Movie playback action |
| 0x00913F37 | TGCreditAction | 10 | Credits sequence |
| 0x0095B83C | TGOverlayAction | -- | Overlay display action |
| 0x0095B7C0 | TGPhonemeAction | -- | Lip-sync phoneme action |
| 0x008D85CC | TGScriptAction | -- | Python script action |
| 0x00913F63 | TGSoundAction | 7 | Sound playback action |
| 0x008E0F20 | TGTimedAction | -- | Time-delayed action |
| 0x00913EE3 | TGAnimAction | 5 | Animation action |
| 0x00913EC3 | TGAnimPosition | 2 | Animation position |
| 0x00913F4B | TGConditionAction | 4 | Conditional action |

### Events (Typed)
| Address | Class | Description |
|---------|-------|-------------|
| 0x0091429B | TGIEvent | Input event base |
| 0x008D9840 | TGBoolEvent | Boolean event |
| 0x008E54D0 | TGCharEvent | Character event |
| 0x008DCE9C | TGFloatEvent | Float event |
| 0x008DAC5C | TGIntEvent | Integer event |
| 0x00914D77 | TGKeyboardEvent | Keyboard event |
| 0x00913FB3 | TGMouseEvent | 15 methods, mouse input |
| 0x00914D9F | TGGamepadEvent | Gamepad input |
| 0x008D8594 | TGObjPtrEvent | Object pointer event |
| 0x00913E9F | TGPlayerEvent | Player event |
| 0x009580E4 | TGSequenceEvent | Sequence event |
| 0x00913EB3 | TGShortEvent | Short integer event |
| 0x008D8764 | TGStringEvent | String event |
| 0x00913E8B | TGVoidPtrEvent | Void pointer event |
| 0x0095AA78 | TGGameSpyEvent | GameSpy event |
| 0x00913F9F | TGMessageEvent | Network message event |
| 0x0095BAA8 | TGMusicFadeEvent | Music fade event |

### Networking
| Address | Class | SWIG Methods | Description |
|---------|-------|-------------|-------------|
| 0x0091437F | TGWinsockNetwork | 9 | UDP network (WSN) |
| 0x00914393 | TGNetwork | 50 | Network abstraction |
| 0x00913CCB | TGNetworkListType | -- | Network list type |
| 0x0091221F | TGNetGroup | 8 | Network group |
| 0x00913D85 | TGNetPlayer | 16 | Network player |
| 0x0091319F | TGPlayerList | 11 | Player list |
| 0x00913D5F | TGGroupPlayer | 2 | Group-player association |
| 0x00913B0B | TGEncrypt | -- | Encryption (AlbyRules cipher) |

### Network Messages
| Address | Class | SWIG Methods | Description |
|---------|-------|-------------|-------------|
| 0x009137DD | TGMessage | 53 | Base network message |
| 0x0091379D | TGAckMessage | 6 | Acknowledgement message |
| 0x00913769 | TGBootPlayerMessage | 6 | Boot/kick player message |
| 0x00913751 | TGConnectMessage | 4 | Connection message |
| 0x00913735 | TGDisconnectMessage | 4 | Disconnection message |
| 0x00913785 | TGDoNothingMessage | 4 | No-op/keepalive message |
| 0x009137B1 | TGNameChangeMessage | 4 | Name change message |

### Managers (Singletons)
| Address | Class | SWIG Methods | Description |
|---------|-------|-------------|-------------|
| 0x00912C93 | TGInputManager | 41 | Input handling |
| 0x00912C6B | TGTimerManager | 3 | Timer management |
| 0x00912C43 | TGEventManager | 5 | Event dispatch |
| 0x00912AEF | TGMovieManager | 7 | Movie playback |
| 0x00912B33 | TGModelPropertyManager | 18 | Model property management |
| 0x00912CB7 | TGIconManager | 22 | Icon management |
| 0x00912B9B | TGFontManager | 8 | Font management |
| 0x00912BBF | TGPoolManager | 9 | Object pool management |
| 0x00912BEB | TGLocalizationManager | 6 | Localization |
| 0x00912C1B | TGModelManager | 17 | Model management |
| 0x00912B77 | TGUIThemeManager | 4 | UI theme management |
| 0x009143CF | TGSoundManager | 33 | Sound management |
| 0x00914C77 | TGAnimationManagerClass | 13 | Animation management |
| 0x00914C43 | TGSystemWrapperClass | 17 | System wrapper |

### UI Framework
| Address | Class | SWIG Methods | Description |
|---------|-------|-------------|-------------|
| 0x008E4A5C | TGWindow | 4 | Base window |
| 0x009145D7 | TGFrame | 17 | Frame container |
| 0x00914D0F | TGFrameWindow | 4 | Frame window |
| 0x00914D57 | TGPane | 26 | Pane container |
| 0x00914CEB | TGRootPane | 21 | Root UI pane |
| 0x00914D3F | TGButton | 5 | Button |
| 0x00914D2F | TGButtonBase | 11 | Button base |
| 0x00914CBB | TGTextButton | 19 | Text button |
| 0x00914433 | TGIcon | 12 | Icon |
| 0x00914CCB | TGConsole | 7 | Debug console |
| 0x00914CFB | TGDialogWindow | 28 | Dialog window |
| 0x0095CDB4 | TGStringDialog | -- | String input dialog |
| 0x00914D23 | TGPrompt | 3 | Prompt dialog |
| 0x0091444B | TGUIObject | 94 | Base UI object (largest SWIG binding!) |
| 0x00914DF3 | TGUITheme | 16 | UI theme |
| 0x008E3574 | TGParagraph | 34 | Text paragraph |
| 0x008E4A41 | TGParagraphSoundHandler | -- | Paragraph sound |

### Model Properties
| Address | Class | SWIG Methods | Description |
|---------|-------|-------------|-------------|
| 0x0091408B | TGModelProperty | 11 | Model property |
| 0x008E5D1C | TGModelPropertySet | 4 | Property set |
| 0x00912357 | TGModelPropertyInstance | 4 | Property instance |
| 0x009133D7 | TGModelPropertyList | 5 | Property list |

### Audio
| Address | Class | SWIG Methods | Description |
|---------|-------|-------------|-------------|
| 0x009124AF | TGSound | 63 | Sound (second-largest SWIG binding) |
| 0x0091443F | TGMusic | 9 | Music |
| 0x009148EF | TGSoundRegion | 8 | Spatial audio region |
| 0x00913003 | TGRedbookClass | 12 | CD audio (Redbook) |
| 0x0095B7F8 | TGPhonemeSequence | -- | Lip-sync sequence |

### Scene Graph Extensions
| Address | Class | Description |
|---------|-------|-------------|
| 0x00913097 | TGAnimNode | Animation scene node (14 methods) |
| 0x00913C1B | TGAnimBlender | Animation blender |
| 0x008DAED4 | TGDimmerController | Brightness controller |
| 0x008DAEE8 | TGFuzzyTriShape | Soft-edged geometry |
| 0x008E5D88 | TGFuzzyClusterGeom | Fuzzy cluster geometry |
| 0x008E5D70 | TGFuzzyClusterInnerGeom | Fuzzy cluster inner geometry |
| 0x008DAEF8 | TGOverlayController | Overlay controller |

### Miscellaneous
| Address | Class | Description |
|---------|-------|-------------|
| 0x00913347 | TGFontGroup | Font group (17 methods) |
| 0x00913367 | TGIconGroup | Icon group (21 methods) |
| 0x0091338B | TGConfigMapping | Configuration (11 methods) |
| 0x00913B5B | TGGroupList | Group list |
| 0x0091306B | TGPMWalkObjectsFunc | Property manager walk |
| 0x009145FB | TGStringToStringMap | String-to-string map |
| 0x0095ACD8 | TGLocalizationDatabase | Localization DB (5 methods) |
| 0x00913E7F | TGTimer | Timer (10 methods) |
| 0x0091340B | TGPhoneme | Phoneme data |
| 0x00913DEB | TGConditionHandler | Condition handler (3 methods) |
| 0x00930A74 | TGLocDBWrapperSerialize | Localization serializer |
| 0x00930A58 | TGLocDBWrapperUnserialize | Localization deserializer |

---

## Game-Specific Classes (referenced from .text section)

These are Bridge Commander's own classes, built on top of the TG framework and NetImmerse.
Organized by game subsystem.

### Ship / Vessel Classes (28 unique)
| Address | Class |
|---------|-------|
| 0x008D8AC0 | ShipClass |
| 0x008E52F0 | ShipSubsystem |
| 0x008E4EC0 | HullClass |
| 0x008E42C8 | Cloak |
| 0x008E4E24 | CloakingSubsystem |
| 0x008E4EEC | ImpulseEngineSubsystem |
| 0x008E5330 | WarpEngineSubsystem |
| 0x008E61A8 | InSystemWarp |
| 0x008E42D4 | Tractor |
| 0x008E56BC | TractorBeamProjector |
| 0x008E5704 | TractorBeamSystem |
| 0x008E1074 | TractorBeamGraphic |

### Ship Properties (data-driven configuration)
| Address | Class |
|---------|-------|
| 0x00959440 | ShipProperty |
| 0x00958808 | HullProperty |
| 0x00958844 | ImpulseEngineProperty |
| 0x00959910 | WarpEngineProperty |
| 0x00958580 | CloakingSubsystemProperty |
| 0x00959874 | TractorBeamProperty |

### Weapon Classes
| Address | Class |
|---------|-------|
| 0x008E57C8 | Weapon |
| 0x008E539C | EnergyWeapon |
| 0x008E53E4 | PhaserBank |
| 0x008E5410 | PhaserSystem |
| 0x008E54FC | PulseWeapon |
| 0x008E5560 | PulseWeaponSystem |
| 0x008E55D4 | Torpedo |
| 0x008E562C | TorpedoSystem |
| 0x008E5690 | TorpedoTube |
| 0x008D9D4C | WeaponSystem |

### Weapon Properties
| Address | Class |
|---------|-------|
| 0x00959960 | WeaponProperty |
| 0x0095861C | EnergyWeaponProperty |
| 0x009589D0 | PhaserProperty |
| 0x00958FAC | PulseWeaponProperty |
| 0x009596AC | TorpedoSystemProperty |
| 0x00959764 | TorpedoTubeProperty |
| 0x00959A68 | WeaponSystemProperty |

### Subsystem / Damage Classes
| Address | Class |
|---------|-------|
| 0x00959590 | SubsystemProperty |
| 0x008E5CE0 | DamageableObject |
| 0x008DA2E4 | PowerSubsystem |
| 0x008E4F3C | PoweredSubsystem |
| 0x008E4FA0 | RepairSubsystem |
| 0x008E50F8 | SensorSubsystem |
| 0x008E52A0 | ShieldClass |
| 0x00958ED0 | PowerProperty |
| 0x00958E50 | PoweredSubsystemProperty |
| 0x0095902C | RepairSubsystemProperty |
| 0x009590C0 | SensorProperty |
| 0x00959138 | ShieldProperty |

### Multiplayer / Network
| Address | Class |
|---------|-------|
| 0x008DA714 | MultiplayerGame |
| 0x008E1664 | MultiplayerWindow |
| 0x008E1720 | MultiplayerInterfaceHandlers |
| 0x0095A354 | InitNetwork |
| 0x0095A390 | NetFile |
| 0x0095A30C | Network |
| 0x0095C798 | Message |
| 0x008D9AA8 | SkipChecksum |
| 0x0095A434 | SystemChecksumFail |
| 0x008DA74C | ServerListEvent |
| 0x008DA784 | SortServerListEvent |

### Object System
| Address | Class |
|---------|-------|
| 0x008D8BEC | ObjectClass |
| 0x008D9750 | BaseObjectClass |
| 0x008D967C | CameraObjectClass |
| 0x008DA0E0 | ChatObjectClass |
| 0x008D9788 | LightObjectClass |
| 0x008E5E40 | PhysicsObjectClass |
| 0x0095826C | ZoomCameraObjectClass |
| 0x008E5884 | CollisionEvent |

### Mission / Set System
| Address | Class |
|---------|-------|
| 0x008D89F0 | Mission |
| 0x008D867C | MissionLib |
| 0x008D8B90 | SetClass |
| 0x008D9D80 | SetInstance |
| 0x008D8D40 | SetManager |
| 0x00957144 | BridgeSet |
| 0x008E136C | System |
| 0x008D87D0 | Game |
| 0x008E19A0 | GameInit |
| 0x00959BFC | GameSpy |

### Space Objects
| Address | Class |
|---------|-------|
| 0x008DA35C | Planet |
| 0x008DA31C | Nebula |
| 0x008D9D04 | MetaNebula |
| 0x008DA37C | Sun |
| 0x008D8FB0 | Asteroid |
| 0x008D8D94 | AsteroidField |
| 0x008D8E3C | AsteroidTile |
| 0x008E5884 | Backdrop |
| 0x008E59A4 | BackdropSphere |
| 0x008E5BB0 | StarSphere |
| 0x008DA3C8 | Waypoint |

### AI System
| Address | Class |
|---------|-------|
| 0x008D9EFC | ArtificialIntelligence |
| 0x008D9CE4 | BuilderAI |
| 0x008D9E48 | ConditionalAI |
| 0x008D9E84 | PlainAI |
| 0x008D9E20 | PreprocessingAI |
| 0x008DBD34 | RandomAI |
| 0x008DBDC8 | SequenceAI |
| 0x008DBC4C | PriorityListAI |

### Character / Bridge
| Address | Class |
|---------|-------|
| 0x00957308 | Captain |
| 0x00957178 | CharacterClass |
| 0x0095702C | BridgeObjectClass |
| 0x008DA5E4 | CharacterAction |
| 0x008DA594 | CharacterSpeakingQueue |

### UI Windows (Game-Specific)
| Address | Class |
|---------|-------|
| 0x008E21DC | TopWindow |
| 0x008E24F4 | MainWindow |
| 0x008E1118 | BridgeWindow |
| 0x008E12AC | CinematicWindow |
| 0x008E2530 | ConsoleWindow |
| 0x008E1CA4 | SubtitleWindow |
| 0x008E202C | TacticalControlWindow |
| 0x008E2134 | TacticalWindow |
| 0x008E2208 | OptionsWindow |
| 0x008DA118 | MapWindow |
| 0x008E14C4 | ModalDialogWindow |
| 0x008E1508 | StylizedWindow |
| 0x008DA6CC | ReticleManagerWindow |
| 0x008E2760 | ReticleWindow |
| 0x008E26A4 | PlayerReticleWindow |
| 0x008E263C | NamedReticleWindow |
| 0x008E11A0 | CDCheckWindow |
| 0x008E4774 | GraphicsMenu |

### UI Controls (Game-Specific ST* prefix)
| Address | Class |
|---------|-------|
| 0x008E282C | STButton |
| 0x008E28C0 | STCheckbox |
| 0x008E2860 | STCharacterMenu |
| 0x008E37F8 | STComponentMenu |
| 0x008E387C | STComponentMenuItem |
| 0x008E2A3C | STFileDialog |
| 0x008E2E30 | STFileMenu |
| 0x008E2ED4 | STLoadDialog |
| 0x008E3048 | STMenu |
| 0x008E3198 | STMissionLog |
| 0x008E32B8 | STRepairButton |
| 0x008E3358 | STRoundedButton |
| 0x008E33C4 | STSaveDialog |
| 0x008D9D24 | STStylizedWindow |
| 0x008E365C | STSubPane |
| 0x008E373C | STSubsystemMenu |
| 0x008E39E8 | STTargetMenu |
| 0x008E3A74 | STTargetMenuSubPane |
| 0x008E3AB8 | STTiledIcon |
| 0x008E3A18 | STTopLevelMenu |
| 0x008E3AE4 | STToggle |
| 0x008E2EA8 | STFillGauge |
| 0x008DA144 | STNumericBar |
| 0x008E3BAC | STWarpButton |
| 0x008E2BFC | UIHelpers |

### Display Panels
| Address | Class |
|---------|-------|
| 0x008E404C | ShipDisplay |
| 0x008E43FC | WeaponsDisplay |
| 0x008E3CF0 | ShipIcons |
| 0x008E3FA4 | ShieldsDisplay |
| 0x008E3CFC | DamageDisplay |
| 0x008E3DE8 | RadarDisplay |
| 0x008E3ED4 | RadarScope |
| 0x008E3E4C | RadarBlip |
| 0x008E3C90 | DamageIcon |
| 0x008E4640 | EngPowerDisplay |
| 0x008E46F8 | EngRepairPane |
| 0x008E4520 | EngPowerCtrl |
| 0x008E41A0 | TacWeaponsCtrl |
| 0x008E4190 | LeftSeparator |

### Camera Modes
| Address | Class |
|---------|-------|
| 0x008D9010 | CameraMode |
| 0x008D9178 | ChaseCameraMode |
| 0x008D90BC | IdealControlledCameraMode |
| 0x008D94B4 | LockedPositionMode |
| 0x008D92C0 | MapCameraMode |
| 0x008D924C | TargetCameraMode |
| 0x008D95B8 | TorpCameraMode |
| 0x008D9288 | ZoomTargetMode |
| 0x008D9634 | PlaceByDirectionMode |
| 0x008D9444 | PlacementWatchMode |
| 0x008D93E0 | DropAndWatchMode |
| 0x008D96F8 | SpaceCamera |

### Effects / Particles
| Address | Class |
|---------|-------|
| 0x008E0D30 | EffectController |
| 0x008E0D18 | EffectControllerData |
| 0x008E0CDC | AnimTSParticleController |
| 0x008E0CF8 | DebrisParticleController |
| 0x008E0D58 | ExplodeParticleController |
| 0x008E0D74 | PointParticleController |
| 0x008E0D8C | SparkParticleController |
| 0x008E0DA4 | TexturedSparksController |
| 0x008E0F04 | AnimatedTriShapeParticles |
| 0x008E10FC | TriShapeOrientedParticles |
| 0x008E10C8 | TriShapeParticles |
| 0x008E10B0 | TriShapeParticlesData |
| 0x008E10DC | TriShapeOrientedParticlesData |
| 0x008E1050 | FlareController |
| 0x008E1040 | SpecularPass |
| 0x008E0FD4 | GlowPass |
| 0x008E0FE0 | PhaserGraphic |
| 0x008E0F58 | DisruptorGraphic |
| 0x008E1064 | TorpedoGraphic |

### Properties (Game Object Configuration)
| Address | Class |
|---------|-------|
| 0x009582AC | BlinkingLightProperty |
| 0x009583D0 | EffectEmitterProperty |
| 0x0095842C | EngineGlowProperty |
| 0x00958790 | EngineProperty |
| 0x0095847C | ExplodeEmitterProperty |
| 0x009584D8 | SmokeEmitterProperty |
| 0x0095852C | SparkEmitterProperty |
| 0x00958920 | ObjectEmitterProperty |
| 0x00958D24 | PositionOrientationProperty |
| 0x00958604 | DisplayModelExtraData |
| 0x009580A0 | SetLocation |
| 0x00958148 | RotateBonesController |
| 0x00956F90 | BoneStateController |
| 0x009581F0 | ViewScreenObject |

### Warp System
| Address | Class |
|---------|-------|
| 0x008DA2B8 | WarpEvent |
| 0x008DA538 | WarpFlash |
| 0x008DA564 | WarpSequence |
| 0x008E0E98 | WarpSet |
| 0x008E0DDC | WarpFlashTextures |

### Proximity / Placement
| Address | Class |
|---------|-------|
| 0x008DA1C4 | ProximityCheck |
| 0x008DA1FC | ProximityEvent |
| 0x008DA390 | PlacementObject |
| 0x008DA3EC | LightPlacement |
| 0x008DA4B8 | AsteroidFieldPlacement |

### Editor
| Address | Class |
|---------|-------|
| 0x008DA424 | Editor |
| 0x008DA444 | PlacementEditor |
| 0x008DA47C | BackgroundEditor |
| 0x008DC2C4 | EditorCamera |
| 0x008DC2D4 | GridClass |

### Scoring / Game Events
| Address | Class |
|---------|-------|
| 0x008E62D0 | WeaponHitEvent |
| 0x008DA270 | ObjectExplodingEvent |
| 0x008DA234 | StartFiringEvent |
| 0x008DA61C | WaypointEvent |
| 0x008DA5E4 | CharacterAction |
| 0x008DA0A8 | VarManagerClass |
| 0x008DA67C | ConditionEventCreator |

---

## SWIG Python Binding Statistics

The SWIG 1.x binding layer exposes C++ classes to Python 1.5.2 via the `App` and `Appc`
modules. Each class has wrapper functions named `ClassName_MethodName`.

### Largest SWIG Interfaces (by method count)
| Class | Methods | Role |
|-------|---------|------|
| TGUIObject | 94 | UI object (largest binding) |
| TGSound | 63 | Sound system |
| TGMessage | 53 | Network messages |
| TGNetwork | 50 | Network abstraction |
| TGInputManager | 41 | Input handling |
| TGMatrix3 | 38 | Matrix math |
| TGBufferStream | 35 | Stream I/O |
| TGPoint3 | 35 | 3D vector math |
| TGParagraph | 34 | Text rendering |
| TGSoundManager | 33 | Sound management |
| TGDialogWindow | 28 | Dialogs |
| TGPane | 26 | UI panes |
| TGINPUT | 25 | Input constants |
| TGRect | 24 | Rectangle math |
| TGIconManager | 22 | Icon management |
| TGIconGroup | 21 | Icon groups |
| TGColorA | 21 | RGBA color |
| TGEvent | 21 | Events |
| TGRootPane | 21 | Root UI |
| TGTextButton | 19 | Text buttons |
| TGModelPropertyManager | 18 | Model properties |
| TGNETWORK | 18 | Network constants |
| TGFontGroup | 17 | Font groups |
| TGFrame | 17 | Frames |
| TGModelManager | 17 | Model management |
| TGSystemWrapperClass | 17 | System wrapper |
| TGUITheme | 16 | UI themes |
| TGNetPlayer | 16 | Network players |
| TGMouseEvent | 15 | Mouse input |
| TGAnimNode | 14 | Animation |
| TGAnimationManagerClass | 13 | Animation manager |
| TGIcon | 12 | Icons |
| TGRedbookClass | 12 | CD audio |

### Total: 114 classes with SWIG bindings, ~1,340 wrapper methods

---

## Summary Statistics

| Category | Count |
|----------|-------|
| MSVC RTTI TypeDescriptors | 22 (21 CRT/STL + 1 game) |
| NetImmerse Ni* classes | 129 |
| TG Framework classes | 124 |
| TG SWIG-bound classes | 114 |
| TG SWIG wrapper methods | ~1,340 |
| Game-specific classes (non-Ni/TG) | ~420 |
| **Total unique C++ classes identified** | **~670** |
| Total class-like name strings in binary | ~1,179 (referenced from code) |
