# NIF Loading & Subsystem Creation Analysis (2026-02-13)

## Ship Creation Pipeline (Network Path)

When a ship arrives via ObjCreateTeam (opcode 0x03):

1. **C++ deserializes ship** from network stream (FUN_005b0e80 = InitObject)
2. **InitObject calls Python** `Multiplayer.SpeciesToShip.InitObject(self, iType)`
3. **Python InitObject** does:
   a. `GetShipFromSpecies(iType)` -> imports `ships.Sovereign` etc. -> calls `LoadModel()`
   b. `self.SetupModel(kStats['Name'])` -> C++ associates LODModel with ship object
   c. `pPropertySet = self.GetPropertySet()` -> gets ship's property container
   d. `mod = __import__('ships.Hardpoints.sovereign')` -> loads hardpoint definitions
   e. `mod.LoadPropertySet(pPropertySet)` -> **populates property set from Python**
   f. `self.SetupProperties()` -> **C++ FUN_005b3fb0 creates runtime subsystem objects**
   g. `self.UpdateNodeOnly()` -> updates scene graph transforms
4. **SetupProperties** (FUN_005b3fb0) iterates property types, creates subsystem objects:
   - 0x812f: Phaser/TorpedoTube/PulseWeapon (weapon subsystems)
   - 0x8132: PhaserEmitter (individual emitters)
   - 0x8133: ShieldGenerator
   - 0x8134: TorpedoTube/TractorBeam
   - Each subsystem is added to linked list at ship+0x284 via FUN_005b3e50
5. **AddToSet** (FUN_006c9520) links property objects to NiNode "Scene Root"

## Critical Bottleneck

`self.SetupModel(kStats['Name'])` calls C++ which looks up the LODModel by name.
LODModel was previously created by `ships.Sovereign.LoadModel()` which does:
- `pLODModel = App.g_kLODModelManager.Create("Sovereign")`
- `pLODModel.AddLOD("data/Models/Ships/Sovereign/Sovereign.nif", ...)`
- `pLODModel.Load()` -- **THIS TRIGGERS NIF LOADING VIA NiStream**

## NIF Loading (NiStream::Load at FUN_008176b0)

NiStream::Load is pure file I/O + object deserialization:
1. Reads block type names (e.g. "NiTriShape", "NiNode", "NiSourceTexture")
2. Looks up class factory in global table at DAT_009a2b98
3. Instantiates objects via factory callbacks
4. Objects read their data from the stream (pure data, no renderer)
5. "End Of File" sentinel terminates load
6. Post-load fixup: link references, process "Top Level Object"

**Does NOT require renderer for geometry/node creation.**
NiSourceTexture stores NULL texture handle if no renderer present (does NOT crash).
DX7 vertex/index buffers created lazily on first render call, NOT during NiStream::Load.

## Why Headless Fails: The AddToSet -> "Scene Root" Connection

FUN_006c9520 (AddToSet) searches the NIF model's scene graph for a node named "Scene Root".
At line 4932 of 12_data_serialization.c, it string-compares against `s_Scene_Root_008daec8`.

If NIF load succeeds -> "Scene Root" NiNode exists -> properties link -> subsystems create.
If NIF load fails -> no "Scene Root" -> AddToSet returns 0 -> no subsystems -> ship+0x284 NULL.

## Key Question: Does NIF Loading Actually Fail?

The documentation states NIF loading is decoupled from renderer. But the headless server
has ship+0x284 = NULL, which means either:
1. NIF loading never runs (LoadModel() is never called in network path)
2. NIF loading runs but crashes/fails silently
3. SetupModel() fails to associate the loaded NIF with the ship
4. Something between NIF load and SetupProperties breaks

The stock-dedi subsystem trace shows InitObject -> AddToSet (4-6 calls) -> SetupProperties (45 calls).
If AddToSet is never called or always returns 0, the entire subsystem chain is dead.

## Hardpoint Files Are Pure Python Data

Hardpoint files (e.g. sovereign.py) define subsystem properties entirely in Python:
- `App.PhaserProperty_Create("Ventral Phaser 3")` -> creates property object
- `.SetMaxCondition(1000.0)`, `.SetPosition(...)`, etc. -> configures it
- `App.g_kModelPropertyManager.RegisterLocalTemplate(prop)` -> registers it
- `mod.LoadPropertySet(pPropertySet)` -> links all registered templates to ship's property set

**Hardpoints do NOT depend on NIF files.** They are pure data definitions.
The NIF dependency is in SetupModel() -> LODModel -> NiStream::Load for the "Scene Root" node.

## Subsystem Creation Does NOT Require Renderer

SetupProperties (FUN_005b3fb0) is purely C++ object construction:
- Reads property types from the property set
- Allocates subsystem objects (heap allocation)
- Initializes HP, position, arc angles from property values
- Links to ship's named slots and linked list

No renderer calls. No texture operations. No vertex buffer creation.
The ONLY renderer-adjacent dependency is NIF loading for the "Scene Root" node name lookup.
