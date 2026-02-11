# NIF Loading Pipeline Analysis (2026-02-10)

## Ship Creation Call Chain (Network -> Subsystems)

```
Network opcode 0x02/0x03 (ObjectCreate)
  -> FUN_0069f620 (MP game object processor)
    -> FUN_005a1f50 (deserialize game object from stream)
      -> FUN_006f13e0 (object factory, creates ShipClass)
      -> vtable[0x118](stream) -> vtable[0x11c](stream) -> ...
        -> FUN_005b0e80 (InitObject C++ entry)
          -> FUN_005a2030 (reads net type from stream)
          -> FUN_006f8ab0("Multiplayer_SpeciesToShip", "InitObject", "ii", args, "i")
            [Python: SpeciesToShip.InitObject(self, iType)]
              -> GetShipFromSpecies(iType)
                -> ships/<Name>.LoadModel()
                  -> g_kLODModelManager.Create(<name>)
                  -> pLODModel.AddLOD(<nif_path>, ...)
              -> self.SetupModel(<name>)  [C++: PhysicsObjectClass_SetupModel]
                -> FUN_006c9100 (TGModelContainer::Load)
                  -> FUN_006c8fa0 (set NIF path)
                  -> FUN_006c9020 (set search paths)
                  -> FUN_00817a40 (NiStream::Load) -- FILE I/O, reads .nif
                    -> FUN_008176b0 (NiStream internal parse)
                  -> FUN_006c9520 (AddToSet / ExtractModel)
                    -> Finds NiNode "Scene Root" in NIF scene graph
                    -> Creates TGModelPropertyInstance (0x150 bytes)
                    -> FUN_007dc5c0/FUN_007dc690 (NiNode::Update/UpdateBound)
              -> mod.LoadPropertySet(pPropertySet)  [Python]
                -> pObj.AddToSet("Scene Root", prop) per subsystem
              -> self.SetupProperties()  [C++: FUN_005b3fb0]
                -> Creates concrete subsystem objects from properties
                -> Populates linked list at ship+0x284
              -> self.UpdateNodeOnly()  [C++]
    -> FUN_0047dab0 (create network wrapper)
    -> vtable[0x134](wrapper, 1, 1)  (register in network system)
```

## Key Functions

| Address | Name | Role |
|---------|------|------|
| 0x005a1f50 | DeserializeGameObject | Creates object from network stream |
| 0x005b0e80 | InitObject (C++) | Calls Python InitObject via dispatcher |
| 0x006f8ab0 | PyCallModuleFunc | Dispatches Python module.function call |
| 0x006f8490 | PyResolveModuleFunc | Imports module, looks up function attr |
| 0x006c9100 | TGModelContainer::Load | Loads NIF and creates scene graph |
| 0x00817a40 | NiStream::Load (file) | Opens file, calls FUN_008176b0 |
| 0x008176b0 | NiStream::LoadObjects | Parses NIF binary, creates NiNodes |
| 0x006c9520 | AddToSet/ExtractModel | Finds "Scene Root" NiNode in loaded NIF |
| 0x005b3fb0 | SetupProperties | Creates subsystem objects from properties |
| 0x007dc5c0 | NiNode::Update | Updates scene graph transforms |
| 0x007dc690 | NiNode::UpdateBound | Updates bounding volumes |

## NIF Loading is Filesystem I/O
- NiStream::Load (0x00817a40) opens file via FUN_0086e550 (NiBinaryStream from fopen)
- FUN_008176b0 reads NIF binary, uses class loader registry
- Class loaders create NiNode, NiTriShape, NiTexturingProperty etc.
- In NI 3.1, geometry stored in system RAM, not GPU, until renderer bind
- **NIF loading SHOULD work headlessly** if files exist

## Headless Server Failure
- C++ DIAG confirms InitObject fires
- Python monkey-patch produces NO log output -> Python InitObject may not execute
- SetupProperties NEVER fires -> nothing after InitObject works
- Possible causes:
  1. Missing NIF files in server game directory
  2. Python exception in LoadModel/SetupModel silently kills chain
  3. Module resolution: C++ uses "Multiplayer_SpeciesToShip" (underscore notation)
  4. FUN_006f8ab0 returns -1 on any Python error -> InitObject returns 0

## Python InitObject Dependencies
- `GetShipFromSpecies()` calls `__import__("ships." + name)` then `ShipScript.LoadModel()`
- `LoadModel()` needs App.g_kLODModelManager (shadow class wrapper)
- `SetupModel()` is SWIG-wrapped C++ PhysicsObjectClass method
- `GetPropertySet()` is SWIG-wrapped C++ method
- Hardpoint scripts use `App.g_kModelPropertyManager.RegisterLocalTemplate()`
- `LoadPropertySet()` calls `AddToSet("Scene Root", prop)` - needs NIF loaded
