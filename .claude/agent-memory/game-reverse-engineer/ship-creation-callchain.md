# Ship Creation Call Chain Analysis (HOST Side)
## Date: 2026-02-13

## Full Call Chain: Network -> Ship Object -> Python InitObject

```
Network opcode 0x03 (ObjCreateTeam)
  -> FUN_0069f2a0 (MultiplayerGame message dispatcher, jump table at 0x0069F534)
    -> FUN_0069f620 (ObjCreateTeam handler, __thiscall on MultiplayerGame)
      -> FUN_006b8530 (extract payload + length from TGMessage)
      -> Temporarily swaps active player context to source player
      -> FUN_005a1f50 (DeserializeGameObject)
        -> FUN_006cefe0 + FUN_006cf180 (create FlatBufferStream from payload)
        -> FUN_006cf670 (read two ints: object type ID, network ID)
        -> FUN_00430730(NULL, typeID) (lookup type in global factory registry)
          If returns non-NULL: object already exists, return NULL
        -> FUN_006f13e0(typeID) (factory: hash lookup -> create new C++ object)
        -> vtable[0x118](stream) -> ReadStream cascade
          -> TGPersistable::ReadStream -> ... -> Ship::ReadStream (FUN_0057a280)
            -> FUN_005a2030 (reads net-type byte -> this+0xEC)
            -> FUN_005b0e80 (ShipExt::ReadStreamInit)
              -> vtable[0x20]() -> GetNetType (returns PyObject* for this+0xEC)
              -> FUN_006f8ab0("Multiplayer.SpeciesToShip", "InitObject", "ii", {self,iType}, "i")
                -> FUN_0074bbf0(1)  -- nesting counter++
                -> FUN_006f8490(module, func)  -- resolve callable
                  -> FUN_006f7a00  -- dots to underscores
                  -> FUN_006f7d90  -- __import__ or cached lookup
                  -> FUN_0074c140  -- getattr(module, funcname)
                -> FUN_006f8c00  -- call Python function
                  -> FUN_00776cf0  -- PyObject_CallObject
                -> FUN_0074bbf0(0)  -- nesting counter--
        -> vtable[0x11c](stream) -> second ReadStream pass
      -> Restores player context
      -> FORWARDS message to all other connected players (FUN_006b4c10)
      -> Creates network wrapper (FUN_0047dab0)
      -> Registers in network system (vtable[0x134])
```

## Key Function Signatures

| Address | Name | Signature | Role |
|---------|------|-----------|------|
| 0x0069f620 | ObjCreateTeam handler | `void __thiscall(MultiplayerGame*, TGMessage*, char hasTeam)` | Dispatches incoming ship creation |
| 0x005a1f50 | DeserializeGameObject | `int* __cdecl(void* streamData, int streamLen)` | Creates C++ object from network bytes |
| 0x005b0e80 | ShipExt::ReadStreamInit | `int __thiscall(Ship*, Stream*)` | vtable entry, calls Python InitObject |
| 0x006f8ab0 | TG_CallPythonFunction | `int __cdecl(char* module, char* func, char* argFmt, int args, char* retFmt)` | -1=error, 0+=success |
| 0x006f7d90 | TG_ImportModule | `PyObject* __cdecl(char* name, char useCached)` | Imports or returns cached module |
| 0x006f8490 | TG_ResolveModuleFunc | `PyObject* __cdecl(char* module, char* func)` | Import + getattr |
| 0x006f8c00 | TG_InvokeCallable | `int __cdecl(callable, argFmt, args, kwargs, isRuncall, releaseFunc)` | Actually calls the Python function |
| 0x0074bbf0 | PyNesting | `void __cdecl(int direction)` | 1=increment, 0=decrement nesting counter |
| 0x006f9b80 | TG_CheckPyError | `int(void)` | Returns 1 if PyErr_Occurred, 0 if clean |

## CRITICAL: FUN_006f8ab0 Does NOT Use PyRun_SimpleString
- Uses FUN_006f7d90 (__import__) + FUN_0074c140 (getattr) + FUN_00776cf0 (PyObject_CallObject)
- Nesting counter (FUN_0074bbf0) supports nested calls (just inc/dec)
- SHOULD work in TIMERPROC context -- different code path from PyRun_SimpleString

## FUN_006f7d90 Import Logic
1. Converts dots to underscores via FUN_006f7a00
2. Checks sys.modules (FUN_0075b250 + FUN_00752cd0)
3. Special case: "__main__" -> PyImport_AddModule
4. If found in sys.modules:
   - Checks for "__dummy__" attribute (placeholder module)
   - If no __dummy__ and param_2=='\0': return cached
   - If __dummy__: fall through to real import
5. If not cached: FUN_0075bbf0 = __import__(name) full import

## FUN_0069f620 Host Behavior
- On HOST (DAT_0097fa88==0, IsClient==0):
  - Deserializes ship object from network stream
  - Forwards ObjCreate to ALL other connected players
  - Creates network wrapper (FUN_0047dab0 with "Network" string)
  - Registers via vtable[0x134](wrapper, 1, 1)
- Player slot array at MultiplayerGame+0x7c, 16 slots, 0x18 bytes each

## Why InitObject Might Not Fire on Our Server
1. ObjCreateTeam (0x03) message never dispatched to FUN_0069f620
2. FUN_005a1f50 fails (factory can't create Ship type ID)
3. ReadStream chain fails before FUN_005b0e80
4. FUN_006f7d90 import fails (module not in sys.modules, __import__ fails)
5. Python InitObject throws exception -> FUN_006f8ab0 returns -1 -> silently handled
