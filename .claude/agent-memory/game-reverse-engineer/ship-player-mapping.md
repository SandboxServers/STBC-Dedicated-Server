# GetShipFromPlayerID & Player-Ship Mapping

## GetShipFromPlayerID = FUN_006a1aa0 (VERIFIED via Ghidra decompile)
- SWIG name: `Appc.MultiplayerGame_GetShipFromPlayerID`
- String at 0x00915160, format "Oi:" at 0x0094ee64
- Takes (int connectionID), returns ship ptr or 0
- Calling convention: `__cdecl` (NOT __thiscall - no this ptr needed)

### Decompiled Algorithm (verified)
```c
int __cdecl FUN_006a1aa0(int connectionID) {
    for (int s = 0; s < DAT_0097e9cc; s++) {  // iterate sets
        int count = 0;
        int **ships = (int**)FUN_005ab550(DAT_0097e9c8[s], &count);  // type 0x8008
        for (int i = 0; i < count; i++) {
            if (*(int*)(ships[i] + 0x2E4) == connectionID) {  // ship.NetPlayerID match
                return ships[i];  // return ship pointer
            }
        }
    }
    return 0;  // not found
}
```

### Key: Mapping is ON THE SHIP, not in MultiplayerGame
- `ship + 0x2E4` = NetPlayerID (owner's connection ID)
- Initialized to 0 in ship constructor
- Set by `ShipClass.SetNetPlayerID(connectionID)` -- SWIG-exposed
- Read by `ShipClass.GetNetPlayerID()` -- SWIG-exposed
- Read by `ShipClass.IsPlayerShip()` -- returns `ship+0x2E4 != 0` on host

## C Code to Call GetShipFromPlayerID
```c
typedef int (__cdecl *GetShipFromPlayerID_t)(int connectionID);
#define GetShipFromPlayerID ((GetShipFromPlayerID_t)0x006a1aa0)

int shipPtr = GetShipFromPlayerID(peerID);
if (shipPtr) {
    // Read ship fields:
    int niNode    = *(int*)(shipPtr + 0x18);   // NiNode*
    int dTarget   = *(int*)(shipPtr + 0x140);  // damage target
    int dmgArray  = *(int*)(shipPtr + 0x128);  // damage handler array
    int dmgArr2   = *(int*)(shipPtr + 0x130);  // related damage array
    int field_1B8 = *(int*)(shipPtr + 0x1B8);
    int field_1BC = *(int*)(shipPtr + 0x1BC);
    int field_D8  = *(int*)(shipPtr + 0xD8);
}
```

## Alternative: Direct Slot Table Lookup
If you already know the slot index (0-15):
```c
DWORD mpGame = *(DWORD*)0x0097e238;
BYTE *slot = (BYTE*)mpGame + 0x74 + slotIndex * 0x18;
BYTE active = *(slot + 0x04);
int playerID = *(int*)(slot + 0x08);
int shipObjID = *(int*)(slot + 0x0C);
```
Then use hash lookup: `FUN_0059fc60(NULL, shipObjID)` for ship by object ID.

## Normal Flow (Stock Game, CLIENT-SIDE)
1. StartMission (Mission1Menus.py line 740)
2. `pPlayer = MissionMenusShared.CreateShip(iSpecies)` -- creates ship locally
3. `pPlayer.SetNetPlayerID(pNetwork.GetLocalID())` -- stamps ship (line 784)
4. `pMultGame.SetPlayer(pPlayer)` -- registers in MultiplayerGame (line 818)
5. Ship is serialized via vtable[0x120] and sent as ObjCreateTeam to host
6. Host receives via FUN_0069f620, deserializes, sets ship+0x2E4 from packet

## ObjCreateTeam Receiver: FUN_0069f620
- `param_2` = 0 for ObjCreate (opcode 0x02), 1 for ObjCreateTeam (opcode 0x03)
- Packet layout for ObjCreateTeam: `[type:1][playerSlot:1][netPlayerID:1][ship_data...]`
- `cVar2 = byte[1]` = player slot
- `local_10 = byte[2]` = NetPlayerID (only read if param_2 != 0)
- Deserializes from byte[3] onward
- After deserialize: `ship[0xb9] = local_10` -> `ship+0x2E4 = byte[2]`
- Also: `playerSlot[+0x0C] = ship.networkID` (line 5760)

## ObjCreateTeam Sender: FUN_006a02a0 (HOST relay)
- Called by ObjectCreatedHandler on host
- Header: `[type:1][playerSlot:1][opt_netPlayerID:1]`
- Type = 2 (normal) or 3 (cloaked)
- Byte[2] = `ship+0x2E4` (NetPlayerID) -- only if type==3 (cloaked)
- Serializes ship via vtable[0x10c] (WriteStream)
- NOTE: For non-cloaked ships, header is only 2 bytes (no NetPlayerID byte)

## MultiplayerGame Player Slot Array
- Base: `game + 0x74`, stride 0x18 (24 bytes), max 16 entries
- Slot table spans: +0x74 to +0x1F4
- FUN_0069efc0 initializes all 16 slots via FUN_006a7770
- Constructor: FUN_0069e590

### Per-Slot Layout (24 bytes each)
| Offset | Size | Field | Notes |
|--------|------|-------|-------|
| +0x00 | 4 | vtable | PTR_FUN_0089565c |
| +0x04 | 1 | active | 0=empty, nonzero=occupied |
| +0x08 | 4 | playerID | Network peer/connection ID |
| +0x0C | 4 | shipObjID | Ship's network object ID (set by ObjCreateTeam) |
| +0x10 | 4 | baseObjID | `slotIndex * 0x40000 + 0x3FFFFFFF` |
| +0x14 | 1 | flag | Initialized to 1 by FUN_006a7770 |

### After Slot Table
- `MPGame + 0x1F8` = ReadyForNewPlayers (BYTE)
- `MPGame + 0x1FC` = MaxPlayers (int, capped at 16)

## Key Helper Functions
| Address | Name | Calling Conv | Signature |
|---------|------|-------------|-----------|
| FUN_006a1aa0 | GetShipFromPlayerID | __cdecl | `int(int connectionID)` |
| FUN_006a19c0 | FindPlayerSlotByID | __thiscall(MPGame) | `int(int playerID)` - WARNING: returns 0 on failure |
| FUN_006a19a0 | SlotFromObjectID | __cdecl | `int(int objID)` = `(objID - 0x3FFFFFFF) >> 18` |
| FUN_00434e00 | FindObjectByID | __cdecl | `int*(void* set, int objID)` - type 0x8003, set=NULL for global |
| FUN_0059fc60 | FindShipByObjID | __cdecl | `int*(void* set, int objID)` - type 0x8006, set=NULL for global |
| FUN_005ab550 | GetShipsInSet | __cdecl | `int*(int set, int* outCount)` - type 0x8008 |
| FUN_0059fc10 | GetObjectsInSet | __cdecl | `int*(int set, int* outCount)` - type 0x8006 |
| FUN_005ab670 | GetShipRef | ? | Gets ship extension/ref object |
| FUN_005ae140 | IsCloaked | ? | Cloaked check |

## Global Data
| Address | Description |
|---------|-------------|
| 0x0097e238 | MultiplayerGame* |
| 0x0097e9c8 | Set pointer array (int*[]) |
| 0x0097e9cc | Set count |
| 0x0099a67c | Global object hash table |
| 0x0097fa78 | TGWinsockNetwork* |
| 0x0097fa84 | Current player slot index |
| 0x0097fa8c | Current object context ID |

## Respawn Flow
1. Ship destroyed -> ObjectDestroyedHandler -> ShowShipSelectScreen
2. Player picks new ship -> FinishedSelectHandler -> StartMission
3. Client creates new ship, calls SetNetPlayerID, SetPlayer
4. New ship sent via ObjCreateTeam to server
5. Server receives, deserializes, sets ship+0x2E4 from packet byte[2]
6. Old destroyed ship may still exist in the set with the old +0x2E4 value
