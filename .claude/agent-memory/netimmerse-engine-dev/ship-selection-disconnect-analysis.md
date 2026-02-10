# Ship Selection Disconnect Analysis (2026-02-07)

## Problem
First client connection disconnects after ship selection. Second connection works.

## Root Cause: Missing Set on Server

### The Critical Chain
1. Server boots, DedicatedServer.py calls `_sysMod.Initialize()` to create the star system Set
2. Multi1.py `Initialize()` calls `pSet = App.SetClass_Create()` then `pSet.SetRegionModule(...)`
3. **SetClass_Create() returns a raw SWIG pointer string** (e.g. `_1234abcd_p_SetClass`)
4. Calling `.SetRegionModule()` on a string fails: `AttributeError: 'string' object has no attribute 'SetRegionModule'`
5. The Set is never added to SetManager (g_kSetManager), so `DAT_0097e9cc` (Set count) = 0

### Why This Causes Disconnect

#### FUN_006a1e70 (NewPlayerInGameHandler) - Lines 984-1045
After calling Python `InitNetwork(playerID)`, this function iterates over ALL Sets:
```c
if (0 < DAT_0097e9cc) {           // Set count > 0?
    local_45c = DAT_0097e9c8;      // Set array pointer
    local_468 = DAT_0097e9cc;      // Set count
    do {
        // For each Set, get all objects in the Set
        puVar10 = FUN_0059fc10(*local_45c, &local_458);
        // For each object: serialize and send object creation message to new player
        // This tells the client about existing ships, asteroids, etc.
        ...
        FUN_006b4c10(this_00, iVar2, piVar12, 0);  // Send to player
    } while (local_468 != 0);
}
```

With **no Sets** (DAT_0097e9cc == 0), this entire loop is SKIPPED. The client receives:
- MISSION_INIT_MESSAGE (system ID, limits) -- OK
- Score messages -- OK
- **NO object creation messages** (no asteroids, no grid, nothing)

The client proceeds to create its Set locally (via ProcessMessageHandler -> CreateSystemFromSpecies),
builds menus, player selects ship, clicks Start -> `StartMission()` runs client-side.

#### StartMission (Mission1Menus.py lines 740-874)
Client-side `StartMission()`:
1. Calls `CreateSystemFromSpecies(iSystem)` if host hasn't already created the Set
2. Creates the player's ship via `CreateShip(iSpecies)` -> `SpeciesToShip.CreateShip(iType)`
3. Calls `pSet.AddObjectToSet(pPlayer, pcName)` -- THIS TRIGGERS NATIVE NETWORK REPLICATION

#### Server-side Object Creation (FUN_0069f620, called from ReceiveMessageHandler opcode 0x02/0x03)
When the server receives the client's ship creation message:
1. `FUN_005a1f50(data, len)` deserializes the object from network data
2. Creates a ship object on the server
3. `FUN_0047dab0(pvVar6, piVar4, "Network")` creates a NetworkPlacement for it
4. Calls `vtable+0x134` (AddToSet equivalent) to add the object to the current Set

**But there is NO current Set on the server!** The object either:
- Gets placed into a NULL Set (crash/silent failure)
- Gets registered globally but not in any Set
- The vtable call at 0x134 may bail out without error

The critical `DAT_0097fa84` (current active player slot) and `DAT_0097fa8c` are swapped
around the deserialization (lines 5728-5737), suggesting the server needs to know WHICH
player's context (and thus which Set) to use for object placement.

#### Disconnect Mechanism
The disconnect likely happens because:
1. Server fails to properly register the ship object (no Set context)
2. Server can't send object update messages back to client (object not tracked)
3. Client times out waiting for server acknowledgment of its ship
4. OR: A native exception/error in the object placement causes the server to drop the connection

### Why Second Connection Works

The key is that the FIRST connection's client DID create the Set on its own side, and
the Python `CreateSystemFromSpecies` code also runs on the server during ProcessMessageHandler
(line 263 of Mission1.py):
```python
Multiplayer.MissionShared.g_pStartingSet = Multiplayer.SpeciesToSystem.CreateSystemFromSpecies(g_iSystem)
```

Wait - this only runs on the CLIENT side (inside ProcessMessageHandler which handles
MISSION_INIT_MESSAGE received FROM the server). The server SENDS this message, it doesn't
receive it.

**Revised theory**: The second connection works because between the first and second
connection attempts, something else completes that creates the Set:

1. **First connection triggers InitNetwork -> calls Python InitNetwork**
2. Python InitNetwork is our replacement `_ds_InitNetwork` which sends MISSION_INIT_MESSAGE
3. Client receives MISSION_INIT_MESSAGE, creates Set locally, shows ship select
4. Client selects ship, creates ship object, sends opcode 0x02 to server
5. Server's FUN_0069f620 tries to process it, fails because no server-side Set
6. Client gets disconnected
7. BUT: During step 5, or during cleanup, the system module might have been
   imported and partially initialized (sys.modules cache persists)
8. **Second connection**: InitNetwork runs again. This time, some cached state from
   the first attempt allows the Set creation to succeed (or the object is placed
   into whatever partial state exists)

**Most likely**: The ET_NEW_PLAYER_IN_GAME (0x8000f1) event fires and FUN_006a1e70 runs.
Line 975 shows it CREATES a 0x8000f1 event and posts it to the event manager. This is a
self-referential re-broadcast. On the FIRST connection, this event fires the Python-side
NewPlayerHandler (Mission1.py line 834) which tries to rebuild player lists (GUI calls,
caught by wrapper). The Kill/Death dictionaries get populated.

On the SECOND connection, the dictionaries already have entries from the first connection,
AND potentially the server's internal player slot tracking is in a state that allows
the ship creation to succeed.

## Solution: Fix Set Creation on Server

The `SetClass_Create()` SWIG issue must be resolved. Options:
1. Use Appc functional API: `pSet = Appc.SetClass_Create()` then `Appc.SetClass_SetRegionModule(pSet, name)`
2. Manually construct the SWIG shadow class wrapper around the raw pointer
3. Create the Set entirely from C-side code before Python runs

The Set needs:
- `SetClass_Create()` -> valid Set object
- `SetClass_SetRegionModule(pSet, "Systems.Multi1.Multi1")`
- `g_kSetManager.AddSet(pSet, "Multi1")`
- `SetClass_SetProximityManagerActive(pSet, 1)`
- Optionally: load placements, backdrops, asteroids, grid
