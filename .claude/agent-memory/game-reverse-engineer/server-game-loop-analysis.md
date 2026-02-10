# Server Game Loop Analysis: What's Missing After Ship Select

## State After Ship Select
Client creates ship locally, sends creation packet to server.
Server SHOULD: instantiate server-side ship, start sending 0x1C state updates.
Server ACTUALLY: VEH crashes on bounding box calc (0x004360CB), ship partially created.

## Opcode 0x1C: Object State Updates (FUN_005b17f0)
- Called every tick for every game object with network representation
- Flags byte (bVar6) determines what data follows:
  - 0x01: absolute position (xyz floats + hash)
  - 0x02: relative position (compressed 3-byte per axis)
  - 0x04: orientation column 1
  - 0x08: orientation column 2
  - 0x10: speed (compressed short)
  - 0x20: subsystem states (linked list iteration)
  - 0x40: shield throttle
  - 0x80: weapon states (linked list iteration)
- PatchNetworkUpdateNullLists clears 0x20/0x80 when ESI+0x284 is NULL
- Without objects in game loop, 0x1C never sent at all

## Object Replication (FUN_0069f620)
- Handles incoming object data (creation/updates from clients)
- In multiplayer: forwards to all other peers
- On host: processes object and creates server-side representation
- Server-side object needs to join game object lists for 0x1C updates

## Game Objects are Client-Created
- Ship creation happens in Mission1Menus.py:StartMission (line 776)
- Client calls MissionMenusShared.CreateShip(iSpecies)
- Client adds to Set, sets as player
- Server never creates ships -- only receives replication

## Database/Assets are Client-Local
- g_pDatabase, g_pShipDatabase, g_pSystemDatabase: loaded from TGL files locally
- g_pStartingSet: created locally via CreateSystemFromSpecies(iSystem)
- Server only sends the system ID, client does the work

## The ~3 Second Disconnect
Most likely NOT a timeout (45 sec configured).
Likely causes:
1. Corrupted 0x1C packet from server (flags promise data that's missing)
2. Server-side object processing crash -> C++ sets IsGameOver flag
3. ET_DELETE_OBJECT_PUBLIC fires for malformed server object -> game over screen

## Forward Table
FUN_006a1e70 line 1047-1117: after object sync, registers player in "Forward"
event dispatch table. This is needed for routing events between peers.
