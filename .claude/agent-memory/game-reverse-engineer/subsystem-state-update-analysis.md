# Subsystem/Weapon State Update (0x1C Packet) Analysis

## Date: 2026-02-09

## Summary
The renderer unstubbing was intended to allow NIF model loading so ships would have
subsystem/weapon lists. However, the 0x1C state update problem is NOT the primary
cause of client disconnect -- it's a downstream symptom of a more fundamental issue:
the server has NO game objects at all.

## The 0x1C State Update Function (FUN_005b17f0)

### Flags Byte Layout
| Bit | Hex  | Meaning |
|-----|------|---------|
| 0   | 0x01 | Position (absolute coordinates) |
| 1   | 0x02 | Position delta (compressed) |
| 2   | 0x04 | Orientation (Euler angles) |
| 3   | 0x08 | Angular velocity |
| 4   | 0x10 | Speed/velocity magnitude |
| 5   | 0x20 | Subsystem data (iterate subsystem linked list) |
| 6   | 0x40 | Shield/cloaking state |
| 7   | 0x80 | Weapon data (iterate weapon linked list) |

### When flags are set
- **0x80 (weapons)**: Set ONLY in single-player (IsMultiplayer==0). NOT used in MP.
- **0x20 (subsystems)**: Set in MP when player count is below threshold:
  - If IsClient==0 (host): set when playerCount < 2
  - If IsClient==1 (client): set when playerCount < 3
  - This means subsystem data is sent during initial state sync (low player count)
    and then STOPS once enough players are connected. A "full state dump" mechanism.

### Subsystem/Weapon List Source (offset 0x284)
- `ship+0x284` = head of subsystem linked list (doubly-linked, nodes are [data, next, prev])
- `ship+0x288` = tail of subsystem linked list
- `ship+0x280` = list count
- Populated by FUN_005b3e50 (AddSubsystem), called from FUN_005b3fb0 (ship setup)
- FUN_005b3fb0 iterates subsystem descriptors (type 0x812b) from the model property set
- Subsystem types: 0x812f (weapon/phaser), 0x8132 (hull), 0x8133 (shield), etc.
- Type dispatch creates concrete subsystem objects (PowerSubsystem, SensorSubsystem, etc.)

### Where Subsystem Descriptors Come From
1. Python hardpoint files (e.g., `ships/Hardpoints/warbird.py`) define SubsystemProperty objects
2. Properties are registered with `g_kModelPropertyManager.RegisterLocalTemplate()`
3. Ship's LoadModel function calls `pObj.AddToSet("Scene Root", prop)` for each subsystem
4. AddToSet (C++ FUN_006c9520) links properties to NiNode "Scene Root" in the NIF model tree
5. FUN_005b3fb0 reads these linked properties and creates runtime subsystem objects

### The NIF Model Dependency
- `AddToSet("Scene Root", prop)` searches the NIF model's node tree for "Scene Root"
- This requires the NIF model to be loaded via NiStream
- The NIF model contains the scene graph with named NiNodes
- Without a loaded NIF, there is no "Scene Root" node, and AddToSet has nothing to attach to
- Result: ship objects created without NIF models have EMPTY subsystem lists (0x284 = NULL)

## Current Server State (from logs)

### What Happens
1. Server boots, renderer constructor runs, pipeline builds (PatchSkipRendererSetup removed).
   Renderer has basic data structures but actual D3D calls are proxied/stubbed.
2. Client connects, checksums pass, NewPlayerInGame fires
3. Server sends opcode 0x00 (settings) + 0x01 (start game) + Python messages
4. Client enters ship selection screen (this works now!)
5. **Server has NO game objects** -- no ships exist on the server
6. No 0x1C state updates are ever sent (confirmed by packet trace)

### Why No Game Objects
- Ship creation is CLIENT-SIDE in STBC multiplayer
- Client creates its own ship locally after selecting species
- Client sends ship creation data to server via game message
- Server must deserialize this data (FUN_005a1f50 -> FUN_006f13e0 factory)
- The factory creates a ShipClass object on the server side
- For the server-side ShipClass to have subsystems, it needs:
  1. The hardpoint file loaded (Python) -- sets up SubsystemProperty templates
  2. The NIF model loaded (via NiStream) -- provides "Scene Root" NiNode
  3. AddToSet called -- links properties to model nodes
  4. FUN_005b3fb0 called -- creates runtime subsystem objects from linked properties

### PatchNetworkUpdateNullLists Effectiveness
- The code cave at 0x005b1d57 checks `[ESI+0x284]` (subsystem list head)
- If NULL, it clears bits 0x20 and 0x80 from the flags byte
- This PREVENTS the subsystem/weapon iteration loops from executing
- The code cave prevents the crash entirely -- no exception handling needed
- Result: if a ship existed with no subsystems, its 0x1C packet would be well-formed
  but contain NO subsystem/weapon data (just position/orientation)

## Conclusion

The PatchNetworkUpdateNullLists fix is WORKING CORRECTLY. It prevents malformed packets
by clearing the flags that promise subsystem/weapon data when the lists are NULL.

However, the REAL problem is that:
1. The server has no game objects at all (no ships)
2. Therefore FUN_005b17f0 is never called
3. Therefore no 0x1C state updates are generated
4. The client never receives state updates for any objects

The renderer unstubbing (letting NiDX7Renderer ctor run) was a step in the right
direction, but it's not sufficient. The full chain requires:
- NIF models loaded via NiStream (requires file I/O, not D3D)
- Hardpoint Python files executed (provides subsystem property definitions)
- Ship objects created on the server (requires client to send creation data)
- AddToSet linking properties to model nodes
- FUN_005b3fb0 creating runtime subsystem objects

The 0x004360CB bounding box crash (happening hundreds of times) suggests some objects
DO exist but have no mesh geometry. This could be the MultiplayerGame object or
proximity manager objects that try to compute bounds on headless entities.
