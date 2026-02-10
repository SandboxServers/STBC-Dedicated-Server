# Native Game Logic Handoff Analysis (2026-02-07)

## ReceiveMessageHandler Opcode Dispatch (0x0069f2a0)
Ghidra does not recognize this as a function (unanalyzed ~912 bytes from 0x0069f2a0 to 0x0069f620).
It's registered as `LAB_0069f2a0` via FUN_006da130. It's the main opcode switch for
ET_NETWORK_MESSAGE_EVENT (0x60001).

### Dispatch Map (from xref analysis)
| Call Address | Target | Function |
|-------------|--------|----------|
| 0x0069f30d | FUN_006a1e70 | NewPlayerInGameHandler (calls InitNetwork!) |
| 0x0069f323 | FUN_0069f620 | Object create (opcode 0x02?) |
| 0x0069f339 | FUN_0069f620 | Object create variant (opcode 0x03?) |
| 0x0069f352-0x0069f458 | FUN_0069fda0 | Forward relay (10 event types) |
| 0x0069f3f4 | FUN_0069f880 | Unknown handler |
| 0x0069f494 | FUN_006a2470 | ProximityCheck collision test |
| 0x0069f4a8 | FUN_006a1360 | HostEventHandler relay |
| 0x0069f4bc | FUN_006a1420 | Delete player display |
| 0x0069f4d0 | FUN_0069f930 | Unknown handler |
| 0x0069f4e4 | FUN_0069fbb0 | Unknown handler |

### CRITICAL: InitNetwork called directly from opcode dispatch
FUN_006a1e70 is called from 0x0069f30d INSIDE the ReceiveMessageHandler.
This means: when the CLIENT sends a specific opcode (likely acknowledging opcode 0x01),
the server's ReceiveMessageHandler directly calls NewPlayerInGameHandler which calls
Python InitNetwork. This is NOT via the event system - it's a direct function call.

## FUN_0069fda0 = ForwardAndFireEvent(packet, eventType)
- Checks "Forward" filter list on the TGNetwork
- Relays packet to other clients via FUN_006b4ec0
- Converts packet to TGEvent, sets event type from param_2
- Fires event locally via FUN_006da300
- Called 10 times from ReceiveMessageHandler for 10 different opcodes

## Collision System Architecture
### ProximityManager
- Each Set has a ProximityManager (`pSet.GetProximityManager()`)
- Must be activated: `pSet.SetProximityManagerActive(1)` -- done by system scripts (Multi1.py etc.)
- Global collision toggles: `ProximityManager_SetPlayerCollisionsEnabled(1)` +
  `ProximityManager_SetMultiplayerPlayerCollisionsEnabled(1)`
- Ships must be registered: `pProximityManager.UpdateObject(kShip)` after position change

### Collision Events
- `0x800050` = ET_COLLISION -> ShipClass::CollisionEffectHandler + DamageableObject::CollisionEffectHandler
- `0x8000FC` = ET_HOST_COLLISION -> ShipClass::HostCollisionEffectHandler
- `0x800052` = ET_PLANET_COLLISION -> ShipClass::PlanetCollisionHandler

### FUN_006a2470 = ProximityCheck (collision distance test)
- Called from ReceiveMessageHandler at 0x0069f494
- Gets positions via vtable 0x94 (GetPosition)
- Gets bounding radius via vtable 0xe4 + offset 0xC
- Computes distance minus radii, compares to DAT_008955c8 threshold
- If close enough, fires ET_HOST_COLLISION (0x8000FC) via FUN_006da2a0

### HostCollisionEffectHandler (FUN_005afad0)
- Fires ET_COLLISION_DAMAGE (0x800053) event
- Calculates damage based on collision velocity / ship mass
- Applies damage to subsystems via FUN_005afd70 -> FUN_005af4a0

### Why Collisions Don't Work on Server
The collision check FUN_006a2470 is called from ReceiveMessageHandler opcode dispatch.
It requires:
1. Two valid ship objects with positions (vtable 0x94) and bounding volumes (vtable 0xe4)
2. ProximityManager must be active on the Set
3. Set must be loaded (Systems/MultiX/MultiX.py calls SetProximityManagerActive(1))
4. Ships need scene graph nodes with valid transforms for GetPosition to work

In headless mode, the scene graph may not be fully set up, so GetPosition may return
zero/garbage, causing proximity checks to never trigger or always trigger.
