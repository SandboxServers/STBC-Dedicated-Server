# Design Intent Analysis

## NetImmerse 3.1 Architecture: Rendering and Simulation Are Inseparable

### Why the scene graph cannot be separated from the renderer
NetImmerse 3.1 does not distinguish between "spatial hierarchy" and "renderable hierarchy." NiNode serves both purposes. NiBound is computed from child geometry. Hardpoints are NiNode children found by name. The NIF file format encodes everything in one structure.

Skipping renderer pipeline construction breaks internal state that NIF loading depends on for complete scene graphs. This manifests as:
- NULL subsystem/weapon linked lists (hardpoints can't be resolved)
- Zero bounding volumes (NiBound not computed from geometry)
- Missing transforms (NiAVObject world transforms not propagated)

The pipeline now runs fully (PatchSkipRendererSetup removed, PatchDeviceCapsRawCopy prevents
the raw memcpy crash). NIF models still don't fully load because GPU texture backing is
needed, but the pipeline infrastructure is in place.

### FUN_005b17f0 Network State Update - Invariants
The function (05_game_mission.c:53990) assumes:
1. Every object in the MP object table has a valid NiAVObject with scene graph
2. vtable+0x94 (GetWorldTranslation) returns valid float[3]
3. vtable+0xac (GetWorldRotation) returns valid rotation data
4. vtable+0xb0 (GetWorldScale) returns valid scale data
5. object+0x284 subsystem linked list is populated (or at least valid)
6. object+0xa1 (subsystem list head) is valid for iteration

None of these have NULL guards. The function was written with the guarantee that CreateShip->SetupModel->SetupProperties always succeeds before an object enters the simulation.

### Flag byte logic in FUN_005b17f0
- bit 0x01: position changed
- bit 0x02: compressed position delta
- bit 0x04: rotation changed
- bit 0x08: angular velocity changed
- bit 0x10: speed changed
- bit 0x20: subsystem data (set based on player count, NOT on list validity)
- bit 0x40: cloak state
- bit 0x80: weapon data (always set in single-player; multiplayer conditional)

The 0x20/0x80 bits are set based on game state, never based on whether the lists exist. PatchNetworkUpdateNullLists is a correct band-aid but doesn't fix the position/rotation vtable calls.

## Stock Dedicated Server Mode

### How it works (from MultiplayerMenus.py)
The stock dedicated server toggle at line 1632 reads "Multiplayer Options" > "Dedicated Server" from config. When chosen=1:
- Line 2996-2999: Sets IsHost=1, IsClient=0
- Line 909-917: After game starts, shows options window instead of tactical view
- Line 2426: Uses GetDedicatedServerMenu() for configuration UI
- The full renderer, scene graph, NIF loading, and simulation all run normally

### What IsClient=0 does in the engine
- 09_multiplayer_game.c:5509: Skips GameSpy client timer creation
- 09_multiplayer_game.c:5771: Changes player count threshold for subsystem updates
- 05_game_mission.c:54195: Affects subsystem update flag calculation
- 10_netfile_checksums.c:2988: Changes checksum behavior
- The host with IsClient=0 does NOT create a player ship -- it just manages the game

### The key insight
"Dedicated server" in BC means "no player ship" not "no renderer." The engine was never designed to run without its scene graph infrastructure.

## Recommended Headless Architecture

### What to let run natively
- NiDX7Renderer constructor (un-stubbed, runs fully)
- Renderer setup pipeline (PatchSkipRendererSetup removed, pipeline builds)
- NIF loading (NiStream, geometry, transforms)
- Scene graph construction (NiNode hierarchy, NiAVObject)
- SetupProperties (hardpoint resolution, subsystem creation)
- All simulation (physics, collision, AI, networking)

### What to stub at the D3D device level
- DrawPrimitive / DrawIndexedPrimitive (return S_OK)
- Present / Flip (return S_OK)
- Texture creation that hits the GPU (return system-memory stubs)
- UI rendering functions (LCARS panes, bridge view)

### DDraw/D3D proxy surface requirements
Surfaces must have real system-memory allocations with valid lpSurface pointers and correct lPitch. Some code paths read back from surfaces. Zeroed memory is fine but NULL pointers are not.

## NiDX7Renderer Pipeline (FUN_007c3480) Detailed Analysis

### Object Layout
- **renderer+0x14**: IDirect3D7* (set by QueryInterface in FUN_007c09c0)
- **renderer+0x18**: IDirect3DDevice7* (set by CreateDevice inside FUN_007c3480)
- **renderer+0x34**: Display adapter object (NiDX7AdapterDesc)
- **renderer+0xC8**: NiD3DGeometryGroupManager* (vertex cache)
- **renderer+0x2A4**: Capability flags bitmask

### NiD3DGeometryGroupManager (FUN_007cb2c0)
Constructor for the geometry batching system. 0x2C-byte object, `__thiscall` with 3 stack params:
- param_1 (ESP+0x20): IDirect3D7* -- stored at this+0x00, AddRef'd
- param_2 (ESP+0x24): IDirect3DDevice7* -- stored at this+0x04, AddRef'd
- param_3 (ESP+0x28): bool -- controls SYSTEMMEMORY vs WRITEONLY VB allocation

Ghidra shows only 1 param because it mismodeled the stack. The `RET 0xC` confirms 3 DWORDs.
The D3D7 pointer is held for later CreateVertexBuffer calls; Device7 for DrawPrimitive.
Both AddRef calls go through vtable[1] which must be valid AddRef implementations.

### T&L Path Selection
At 0x007c39fc-0x007c3a06: checks `[adapter+0x190]+0x14 & 4` (T&L capability).
If T&L set: takes path at 0x007c3a08 (PUSH 0 = false for bool param).
If T&L NOT set: takes path at 0x007c3a3f (PUSH 1 = true for bool param).

### Pipeline construction sequence (after caps check passes)
1. vertex cache = new NiD3DGeometryGroupManager(d3d7, device7, bool) -> renderer+0xC8
2. Check W-buffer cap, set renderer flags
3. SetCameraData (vtable+0xa4 = 0x007c16f0) with 6 pointer params (24 bytes)
4. FUN_007d4950 (texture manager creation) -> renderer+0xC4
5. FUN_007d2230 (render state manager) -> renderer+0xB8
6. FUN_007ccd10 (buffer manager) -> renderer+0xBC
7. FUN_007d11a0 (light manager) -> renderer+0xC0
8. Set capability flags, return true

### Adapter creation path (FUN_007c7f80)
Uses GetProcAddress(GetModuleHandle("DDRAW.DLL"), "DirectDrawCreateEx") to create a SECOND
IDirectDraw7 internally. In proxy mode, this returns another ProxyDDraw7 from the proxy DLL.
The adapter wraps this IDirectDraw7 and its IDirect3D7 (from QI). The renderer gets the
IDirect3D7 from adapter+0xC via QueryInterface(IID_IDirect3D7, &renderer+0x14).

### Critical: Display adapter vtable at adapter+0xC
The IDirect3D7 stored at adapter+0xC may be a NetImmerse wrapper, not the raw proxy.
Need to verify: does the QI at 0x007c0b3c-0x007c0b4b return the ProxyD3D7 directly,
or a NetImmerse adapter wrapper?

## Multiplayer Network Protocol - Full Architecture

### Two-Layer Message System
BC multiplayer uses two distinct message dispatch layers:

**Layer 1: C++ Engine Messages (FUN_0069f2a0 dispatcher)**
Handled by MultiplayerGame::ReceiveMessageHandler. These are binary-serialized messages
with compact encodings. Opcodes are in the first byte of the decrypted payload.

**Layer 2: Python TGMessage Messages (via FUN_0069f880)**
Wrapped in TGEvents with type ET_NETWORK_MESSAGE_EVENT (0x60001). Both C++ and Python
handlers receive these. Python reads a type byte from TGBufferStream to dispatch.

### State Update Packet (opcode 0x02 / FUN_005b17f0)
Uses dirty-flag delta compression. The flag byte at offset 7 determines which fields follow:

```
[opcode:0x1C] [objectID:i32] [gameTime:f32] [flagByte:u8]
  bit 0x01: absolute position [posX:f32 posY:f32 posZ:f32] [spFlag:u8] [if SP: hash:u16]
  bit 0x02: compressed delta [deltaVec:3-4 bytes via FUN_006d2f10] (mutually exclusive with 0x01)
  bit 0x04: compressed rotation [3 bytes via FUN_006d2e50]
  bit 0x08: compressed angular velocity [3 bytes via FUN_006d2e50]
  bit 0x10: compressed speed [2 bytes float16 via FUN_006d3a90]
  bit 0x40: cloak percentage [1 byte]
  bit 0x20: subsystem data [count:u8] [per-subsystem: index:u8 + serialized via vtable+0x70]
  bit 0x80: weapon data [per-weapon: index:u8 + type check 0x801c + state:u8]
```

Subsystem data uses round-robin with 10-byte budget per frame.
Weapon data uses round-robin with 6-byte budget per frame.
State updates are UNRELIABLE (msg+0x3A = 0).

### Combat Event Messages (separate from state updates, all RELIABLE)
| Event Type | Handler | C++ Address | Description |
|------------|---------|-------------|-------------|
| 0x008000D8 | StartFiringHandler | 0x006a1790 | Weapon fire start |
| 0x008000DA | StopFiringHandler | 0x006a18d0 | Weapon fire stop |
| 0x008000DC | StopFiringAtTargetHandler | 0x006a18e0 | Stop fire at target |
| 0x008000DD | SubsystemStatusHandler | 0x006a1910 | Subsystem state change |
| 0x008000E0 | SetPhaserLevelHandler | 0x006a1970 | Phaser power level |
| 0x008000E2 | StartCloakingHandler | 0x006a18f0 | Begin cloak |
| 0x008000E4 | StopCloakingHandler | 0x006a1900 | End cloak |
| 0x008000EC | StartWarpHandler | 0x006a17a0 | Warp entry |
| 0x008000C5 | ExitedWarpHandler | 0x006a0a10 | Warp exit |
| 0x008000FE | TorpedoTypeChangeHandler | 0x006a17b0 | Torpedo loadout change |
| 0x0080004E | ObjectExplodingHandler | 0x006a1240 | Object destruction |
| 0x00800058 | ChangedTargetHandler | 0x006a1a70 | Target selection (client only) |
| 0x00800076 | RepairListPriorityHandler | 0x006a1940 | Repair priority change |

### Python Message Types (via TGMessage/TGBufferStream)
All use first byte as type discriminator. App.MAX_MESSAGE_TYPES is the base offset.
| Offset | Name | Defined In |
|--------|------|-----------|
| +1 | CHAT_MESSAGE | MultiplayerMenus.py:475 |
| +2 | TEAM_CHAT_MESSAGE | MultiplayerMenus.py:476 |
| +10 | MISSION_INIT_MESSAGE | MissionShared.py:19 |
| +11 | SCORE_CHANGE_MESSAGE | MissionShared.py:20 |
| +12 | SCORE_MESSAGE | MissionShared.py:21 |
| +13 | END_GAME_MESSAGE | MissionShared.py:22 |
| +14 | RESTART_GAME_MESSAGE | MissionShared.py:23 |
| +20 | SCORE_INIT_MESSAGE | Mission-specific |
| +21 | TEAM_SCORE_MESSAGE | Mission-specific |
| +22 | TEAM_MESSAGE | Mission-specific |

### Bandwidth Design
- Compressed vectors: position delta ~4 bytes (vs 12), rotation 3 bytes (vs 12), speed 2 bytes (vs 4)
- Delta compression: stationary objects send NO updates (flag byte = 0, function returns NULL)
- Round-robin budgets: 10 bytes/frame for subsystems, 6 bytes/frame for weapons
- Subsystem detail gated on player count (more detail with fewer players)
- State updates = unreliable UDP. Combat events = reliable (guaranteed delivery).
- Estimated 15-25 kbps sustained for 2-player combat, fits 56k modem

## Collision Damage Authority Model

### Design: HOST-Authoritative with Client-Side Physics Response

The collision system uses a split authority model:
- **Physics response** (bouncing off): runs locally on ALL clients via ProximityManager
- **Damage calculation**: runs ONLY on the HOST, then relayed via network events

### Event Flow (Two Separate Collision Events)

1. **Event 0x00800050 (CollisionEffect)** - generated by `FUN_00594840` via ProximityManager
   callback `FUN_005a88e0`. Runs on ALL instances (host and clients). The handler at
   `LAB_005af9c0` (ShipClass::CollisionEffectHandler):
   - Calls `FUN_00594840` for basic collision processing
   - Calls `FUN_006a17c0` to SEND the collision over the network (reliable, opcode 0x0C)
   - This is how a client reports "I collided with something" to the host

2. **Event 0x008000fc (HostCollisionEffect)** - generated by `FUN_006a2470`, which is
   called from the MultiplayerGame dispatcher when a collision network message arrives.
   FUN_006a2470 deserializes the collision data, verifies proximity (distance check using
   bounding radii), then fires event 0x008000fc locally.

3. The handler `FUN_005afad0` (ShipClass::HostCollisionEffectHandler) responds to 0x008000fc:
   - Guard: `(IsMultiplayer != 0) || (IsHost == 0)` -- always runs in MP
   - Fires event 0x00800053 (collision visual effect) for VFX
   - **Critical damage guard**: On HOST, `IsHost != 0` satisfies both OR branches →
     host ALWAYS applies damage to any ship
   - On CLIENT: `this != localShip` must be true → client ONLY applies damage to
     OTHER players' ships (not its own)
   - Calls `FUN_005afd70` (damage application) → `FUN_005af4a0` (per-subsystem damage)

### Invulnerability Check (FUN_005ae140)
- **IsHost=1**: returns `ship+0x2e4 != 0` (explicit invulnerability flag)
- **IsHost=0 (client)**: returns `localShip == param_1` (local ship is "invulnerable")
  This prevents clients from locally applying collision damage to their own ship.

### Collision Damage Toggle (DAT_008e5f59)
- Host uses `DAT_008e5f59`, client uses `DAT_008e5f58` (client-local copy)
- UI: collision toggle button is DISABLED on clients (mainmenu.py:3091-3092)
- Only the host can enable/disable collision damage
- Sent to clients via opcode 0x16 (UISettings) as a bit field

### Implications for Dedicated Server
The host MUST run the collision damage path. Since damage is host-authoritative:
1. ProximityManager must be active on the server (it is, via SetProximityManagerActive)
2. Ships must have valid bounding volumes (requires scene graph with geometry)
3. The collision callback `FUN_005a88e0` must fire on the server
4. `FUN_005afad0` applies damage and sends visual effect events to clients
5. If ship objects lack geometry/bounding volumes, ProximityManager won't detect
   collisions, and no damage will be applied to any ship

## OpenBC Design Questions — Confirmed Design Intent (2026-02-23)

### PythonEvent Generation: C++ Event Handlers, Not Scripts
All PythonEvents are generated by C++ event handlers registered in the MultiplayerGame
constructor (0x0069E590). The simulation itself produces the events — damage posts repair
events, weapons post fire events, death posts explosion events. Mission Python scripts
contribute ~12% (base TGEvent class). Server needs full simulation running; events emerge
as side effects. Key producers:
- HostEventHandler (0x006A1150): 3 repair event types → TGSubsystemEvent
- ObjectExplodingHandler (0x006A1240): death → ObjectExplodingEvent
- 5 weapon handlers: weapon/phaser/tractor/cloak/level → TGObjPtrEvent or TGCharEvent

### Weapon Damage: Receiver-Local (Each Client Independently)
Deliberate design for 56K bandwidth. Torpedo/beam fire opcodes (0x19/0x1A) are pure
relays — server forwards, each client creates local projectile and runs its own collision
+ damage pipeline. No "hit confirmation" message exists. StartFiring/StopFiring (0x07/0x08)
signal firing state changes; damage computed frame-by-frame locally. Only collision damage
is host-authoritative. Server-side weapon damage (OpenBC improvement) is valid for
OpenBC-to-OpenBC but would double-apply if stock clients also compute locally.

### ObjCreate (0x02): Host Dummy Ship or Non-Player Objects
3 instances correlate 1:1 with player joins. Most likely the host's dummy ship (slot 0,
no team assignment, GetPlayerController returns NULL → falls to type_tag=2). Could also
be scene objects. OpenBC without a dummy host ship should not generate these.

### PythonEvent2 (0x0D): Client-to-Server Notification, NOT Relayed
Jump table index 11 goes directly to FUN_0069f880 (no relay wrapper). Opcode 0x06
index 4 HAS a relay wrapper. 0x0D = client notifies server privately; server's event
handlers decide what to broadcast. 75 instances in trace, all C→S, 1:1 ratio. OpenBC
should NOT relay 0x0D — doing so double-broadcasts events.

### Post-Death StateUpdates: Continue During Explosion
Ship object remains in simulation during 9.5s explosion. Debris can still take/deal
collision damage. Late repair events at T+9.5s prove continued simulation. Stop updates
only when replaced by client's ObjCreateTeam respawn.

### EnterSet (0x1F): Custom Mission Infrastructure, Never Fires in Standard MP
Built for multi-set custom missions (zone transitions). FFA/TDM has one set → never fires.
Handler relays if object not found locally, performs set transition if found. Forward-thinking
infrastructure that no stock game mode exercises. Safe to ignore for standard modes.
