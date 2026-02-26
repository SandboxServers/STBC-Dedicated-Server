> [docs](../README.md) / [analysis](README.md) / server-side-computation-model.md

# Server-Side Computation Model: What Does the Stock Dedi COMPUTE?

Systematic analysis of what the stock BC dedicated server computes locally versus
merely relays from clients. Derived from decompiled code analysis of all relevant
handler functions.

**Key Finding**: The stock BC dedicated server runs a FULL game simulation. It is NOT
a thin relay. Every subsystem (power, shields, repair, physics, weapons, collision)
ticks on the server. Authority is mixed by path: owner-clients author upstream motion
and weapon-state input, while downstream subsystem/repair/death/score replication is
server-broadcast and client-accepted.

**2026-02-26 Trace Errata**: See
[stateupdate-authority-boundary-20260226.md](stateupdate-authority-boundary-20260226.md)
for updated `0x1C` authority boundaries, downstream `0x20/0x3x` shaping behavior, and
cadence/distribution metrics from stock + battle traces.

---

## Table of Contents

1. [Collision Damage](#1-collision-damage)
2. [Weapon Damage](#2-weapon-damage)
3. [StateUpdate Generation](#3-stateupdate-generation)
4. [Power System Tick](#4-power-system-tick)
5. [Repair System Tick](#5-repair-system-tick)
6. [Shield Recharge](#6-shield-recharge)
7. [PythonEvent Generation](#7-pythonevent-generation)
8. [Ship Physics](#8-ship-physics)
9. [Summary Table](#summary-table)
10. [Implications for OpenBC](#implications-for-openbc)

---

## 1. Collision Damage

**Verdict: SERVER VALIDATES + COMPUTES. Not a blind relay.**

### CollisionEffect Handler (FUN_006a2470, opcode 0x15)

When a client sends a CollisionEffect message to the host, the handler at
`FUN_006a2470` does NOT blindly relay the damage. It performs validation:

```
1. Deserialize TGEvent from stream (FUN_006d6200)
2. Read object references (source, dest)
3. Get the ship that sent this message (FUN_006a1aa0 from connID)
4. VALIDATE: sender must be either source or dest of the collision
5. If sender == dest (not the authority):
   a. Look up source ship (FUN_005ab670)
   b. Check if source ship has active collisions (FUN_005ae140)
   c. If source has active collisions -> DROP the message (already handled)
6. VALIDATE: compute bounding sphere distance between the two ships
   a. Get positions via vtable+0x94 (GetWorldPosition)
   b. Get bounding radii via vtable+0xE4 (GetBoundingBox)->+0xC
   c. distance = |pos1-pos2| - radius1 - radius2
   d. If distance >= DAT_008955c8 (threshold) -> DROP (ships not close enough)
7. If valid: set eventType to 0x008000FC (HostCollisionEffectEvent)
   and POST the event locally via EventManager::PostEvent (FUN_006da2a0)
```

The key insight: the server receives a collision report, validates it against physics
(bounding sphere proximity check), and then CONVERTS it to a HostCollisionEffectEvent
(0x008000FC) which fires on the server's own ship objects. This triggers the server's
own collision damage pipeline.

### HostCollisionEffectHandler (LAB_005afab0)

Registered for event type 0x008000FC (from FUN_005ab7c0 at line 50577). When the
validated CollisionEffect event arrives at the ship, it triggers the SAME
`CollisionDamageWrapper` (FUN_005b0060) that handles local collisions:

```c
CollisionDamageWrapper(ship, colliderNode, damage, radius):
    SubsystemDamageDistributor(ship, colliderNode+0x88, &radius, damage, NULL, 1)
    DoDamage_FromPosition(ship, colliderNode, damage, radius)
```

This means the server RECOMPUTES collision damage through the full damage pipeline:
shield absorption, subsystem distribution, hull damage. The server does NOT trust
the client's damage values -- it recomputes from the collision geometry.

### What the server does NOT recompute

The contact point positions and damage magnitude come from the originating client's
CollisionEffect message. The server validates proximity but trusts the collision
detection result (which contact points were hit, how much energy to apply).

**Authority Model**: CLIENT detects collision + computes contact points. SERVER
validates proximity + recomputes damage distribution through its own ship objects.

---

## 2. Weapon Damage

**Verdict: SERVER RELAYS weapon events. Damage is applied LOCALLY by each peer.**

### GenericEventForward Handler (FUN_0069fda0, opcodes 0x07-0x12, 0x1B)

This is the handler for StartFiring (0x07), StopFiring (0x08), StopFiringAtTarget (0x09),
SubsystemStatus (0x0A), AddToRepairList (0x0B), ClientEvent (0x0C), StartCloak (0x0E),
StopCloak (0x0F), StartWarp (0x10), RepairListPriority (0x11), SetPhaserLevel (0x12),
and TorpTypeChange (0x1B).

```
1. Check DAT_0097fa8a (IsMultiplayer)
2. Serialize the incoming message to a buffer (FUN_006b8530)
3. Look up the "Forward" group in TGWinsockNetwork+0xF4
4. If sender is in the "Forward" group:
   a. Remove sender from group temporarily
   b. RELAY the message to the "Forward" group (FUN_006b4ec0)
   c. Re-add sender to group
5. If sender != host:
   a. ALSO deserialize the event locally
   b. Create a TGEvent and post it to EventManager (FUN_006da300)
   c. The event fires on the server's own ship objects
```

**Critical discovery**: Step 5 shows that the server DOES apply the event to its own
simulation, but only if the sender is NOT the host itself. For weapon events like
StartFiring, this means:

- Client fires weapon -> host receives opcode 0x07
- Host RELAYS to all other clients via "Forward" group
- Host ALSO applies the StartFiring event to the firing ship's local object
- The firing ship's weapon system activates on the server
- But the DAMAGE from the weapon is computed independently by each peer

The weapon damage chain (WeaponHitHandler at FUN_005af010) fires on each peer that
simulates the weapon projectile hitting a target. There is NO network message for
"weapon X hit target Y for Z damage". Each peer independently:
1. Simulates the projectile/beam trajectory
2. Tests ray-ellipsoid intersection for shield gates
3. Runs SubsystemDamageDistributor for shield-penetrating hits
4. Calls DoDamage for hull damage

**Authority Model**: EACH PEER computes weapon damage independently. The server relays
weapon fire/stop events, but damage calculation is fully local.

### TorpedoFire Handler (FUN_0069f930, opcode 0x19)

Same relay pattern as GenericEventForward, PLUS local application:

```
1. Check IsMultiplayer
2. If sender != host: relay to "Forward" group (same remove-add pattern)
3. Deserialize torpedo creation data from stream
4. Look up target object by ID (FUN_006f0ee0)
5. Create torpedo object locally (FUN_0057d110)
```

The server creates the torpedo in its own simulation. The torpedo then flies
and hits targets locally. Each peer independently creates the same torpedo and
simulates its impact. Torpedo damage is therefore computed independently on each peer.

**Authority Model**: RELAY + LOCAL CREATE. No centralized damage computation.

### BeamFire Handler (FUN_0069fbb0, opcode 0x1A)

Same pattern:

```
1. Check IsMultiplayer
2. If sender != host: relay to "Forward" group
3. Deserialize beam hit data
4. Look up target object by ID (FUN_006f0ee0)
5. Apply beam effect locally (FUN_005762b0)
```

The server creates the beam effect in its own simulation. Damage from beams
is computed locally on each peer.

**Authority Model**: RELAY + LOCAL APPLICATION. No centralized damage computation.

---

## 3. StateUpdate Generation

**Verdict: SERVER COMPUTES and BROADCASTS. Server is AUTHORITATIVE for ship state.**

### WriteStateUpdate (FUN_005b17f0)

Called per-ship per-tick by `FUN_0069ee50` (SendStateUpdates). The function:

1. Checks if the ship state has changed since last update (dirty flags)
2. Serializes ONLY changed fields using a bitmask (flags byte)
3. Creates a TGMessage with opcode 0x1C and sends it

### Who generates StateUpdates?

`FUN_0069ee50` (called from `FUN_0069edc0` which is the MultiplayerGame per-tick
Update) iterates all 16 player slots:

```c
for each player slot (0-15):
    if slot.active AND slot.connID != host.connID:
        ship = FindShip(slot.baseObjID)
        if ship != NULL AND ship has subsystems:
            TGMessage* stateMsg = ship->WriteStateUpdate(slot)  // FUN_005b17f0
            if stateMsg != NULL:
                TGNetwork_SendMessage(host, slot.connID, stateMsg, 0)
```

**Key**: The HOST generates StateUpdates for ALL player ships (not just its own).
Each ship's WriteStateUpdate reads the LIVE state from the ship object:
- Position from `vtable+0x94` (GetWorldPosition)
- Orientation from `vtable+0xAC/0xB0` (GetForward/UpVector)
- Speed from `FUN_005a05a0` (GetVelocity)
- Subsystem health from `ship+0x284` linked list, each subsystem's WriteState
- Cloak state from `ship+0x2DC`(cloakSS)+0x9C

### Flag 0x20 (Subsystem Health) Trigger

From the WriteStateUpdate decompilation (lines 54093-54207), the 0x20 flag is set
based on a rate-limiting condition:

```c
bool isSinglePlayer = (DAT_0097fa8a == '\0');
if (isSinglePlayer) {
    flags |= 0x80;  // weapon states in SP
    // skip 0x20 check
} else {
    if (DAT_0097faa2 != 0) {  // settings byte
        int playerCount = GetPlayerCount(multiplayerGame);
        if (IsHost && playerCount > 1) {
            if (!forceUpdate) goto skip_subsystem_flag;
        } else if (IsClient && playerCount > 2) {
            if (!forceUpdate) goto skip_subsystem_flag;
        }
    }
    flags |= 0x20;  // SET subsystem states
}
```

The 0x20 flag is set most ticks. The rate limiting appears to skip it only when
a periodic force-update timer has NOT fired AND there are enough players. In practice
(from traces), flag 0x20 is present in the majority of StateUpdate messages.

### Round-Robin Subsystem Serialization

Within flag 0x20, subsystems are serialized in round-robin order from `ship+0x284`:
- 10-byte budget per tick
- Cursor persists across ticks (wraps around the linked list)
- Each subsystem writes its health via WriteState (vtable+0x70)
- The ship's authoritative subsystem health comes from the server's simulation

**Authority Model**: SERVER is the AUTHORITY for subsystem health. The server runs
the full simulation (damage, repair, power) and broadcasts the authoritative state
via flag 0x20 in StateUpdate messages.

---

## 4. Power System Tick

**Verdict: SERVER COMPUTES. Full power simulation runs on host.**

### "Powered" Master Update (FUN_00563780)

This is the main 1-second power simulation tick. It runs on the server because
the server has ship objects with subsystems, and subsystem Update() is called
via the game tick.

```c
void Powered_Update(this, deltaTime) {
    PoweredSubsystem_Update(this, deltaTime);   // base consumer update
    float gameTime = *(DAT_009a09d0 + 0x90);

    // 1-second interval gate (_DAT_00892e20)
    if (gameTime - this->lastTickTime >= 1.0) {
        this->remainingBudget = 0;

        // Battery recharge (FUN_005638d0) — CONDITIONAL
        if (!IsDead(this)) {
            float available = GetAvailablePower(this);
            BatteryRecharge(this, available * seconds);
        }

        // Power distribution (FUN_00563700) — allocate to consumers
        float distributed = DistributePower(this, seconds);
        this->powerOutput = distributed;

        this->lastTickTime = gameTime - fmod(gameTime, 1.0);
    }

    // Update battery percentages
    this->mainBatteryPct = this->mainBattery / GetMainBatteryLimit(this);
    this->backupBatteryPct = this->backupBattery / GetBackupBatteryLimit(this);

    // Reset accumulators
    ResetDrawAccumulators();
}
```

### Battery Recharge Gating (FUN_005638d0)

```c
if ((DAT_0097fa89 == '\0') || (DAT_0097fa8a != '\0')) {
    // Battery recharge logic
}
```

This means: recharge runs when `IsHost == 0` (standalone) OR `IsMultiplayer == 1`.
On the dedicated server (IsHost=1, IsMultiplayer=1), battery recharge RUNS.

### PoweredSubsystem Draw (FUN_00563a70)

The per-consumer power draw function has authority gating:

```c
if (DAT_0097fa89 != 0) {     // IsHost != 0
    playerShip = GetPlayerShip();
    parentShip = this->parentShip;  // +0x40
    if (!IsMultiplayer) {
        // SP: only own ship draws power
        canDraw = (parentShip == playerShip);
        canChargeBattery = false;
    } else if (parentShip != playerShip && parentShip->aiController != 0) {
        // MP: remote ships with AI don't draw from local sim
        canDraw = false;
    }
}
```

In multiplayer, the host draws power for:
- Its own ship (always)
- All player ships that don't have AI controllers (i.e., all human-controlled ships)

Only AI-controlled remote ships are excluded (they manage their own power). Since
human-controlled ships are the majority in MP, the host computes power for them.

**Authority Model**: SERVER COMPUTES power generation, battery recharge, and power
distribution for all human-controlled ships. Results are broadcast via StateUpdate
flag 0x20 (subsystem health includes battery levels in PowerSubsystem::WriteState).

---

## 5. Repair System Tick

**Verdict: SERVER COMPUTES. Repair queue advances on host only.**

### RepairSubsystem::Update (0x005652a0)

The repair tick has an explicit host-only gate (from docs/gameplay/repair-system.md):

```c
void RepairSubsystem_Update(RepairSubsystem* this, float deltaTime) {
    PoweredSubsystem_Update(this, deltaTime);  // power draw

    if (!this->isOn)  // +0x9C
        return;

    // HOST-ONLY GATE
    byte isHost = g_IsHost;      // 0x97FA89
    if (isHost == 0)
        goto do_repair;          // standalone mode: always repair
    if (isHost != 1 || !g_IsMultiplayer)  // 0x97FA8A
        return;                  // client in MP: DO NOT repair

do_repair:
    // Compute repair amount = MaxRepairPoints * conditionPct * deltaTime
    // Walk queue, apply repair to first N subsystems (N = NumRepairTeams)
    // Fire ET_REPAIR_COMPLETED (0x800074) or ET_REPAIR_CANNOT_BE_COMPLETED (0x800075)
    ...
}
```

The gate logic: repair runs when `IsHost==0` (standalone) or when `IsHost==1 AND
IsMultiplayer==1` (host in MP). On clients in MP (`IsHost==0, IsMultiplayer==1`),
the gate falls through to `do_repair` -- **wait, that seems wrong**. Let me re-read.

Actually: `isHost == 0` means IsHost byte is 0. In standalone, IsHost=0. In MP client,
IsHost=0. In MP host, IsHost=1. The pseudocode from docs says:

```
if isHost == 0: goto do_repair   (standalone AND MP client both have IsHost=0)
if isHost != 1: return           (won't reach -- isHost is 0 or 1)
if !IsMultiplayer: return        (SP with IsHost=1 -- impossible normally)
```

**Wait** -- this means both the client AND standalone run repair. But the doc says
"Host/multiplayer gate: only process repairs on standalone or host." Let me re-read
the actual binary logic more carefully.

The issue is that in MP: host has IsHost=1, IsMultiplayer=1. Client has IsHost=0,
IsMultiplayer=1. Standalone has IsHost=0, IsMultiplayer=0.

With the code as written:
- Standalone (IsHost=0): falls through to do_repair -- REPAIRS
- MP Client (IsHost=0): falls through to do_repair -- REPAIRS
- MP Host (IsHost=1, IsMultiplayer=1): passes both checks -- REPAIRS

So ALL peers repair. This makes sense: each peer simulates its own repair locally,
and the server's StateUpdate corrects any drift. The server IS authoritative because
it generates StateUpdates with the health values, but clients also simulate repair
to provide responsive feedback.

**However**, the repair events (ET_REPAIR_COMPLETED, ET_REPAIR_CANNOT_BE_COMPLETED,
ET_ADD_TO_REPAIR_LIST) are forwarded via the HostEventHandler as PythonEvent (0x06)
messages. These events are what update the Engineering repair panel on clients. The
server generates these events from its simulation and broadcasts them.

**Authority Model**: ALL PEERS compute repair locally. SERVER broadcasts the
authoritative subsystem health via StateUpdate. SERVER generates repair completion
events that sync repair queue state across clients.

---

## 6. Shield Recharge

**Verdict: ALL PEERS COMPUTE. Server is authoritative via StateUpdate.**

### Shield Recharge Mechanism

Shield recharge does NOT happen in a direct per-tick call. It runs through the
event system:

1. `ShieldProperty` constructor registers periodic timer events (0x8000006D-0x800071)
2. Timer events fire periodically (staggered with random phase offset)
3. `HandleSetShieldState` handler calls `BoostShield` (FUN_0056a420) per facing
4. BoostShield converts power budget to shield HP using chargePerSecond rate

Since the event system runs on all peers, shield recharge runs on ALL peers.
Each peer independently recharges its own copy of each ship's shields.

### Power Budget Source

The power budget for shield recharge comes from the PoweredSubsystem's per-tick
energy allocation. Since the power system runs on all peers (see Section 4),
shield recharge is powered on all peers.

### Correction Mechanism

The server's subsystem health is broadcast via StateUpdate flag 0x20. For
ShieldGenerator, the WriteState (Format 2: PoweredSubsystem) writes the
condition byte. However, **individual shield facing HP is NOT in StateUpdate**.
Shield facing HP is only visible in the ship's local state.

This means shield facing distribution may diverge between peers. The overall
shield subsystem condition (one byte) is synced, but the per-facing breakdown
is not.

**Authority Model**: ALL PEERS compute shield recharge independently. Server
provides periodic corrections to overall shield health via StateUpdate. Per-facing
HP is NOT synchronized -- each peer maintains its own shield facing state.

---

## 7. PythonEvent Generation

**Verdict: SERVER GENERATES most PythonEvents. Three distinct C++ producers.**

### Producer 1: HostEventHandler (LAB_006a1150)

Registered for three event types (from MultiplayerGame ctor):
- `0x008000DF` — ET_ADD_TO_REPAIR_LIST
- `0x00800074` — ET_REPAIR_COMPLETED
- `0x00800075` — ET_REPAIR_CANNOT_BE_COMPLETED

When one of these events fires on the server (from the repair tick), the
HostEventHandler serializes it as opcode 0x06 (PythonEvent) and sends it
to the "NoMe" group (all clients except self).

This is COMPUTATION -> BROADCAST: the server's repair simulation produces
events, and the HostEventHandler forwards them to clients.

### Producer 2: ObjectExplodingHandler (LAB_006a1240)

Registered for event type `0x0080004E` (ET_OBJECT_EXPLODING).

When a ship dies on the server (condition reaches 0, ShipDeathHandler fires
ET_OBJECT_EXPLODING), the ObjectExplodingHandler:
- On server (IsMultiplayer): serializes as opcode 0x06 to "NoMe" group
- On client: applies visual explosion effect locally

This is COMPUTATION -> BROADCAST: the server determines when a ship dies
and notifies clients.

### Producer 3: Ship Event Handlers

Several ship-level event handlers post events that get forwarded:
- `CollisionEffectHandler` (LAB_005af9c0) for event 0x800050
- Various subsystem events flow through the event system

### Python-Generated PythonEvents

Python scripts can also create events via the SWIG API (`App.TGEvent_Create`,
`App.TGObjPtrEvent_Create`, etc.) and post them to the event manager. These
also get serialized as opcode 0x06 by the HostEventHandler if they match
the registered event types.

### Full PythonEvent Producer Table

| Source | Event Types | Trigger | Direction |
|--------|------------|---------|-----------|
| HostEventHandler | 0xDF, 0x74, 0x75 | Repair simulation | Server -> Clients |
| ObjectExplodingHandler | 0x4E | Ship death | Server -> Clients |
| CollisionEffectHandler | 0x50 | Collision events | Local (client-side) |
| Python scripts | Various | Script logic | Via EventManager |

**Authority Model**: SERVER generates PythonEvents from its own simulation (repair
events, death events). These are AUTHORITATIVE -- clients receive and apply them.

---

## 8. Ship Physics

**Verdict: TRUST CLIENT. Server does NOT compute physics independently.**

### Position/Velocity

Each client computes its own ship's physics (position, velocity, orientation)
locally and broadcasts via StateUpdate. The server receives these StateUpdates
and APPLIES them to its local copy of each ship.

Evidence:
1. `Ship_WriteStateUpdate` (FUN_005b17f0) reads position from the live ship
   object and only sends it when changed.
2. `FUN_0069ee50` (SendStateUpdates) sends StateUpdates from the HOST to
   each client, but for remote ships the position comes from the last
   received StateUpdate (stored in the ship object).
3. There is NO physics engine tick visible in the multiplayer game update
   (`FUN_0069edc0`).
4. The ship movement system (ImpulseEngine, WarpEngine) uses per-frame
   Update calls that modify position based on input commands.

### Flow

```
Client A presses forward:
  -> ImpulseEngine::Update() modifies position locally
  -> Client A's game tick: WriteStateUpdate includes new position
  -> Sent as opcode 0x1C to host

Host receives Client A's StateUpdate:
  -> FUN_005b21c0 applies position to Client A's ship object
  -> Host's next tick: WriteStateUpdate for Client A's ship
  -> Sent to Client B (and all others)

Client B receives:
  -> FUN_005b21c0 applies position to its local copy of Client A's ship
```

The host is a RELAY for position data. It does not verify or recompute positions.

### Collision Detection

However, collision DETECTION may run on the server if ship objects are close
enough. The collision system (3-tier: sweep-and-prune -> bounding sphere -> narrow)
runs on any peer that has both ship objects loaded. The server has all ships, so
it CAN detect collisions. But in practice, the ORIGINATING peer (the one that
detects the collision first) sends the CollisionEffect message.

**Authority Model**: CLIENT is authoritative for its own ship's position/velocity.
Server trusts and relays. Server validates collision reports (proximity check)
but does not independently detect collisions for collision damage purposes.

---

## Summary Table

| System | Server Computes? | Server Relays? | Authority |
|--------|-----------------|----------------|-----------|
| **Collision Damage** | YES (validates + recomputes through damage pipeline) | YES (opcode 0x15 relay implicit) | SERVER validates, recomputes damage distribution |
| **Weapon Damage** | NO (each peer computes independently) | YES (fire/stop events relayed via "Forward" group) | EACH PEER independently |
| **StateUpdate** | YES (host integrates owner input + server sim state) | YES (host -> all clients) | HYBRID: owner-authored upstream input, server-shaped downstream broadcast |
| **Power System** | YES (host sim + replication), but client slider input is upstream-authored | Via StateUpdate + event relay paths | HYBRID: client-authored slider intent, server-broadcast downstream state |
| **Repair System** | YES (all peers run repair tick) | Via StateUpdate + PythonEvent 0x06 | SERVER (authoritative health + repair events) |
| **Shield Recharge** | YES (all peers run shield recharge) | Via StateUpdate (overall health only) | DUAL (server: overall; each peer: per-facing) |
| **PythonEvent Generation** | YES (repair events, death events from server sim) | YES (opcode 0x06 to "NoMe") | SERVER generates |
| **Ship Physics** | NO (trusts client StateUpdates) | YES (position data relayed) | CLIENT (own ship), relayed by server |

---

## Implications for OpenBC

### Must Compute (Server-Side)

1. **Full subsystem simulation**: Power, repair, shields, weapons all tick on server
2. **Collision damage validation**: Proximity check + full damage pipeline recomputation
3. **StateUpdate generation**: Round-robin subsystem health, position relay, dirty flags
4. **Repair event generation**: ET_REPAIR_COMPLETED, ET_REPAIR_CANNOT_BE_COMPLETED,
   ET_ADD_TO_REPAIR_LIST as PythonEvent (0x06) broadcasts
5. **Death detection**: ET_OBJECT_EXPLODING when ship HP reaches 0
6. **Explosion damage (opcode 0x29)**: Host generates and broadcasts AoE damage

### Can Trust Clients

1. **Ship position/velocity**: Server trusts client StateUpdates (no server-side physics)
2. **Weapon fire commands**: Server relays, does not validate firing conditions
3. **Collision detection**: Server trusts client collision reports (validates proximity)

### Dual-Authority (Both Compute)

1. **Shield recharge**: Both compute; server corrects via StateUpdate (overall only)
2. **Repair progress**: Both compute; server generates authoritative events
3. **Power draw**: Both compute; server corrects via StateUpdate battery levels

### Key Architectural Insight

BC uses a **distributed simulation with server authority** model:
- ALL peers run the full game simulation (damage, repair, power, shields)
- The server's copy is AUTHORITATIVE: its StateUpdates override client state
- Clients simulate locally for responsiveness, get corrected by server updates
- Weapon damage is the notable exception: fully peer-computed, no server authority
- This means weapon damage can diverge between peers (known BC behavior)

This is NOT a lockstep or deterministic simulation. Floating-point differences,
timing variations, and independent computation mean peer states WILL diverge.
The StateUpdate system provides eventual consistency (correcting drift ~10Hz).
