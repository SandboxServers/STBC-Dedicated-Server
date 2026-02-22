> [docs](../README.md) / [gameplay](README.md) / self-destruct-pipeline.md

# Self-Destruct Complete Pipeline Analysis

**Date**: 2026-02-21 (verified)
**Binary**: stbc.exe (32-bit, ~5.9MB, base 0x400000)
**Method**: Ghidra decompilation, objdump disassembly, string analysis, Python script cross-reference
**Status**: SHIPPED FEATURE -- fully functional in both single-player and multiplayer

---

## Executive Summary

Self-destruct is a **shipped, working feature** that allows any player to destroy their own ship via Ctrl+D. In multiplayer, it uses opcode 0x13 (HostMsg) as a **client-to-host request** -- the client sends a 1-byte message (just the opcode byte `0x13`) to the host, which looks up the requesting player's ship and calls `FUN_005af5f0` (DoDamageToSelf) to apply lethal damage through the PowerSubsystem. The ship then follows the normal destruction pipeline (hull reaches zero -> OBJECT_EXPLODING event -> scoring -> DestroyObject network broadcast).

There is no confirmation dialog, no countdown timer, and no abort mechanism. Ctrl+D = instant death.

---

## Key Components

### Constants and Strings

| Item | Address | Value |
|------|---------|-------|
| ET_INPUT_SELF_DESTRUCT | string at 0x00953920 | Event type `0x8001DD` (registered in FUN_0050ca50) |
| SELF_DESTRUCT_REQUEST_MESSAGE | string at 0x00952F44 | SWIG constant name (opcode `0x13`) |
| "TopWindow::SelfDestructHandler" | string at 0x008E2354 | Debug name for handler registration |

### Key Functions

| Address | Name | Signature | Role |
|---------|------|-----------|------|
| 0x0050D070 | TopWindow::SelfDestructHandler | `__thiscall(this, pEvent)` | Client-side: local SP destruct or MP network send |
| 0x006A01B0 | HostMsgHandler (opcode 0x13) | `void(int param_1)` | Host-side: receives request, looks up ship, applies damage |
| 0x005AF5F0 | DoDamageToSelf | `__thiscall(ship*, powerSubsystem*)` | Core: applies lethal damage via PowerSubsystem |
| 0x005AF4A0 | DoDamageToSelf_Inner | `__thiscall(ship*, subsystem*, float, int*, char)` | Core: actual damage application + death chain |
| 0x005AFEA0 | ShipDeathHandler | `__thiscall(ship*, int* subsystem)` | Core: fires OBJECT_EXPLODING event after ship dies |
| 0x006A1AA0 | GetShipFromPlayerID | `__cdecl(int connID) -> ship*` | Utility: maps connection ID to ship pointer |
| 0x0056C310 | GetMaxHP | `__fastcall(subsystem*) -> float` | Reads `subsystem->property->maxCondition` (+0x18 -> +0x20) |
| 0x0056C330 | IsDead | `__fastcall(subsystem*) -> bool` | Checks subsystem death flag (+0x18 -> +0x24) |
| 0x0056C470 | SetCondition | `__thiscall(subsystem*, float newHP)` | Sets HP, clamps to max, fires SUBSYSTEM_HIT if damaged |

---

## Complete Flow Diagram

### Single-Player Path

```
Player presses Ctrl+D
    |
    v
KeyboardBinding: WC_CTRL_D -> ET_INPUT_SELF_DESTRUCT (0x8001DD)
    |
    v
TopWindow::SelfDestructHandler (0x0050D070)
    |
    +-- Check: IsHost == 0 (false in SP host mode)
    |   +-- Check: IsMultiplayer == 0 (true -- skip network path)
    |       +-- Check: Clock+0x8C != 2 and != 3 (TestMenuState guard)
    |           +-- Get player ship via FUN_004069b0
    |           +-- Call FUN_005af5f0(ship, ship+0x2C4)  [PowerSubsystem]
    |
    v
DoDamageToSelf (0x005AF5F0)
    |
    v
Ship destruction via normal pipeline
```

### Multiplayer Path (Client -> Host -> All)

```
CLIENT SIDE:
============
Player presses Ctrl+D
    |
    v
KeyboardBinding: WC_CTRL_D -> ET_INPUT_SELF_DESTRUCT (0x8001DD)
    |
    v
TopWindow::SelfDestructHandler (0x0050D070)
    |
    +-- Check: IsHost != 0? NO (IsHost==0 for client)
    +-- Check: IsMultiplayer != 0? YES
    |
    v
    Create TGMessage (factory at 0x008958D0, size 0x40)
    Write single byte: 0x13 (opcode) to message buffer
    Send to host: TGNetwork::SendTGMessage(hostConnectionID, msg, 0)
    CallNextHandler(event) -- propagates event chain


HOST SIDE (on receiving opcode 0x13):
=====================================
MultiplayerGame_ReceiveMessage (0x0069F2A0)
    |
    +-- case 0x13:
    |
    v
HostMsgHandler (0x006A01B0)
    |
    +-- Check: IsMultiplayer != 0? YES
    +-- Read sender connection ID from message (+0x0C)
    +-- GetShipFromPlayerID(connID) -> ship pointer
    +-- If ship != NULL:
    |       Call FUN_005af5f0(ship, ship+0x2C4)  [PowerSubsystem]
    |
    v
DoDamageToSelf (0x005AF5F0)
    |
    v
Ship destruction -> OBJECT_EXPLODING event -> scoring -> DestroyObject broadcast


ALL CLIENTS (via normal event forwarding):
==========================================
The ship's death is communicated via:
  1. StateUpdate 0x1C (HP drops to 0)
  2. Opcode 0x06 PythonEvent (OBJECT_EXPLODING, forwarded by HostEventHandler)
  3. Opcode 0x14 DestroyObject (cleanup)
  4. Opcode 0x17 DeletePlayerUI (scoreboard update, if player disconnects)
```

---

## Wire Format: Opcode 0x13 (HostMsg)

The HostMsg opcode is remarkably simple -- the **smallest possible game message**:

```
Offset  Size  Type    Field          Notes
------  ----  ----    -----          -----
0       1     u8      opcode         Always 0x13
```

Total size: **1 byte** (just the opcode). There is no payload.

The **sender's identity** is carried in the TGMessage envelope (the `+0x0C` field contains the sender's connection ID), not in the game-level payload. The host uses `GetShipFromPlayerID()` to map the connection ID to the ship object.

### Sender Code (from SelfDestructHandler disassembly at 0x0050D070)

```asm
; Create TGMessage (0x40 bytes)
push   0x0                       ; flags=0
push   0x8d858c                  ; factory string (TGMessage)
push   0x40                      ; size=64
mov    ecx, 0x99c478             ; allocator
call   FUN_00717b70              ; NiAlloc
mov    ecx, eax
call   FUN_00718010              ; construct
; ...
call   FUN_006b82a0              ; TGMessage ctor

; Write opcode byte
mov    BYTE PTR [esp+0x17], 0x13 ; opcode = 0x13
push   0x1                       ; size = 1 byte
push   eax                       ; pointer to byte
mov    ecx, esi                  ; TGMessage*
call   FUN_006b84d0              ; Buffer copy (allocate + memcpy)

; Send to host
mov    ecx, [edi+0x20]           ; host connection ID
push   0x0                       ; options
push   esi                       ; TGMessage*
push   ecx                       ; target ID
mov    ecx, edi                  ; TGNetwork*
call   FUN_006b4c10              ; SendTGMessage
```

---

## DoDamageToSelf (FUN_005AF5F0) -- Decompiled

```c
float10 __thiscall DoDamageToSelf(void *ship, void *powerSubsystem)
{
    if (powerSubsystem == NULL)
        return 0.0f;  // DAT_00888b54 = 0.0

    float maxHP = GetMaxHP(powerSubsystem);  // FUN_0056c310
    // DoDamageToSelf_Inner(ship, powerSubsystem, maxHP, NULL, 1)
    //   param: force_kill=1 (bypasses certain checks)
    return DoDamageToSelf_Inner(ship, powerSubsystem, maxHP, NULL, 1);
}
```

Key insight: The function takes `ship+0x2C4` as the second parameter, which is the **PowerSubsystem** pointer. It reads the PowerSubsystem's max HP and applies that as damage -- effectively **one-shotting the reactor**. The `force_kill=1` flag (5th parameter) ensures the damage goes through regardless of protection states.

---

## DoDamageToSelf_Inner (FUN_005AF4A0) -- Decompiled + Annotated

```c
float10 __thiscall DoDamageToSelf_Inner(
    void *ship,               // this = ship object
    void *subsystem,          // PowerSubsystem or target subsystem
    float damageAmount,       // amount of damage to apply (= maxHP for self-destruct)
    int  *attacker,           // NULL for self-destruct (no attacker)
    char  force_kill          // 1 = force through protections
)
{
    // Gate 1: Is this the player's own ship AND is the ship in god mode?
    void *playerShip = FUN_004069b0();  // Get current player's ship
    if (ship == playerShip && *(char*)(g_TopWindow + 0x60) != 0) {
        // Ship is in God Mode -- refuse damage
        return 0.0f;
    }

    // Gate 2: ship+0x2EA flag (damage enabled flag)
    if (*(char*)((int)ship + 0x2EA) == 0) {
        return 0.0f;  // Damage disabled on this ship
    }

    // Read current HP and max HP
    float currentHP = *(float*)((int)subsystem + 0x30);
    float maxHP = GetMaxHP(subsystem);
    float excessDamage = currentHP - damageAmount;

    float damageApplied = 0.0f;

    if (excessDamage <= 0.0f) {
        // Damage exceeds current HP -- subsystem will die
        damageApplied = -excessDamage;  // overshoot
    } else if (force_kill == 0) {
        goto skip_to_end;
    }

    // Check if ship should auto-self-destruct (ship+0x2E9 flag)
    // This handles cascade failure: if the power subsystem dies,
    // check if the ENTIRE ship should blow up
    if (*(char*)((int)ship + 0x2E9) == 1) {
        if (IsDead(subsystem)) {
            // Power subsystem is dead -- apply total maxHP as damage
            float totalMaxHP = GetMaxHP(subsystem);
            damageApplied = 0.0f;
            force_kill = 0;
            excessDamage = totalMaxHP * DAT_00888a78;  // scale factor
        }
    }

    // Check subsystem minimum HP threshold (+0x44 flag)
    if (*(char*)((int)subsystem + 0x44) == 1) {
        float minHPRatio = GetMinHPRatio(subsystem);  // FUN_0056b960
        if ((float)excessDamage / maxHP < minHPRatio) {
            // Below minimum threshold -- force to minimum
            float minHP = (minHPRatio + DAT_00888a78) * maxHP;
            damageApplied = 0.0f;
            excessDamage = minHP;
        }
    }

    // Apply the damage
    SetCondition(subsystem, excessDamage);  // FUN_0056c470

    // If subsystem is now dead (or force_kill), trigger death chain
    if ((excessDamage <= 0.0f || force_kill != 0) && IsDead(subsystem)) {
        ShipDeathHandler(ship, attacker);  // FUN_005afea0
    }

    return damageApplied;

skip_to_end:
    return damageApplied;
}
```

### Critical Detail: SetCondition (FUN_0056C470)

When `SetCondition` is called and the subsystem's HP drops below its max, it fires a **SUBSYSTEM_HIT** event (`0x0080006B` via TGCharEvent). This is the same event type used for weapon damage -- meaning self-destruct damage flows through the exact same notification pipeline as combat damage.

```c
// Inside SetCondition, when HP < maxHP:
TGCharEvent *event = new TGCharEvent();
event->source = NULL;
event->dest = subsystem->parentShip;  // ship+0x40
event->eventType = 0x0080006B;        // ET_SUBSYSTEM_HIT
event->charData = subsystem->objectID; // +0x04
PostEvent(g_EventManager, event);
```

---

## ShipDeathHandler (FUN_005AFEA0) -- What Happens After Death

After `DoDamageToSelf_Inner` applies lethal damage, `ShipDeathHandler` at `0x005AFEA0` fires. This function:

1. **Gate checks**: ship+0x14C (hull HP) must be >= some threshold (DAT_008e5c18), and ship+0x150 (already-dying flag) must be false
2. **Clears special state**: ship+0x244 = 0
3. **Plays death effects**: `FUN_005ae1b0(ship, 0)` -- explosion visuals/sounds
4. **Cleanup**: `FUN_005b0bb0` (ship state), `FUN_005af460` (subsystem shutdown), `FUN_005ac250` (AI removal)
5. **Creates OBJECT_EXPLODING event** (TGEvent, event type `0x0080004E`):
   - `dest = ship` (the dying ship)
   - `charData = ship->hullHP` (at +0x14C)
   - Posts to `g_EventManager` (at `0x0097F838`)
6. **Sets attacker info**: If there is a subsystem reference (attacker's weapon system), stores attacker's object ID into `event[10]`

The OBJECT_EXPLODING event then triggers:
- **Scoring** (Python `ObjectKilledHandler` in mission scripts)
- **Network forwarding** via HostEventHandler -> opcode 0x06 to "NoMe" group
- **Visual destruction** on all clients

### Multiplayer Event Flow After Death

In multiplayer (host side), the OBJECT_EXPLODING event is handled by the registered `HostEventHandler` (0x006A1150), which serializes it as opcode 0x06 (PythonEvent) and sends it to the "NoMe" network group (all peers except self). This is how all clients learn the ship has died.

For self-destruct specifically, the attacker pointer is **NULL** (passed as NULL from `DoDamageToSelf`), so:
- `FiringPlayerID` = 0 in the event
- The scoring system sees `iFiringPlayerID == 0` and awards no kill credit
- A death IS counted for the self-destructing player
- In Mission5 (team mode), self-destruct awards a kill to the **opposing team** (lines 797-809 of Mission5.py)

---

## DestroyObject Handler (Opcode 0x14, FUN_006a01e0) -- Ship Removal

After the explosion sequence completes, the host sends opcode 0x14 (DestroyObject) to remove the object from all clients. The handler:

```c
void Handler_DestroyObject_0x14(void *param_1)
{
    // Read object data from stream
    int streamResult = FUN_006b8530(param_1, &param_1);

    // Create TGObjectList for multi-object cleanup
    TGObjectList list;
    FUN_006cefe0(&list);
    FUN_006cf180(&list, streamResult + 1, (int)param_1 - 1);

    int objectID = FUN_006cf6a0(&list);
    int *objectPtr = FUN_00434e00(NULL, objectID);  // Look up object by ID

    if (objectPtr != NULL) {
        if (objectPtr[8] == NULL) {
            // No parent set -- direct cleanup
            int *subsysPtr = FUN_0059fd30(objectPtr);  // Get subsystem
            if (subsysPtr != NULL) {
                // Call vtable+0x138: subsystem teardown
                (*(code **)(*(int*)subsysPtr + 0x138))(1, 0);
            }
            // Call vtable+0x00: destructor
            (*(code **)*objectPtr)(1);
        } else {
            // Has parent set -- remove from set
            // vtable+0x5C: RemoveFromSet
            (*(code **)(*(int*)objectPtr[8] + 0x5C))(objectID);
        }
    }

    // Cleanup list
    FUN_006cf120(&list);
}
```

---

## All Callers of DoDamageToSelf (FUN_005af5f0)

There are **5 call sites** for `FUN_005af5f0`, revealing all paths that can trigger the self-destruct damage:

| Call Site | Context | When |
|-----------|---------|------|
| 0x0050D132 | `TopWindow::SelfDestructHandler` | Player presses Ctrl+D (local path: SP or MP-host) |
| 0x006A01D3 | `HostMsgHandler` (opcode 0x13) | Host receives self-destruct request from client |
| 0x005AFD56 | Ship damage handler (sub of larger function) | Part of cascading damage / shield failure path |
| 0x006A0E18 | MultiplayerGame player slot reset | Ship destruction during player slot cleanup/respawn |
| 0x005B355B | Ship linked-list iteration | Loop iterating subsystems, applying damage (cascade?) |

The first two are the self-destruct initiation paths. The last three are internal engine uses where the same "apply lethal damage via PowerSubsystem" primitive is reused.

---

## TopWindow::SelfDestructHandler (0x0050D070) -- Full Reconstruction

Based on the disassembly, here is the complete handler logic:

```c
void __thiscall TopWindow_SelfDestructHandler(void *this, void *pEvent)
{
    // Path 1: Host in multiplayer
    if (g_IsHost != 0) {
        if (g_IsMultiplayer != 0) {
            // Host in MP -- apply damage directly to own ship
            void *playerShip = FUN_004069b0();  // Get player's ship
            if (playerShip != NULL) {
                void *powerSS = *(void**)((int)playerShip + 0x2C4);
                FUN_005af5f0(playerShip, powerSS);  // DoDamageToSelf
            }
        }
        // else: Host in SP mode -- fall through to SP path
    }

    // Path 2: Not host (client) AND multiplayer
    else if (g_IsMultiplayer != 0) {
        // NETWORK PATH: Send opcode 0x13 to host
        TGNetwork *network = g_TGWinsockNetwork;  // 0x97fa78
        if (network != NULL) {
            TGMessage *msg = AllocAndConstruct_TGMessage(0x40);
            byte opcode = 0x13;
            BufferCopy(msg, &opcode, 1);  // Write 1 byte: opcode 0x13

            int hostID = *(int*)(network + 0x20);  // Host connection ID
            TGNetwork_SendTGMessage(network, hostID, msg, 0);
        }

        // CallNextHandler
        CallNextHandler(this, pEvent);
        return;
    }

    // Path 3: Single-player (IsHost==0, IsMp==0)
    else {
        // Check TestMenuState != 2 and != 3 (guard against certain game states)
        int clock = *(int*)0x9a09d0;
        int menuState = *(int*)(clock + 0x8C);
        if (menuState == 2 || menuState == 3) {
            // In menu state 2 or 3 -- don't allow self-destruct
            goto end;
        }

        // Apply damage locally
        void *playerShip = FUN_004069b0();
        if (playerShip != NULL) {
            void *powerSS = *(void**)((int)playerShip + 0x2C4);
            FUN_005af5f0(playerShip, powerSS);
        }
    }

end:
    // CallNextHandler
    CallNextHandler(this, pEvent);
}
```

### Three Execution Paths

1. **Single-player** (IsHost=0, IsMp=0): Direct local damage via PowerSubsystem. Gated by TestMenuState != 2/3.
2. **Multiplayer host** (IsHost=1, IsMp=1): Direct local damage (host is authoritative, no need to send to self).
3. **Multiplayer client** (IsHost=0, IsMp=1): Sends 1-byte network message (opcode 0x13) to host. Host applies damage on next receive.

---

## AI Self-Destruct (PlainAI/SelfDestruct.py)

A separate, parallel implementation exists for AI-controlled ships. The `SelfDestruct` AI module at `reference/scripts/AI/PlainAI/SelfDestruct.py` uses a completely different mechanism:

```python
class SelfDestruct(BaseAI.BaseAI):
    def Update(self):
        pObject = self.pCodeAI.GetObject()
        pShip = App.ShipClass_Cast(pObject)
        if pShip:
            pHull = pShip.GetHull()
            if pHull:
                pShip.DestroySystem(pHull)  # 100% damage to hull
                bDead = 1
        if not bDead:
            pObject.SetDeleteMe(1)  # Fallback: just delete
```

This uses `pShip.DestroySystem(hull)` rather than the PowerSubsystem path. It is used in campaign missions:
- **E3M4** (Maelstrom Episode 3 Mission 4): `E3M4SelfDestructAI.py` -- T'Awsun ship self-destructs
- **E3M2**: `ProbeDestructAI.py` -- probe self-destructs
- **E4M5/E4M6**: `DestructAI.py` -- ships self-destruct

---

## Python PlayerSelfDestruct (COMMENTED OUT)

`TacticalInterfaceHandlers.py` line 97-123 contains a **commented-out** Python handler:

```python
#def PlayerSelfDestruct(pObject, pEvent):
#   pShip = MissionLib.GetPlayer()
#   if (pShip):
#       pShip.DamageSystem(pShip.GetHull(), pShip.GetHull().GetMaxCondition())
#
#   pObject.CallNextHandler(pEvent)
```

This was an earlier prototype that applied hull damage directly. It was superseded by the C++ `TopWindow::SelfDestructHandler` which uses the PowerSubsystem path instead. The key differences:
- Python version: `DamageSystem(hull, maxCondition)` -- damages hull directly
- C++ version: `DoDamageToSelf(ship, powerSubsystem)` -- destroys the reactor, which cascades

The C++ version is more thorough because destroying the PowerSubsystem triggers cascade failure of all powered subsystems.

---

## Event Registration

The SelfDestructHandler is registered in `FUN_0050ca50`:

```c
FUN_006d92b0(&DAT_00987878, 0x8001DD, "TopWindow::SelfDestructHandler");
```

Where:
- `0x00987878` = TopWindow event handler table
- `0x8001DD` = ET_INPUT_SELF_DESTRUCT event type
- The handler function is at `0x0050D070` (registered via `FUN_006da130` in `FUN_0050c8b0`)

Keyboard binding (all language variants):
```python
App.g_kKeyboardBinding.BindKey(App.WC_CTRL_D, App.TGKeyboardEvent.KS_KEYDOWN,
                                App.ET_INPUT_SELF_DESTRUCT, 0, 0)
```

---

## Scoring Implications

When a ship self-destructs in multiplayer:

1. `FiringPlayerID` = 0 (no attacker, since attacker is NULL)
2. **No kill credit** awarded to any player (the `iFiringPlayerID != 0` check in scoring handlers)
3. **Death IS counted** for the self-destructing player (deaths always counted for `iKilledPlayerID`)
4. **In team mode** (Mission5): If the self-destructing player is an Attacker (team 0), a kill is awarded to the Defending team (team 1) -- see Mission5.py lines 797-809:
   ```python
   else:
       # Self destruct?  Collision?  Still award a team kill
       if (g_kTeamDictionary.has_key(iKilledPlayerID)):
           iKilledTeam = g_kTeamDictionary[iKilledPlayerID]
           if (iKilledTeam == 0):  # Attacking team died
               # award a kill to the defending team
               iTeamKills = g_kTeamKillsDictionary.get(1, 0) + 1
               g_kTeamKillsDictionary[1] = iTeamKills
   ```

---

## Summary: Self-Destruct Pipeline

```
Ctrl+D
  -> ET_INPUT_SELF_DESTRUCT (0x8001DD)
    -> TopWindow::SelfDestructHandler (0x0050D070)
      -> [if client] Send opcode 0x13 to host
      -> [if host/SP] DoDamageToSelf(ship, ship+0x2C4)
        -> DoDamageToSelf_Inner(ship, powerSS, maxHP, NULL, force=1)
          -> SetCondition(powerSS, 0)
            -> ET_SUBSYSTEM_HIT (0x0080006B) event
          -> ShipDeathHandler (0x005AFEA0)
            -> ET_OBJECT_EXPLODING (0x0080004E) event
              -> [MP] HostEventHandler -> opcode 0x06 -> "NoMe" group
              -> [MP] Python ObjectKilledHandler -> SCORE_CHANGE_MESSAGE
              -> [all] Explosion visuals/sounds
            -> DestroyObject -> opcode 0x14 -> all clients
```

Total latency in MP: ~1 network round-trip (client sends 0x13, host processes, state updates propagate on next tick).

---

## Appendix: Related Event Types

| Event Type | Name | Role in Self-Destruct |
|------------|------|----------------------|
| 0x8001DD | ET_INPUT_SELF_DESTRUCT | Input trigger (keyboard) |
| 0x0080006B | ET_SUBSYSTEM_HIT | Fired when PowerSubsystem HP changes |
| 0x0080004E | ET_OBJECT_EXPLODING | Fired when ship dies (triggers scoring + visuals) |
| 0x00800050 | ET_COLLISION_EFFECT | NOT involved in self-destruct |
| 0x008000DF | ET_ADD_TO_REPAIR_LIST | NOT involved (damage is instant-lethal) |
