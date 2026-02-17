# Cloaking Device State Machine - Complete Reverse Engineering Analysis

## Overview

The CloakingSubsystem is a PoweredSubsystem subclass that manages ship cloaking in STBC.
It uses a state machine with a transition timer, interacts with shields through a delayed
re-enable mechanism, and controls ship visibility through NiNode alpha manipulation.

**Vtable**: `0x00892EAC` (CloakingSubsystem)
**Parent vtable**: `0x00892D98` (parent class, set by FUN_00562240)
**Constructor**: `FUN_00566d10`
**Destructor**: `FUN_00566e50` (scalar deleting)

## Object Layout

```
Offset  Size  Type    Field                   Notes
------  ----  ------  ----------------------  -----
+0x00   4     ptr     vtable                  -> 0x00892EAC
...           ...     (inherited from PoweredSubsystem via FUN_00562240 -> FUN_0056b970)
+0x18   4     ptr     subsystem property      (inherited)
+0x34   4     float   maxPower                (inherited, used in energy check FUN_0056c350)
+0x3C   4     float   maxCondition(?)         (inherited)
+0x40   4     ptr     ownerShip               Ship* that owns this subsystem
+0x88   4     float   currentPowerDraw        (inherited, managed by FUN_00562470)
+0x8C   4     float   actualPower             (inherited)
+0x90   4     float   powerMultiplier         Init to 1.0f (inherited)
+0x94   4     float   efficiency              ratio = actualPower/maxPower (inherited)
+0x98   4     float   conditionRatio          (inherited)
+0x9C   1     byte    isOn                    PoweredSubsystem::IsOn (Enable/Disable toggle)
+0xA0   4     int     powerMode               0/1/2 (inherited)
+0xA4   1     byte    isNetworkable           (inherited, controls MP event forwarding)
+0xA8   4     ptr     cloakEffectNode         NiNode* for visual cloak effect
+0xAC   1     byte    isFullyCloaked          Set to 1 when state reaches CLOAKED(3)
+0xAD   1     byte    tryingToCloak           1=player wants cloak on, 0=wants off
+0xB0   4     int     state                   State machine value (see below)
+0xB4   4     float   timer                   Accumulates delta time during transitions
+0xB8   4     ?       (unused, init 0)
+0xBC   4     ?       (unused, init 0)
+0xC0   4     int     (init 2)                Possibly render mode
+0xC4   4     ?       (init 0)
+0xC8   4     ?       (init 0)
```

Ship stores the CloakingSubsystem pointer at **ship+0x2DC**.

## State Machine

### Active States (4 states, verified)

| Value | Name        | Timer Behavior           | Entered From          | Exits To               |
|-------|-------------|--------------------------|----------------------|-------------------------|
| 0     | DECLOAKED   | timer irrelevant         | FUN_0055f7f0         | state 2 (via tick)      |
| 2     | CLOAKING    | timer counts UP by dt    | FUN_0055f110(cloak)  | state 3 (timer full)    |
| 3     | CLOAKED     | timer irrelevant         | FUN_0055f6d0         | state 5 (via tick)      |
| 5     | DECLOAKING  | timer counts DOWN by dt  | FUN_0055f110(declk)  | state 0 (timer empty)   |

### Ghost States (never assigned, dead code)

States 1 and 4 are checked in `IsCloaking()` and `IsDecloaking()` SWIG wrappers and in
the visibility function FUN_0055ee10, but are **never written** to `+0xB0` anywhere in the
binary. They are vestiges of a planned 6-state design that was collapsed to 4 active states.

- State 1: checked alongside state 2 in `IsCloaking` (returns true for 1 or 2)
- State 4: checked alongside state 5 in `IsDecloaking` (returns true for 4 or 5)

### State Transition Diagram

```
  StartCloaking()           timer reaches 1.0        StopCloaking()         timer reaches 0.0
  FUN_0055f360         FUN_0055f6d0              FUN_0055f380          FUN_0055f7f0
       |                     |                        |                     |
  DECLOAKED(0) ---> CLOAKING(2) ---> CLOAKED(3) ---> DECLOAKING(5) ---> DECLOAKED(0)
       ^                                                                    |
       +--------------------------------------------------------------------+

  Also: CLOAKED(3) ---> DECLOAKING(5) via energy failure (efficiency < threshold in tick)
```

## Transition Timer

**Global**: `DAT_008e4e1c` = CloakTime (float, settable via `CloakingSubsystem_SetCloakTime`)
**Global**: `DAT_008e4e20` = ShieldDelay (float, settable via `CloakingSubsystem_SetShieldDelay`)

Both are **class-level globals**, NOT per-instance fields. All cloaking devices in the game
share the same CloakTime and ShieldDelay values.

**Default values**: These are set from the .rdata section. Without runtime Python modification,
both remain at their compiled-in defaults. The SetCloakTime/SetShieldDelay SWIG wrappers
allow Python scripts to override them at runtime.

### Tick Function: FUN_0055e500

```c
// FUN_0055e500(this, deltaTime) -- CloakingSubsystem::Update
void CloakingSubsystem_Update(CloakingSubsystem* this, float deltaTime)
{
    // Call parent tick (PoweredSubsystem::Update)
    FUN_00562470(this, deltaTime);

    int state = this->state;  // +0xB0

    if (state == 2) {  // CLOAKING
        // Timer counts UP
        this->timer += deltaTime;                    // +0xB4
        float progress = this->timer / CloakTime;   // DAT_008e4e1c

        if (progress >= 1.0f) {
            progress = 1.0f;
            CloakComplete(this);     // FUN_0055f6d0 -> state=3
        }
    }
    else if (state == 5) {  // DECLOAKING
        // Timer counts DOWN
        this->timer -= deltaTime;                    // +0xB4
        float progress = this->timer / CloakTime;

        if (progress <= 0.0f) {
            progress = 0.0f;
            DecloakComplete(this);   // FUN_0055f7f0 -> state=0
        }
    }
    else {
        goto check_intents;
    }

    // Update visual transparency
    UpdateVisibility(this, progress);   // FUN_0055e640

check_intents:
    // Only if +0x9C (isOn) is true
    if (!this->isOn) {
        // Call parent tick again (energy recalculation)
        FUN_00562470(this, deltaTime);
        return;
    }

    state = this->state;
    bool notInCloakChain = (state != 1 && state != 2 && state != 3);
    bool inCloakChain = (state != 4 && state != 5 && state != 0);
    // Note: effectively notInCloakChain = (state==0||state==4||state==5)
    //                    inCloakChain = (state==1||state==2||state==3)

    if (this->tryingToCloak == 1 && notInCloakChain) {
        // Wants to cloak and not already cloaking
        BeginCloaking(this, 1);    // FUN_0055f110(this, 1) -> state=2
        return;
    }

    if (this->tryingToCloak == 0 || !inCloakChain) {
        if (state != 3) return;     // Not fully cloaked, nothing to do
        if (this->efficiency >= ENERGY_THRESHOLD) return;  // DAT_0088d4ec
        // Energy failure: force decloak
        StopCloaking(this);    // FUN_0055f380
    }

    BeginDecloaking(this, 0);  // FUN_0055f110(this, 0) -> state=5
}
```

### Key Transition Functions

#### FUN_0055f360 - StartCloaking (user-facing)
Address: `0x0055f360`
```c
void CloakingSubsystem_StartCloaking(this) {
    this->vtable[0x7C/4]();   // virtual call (likely base class StartCloaking hook)
    this->tryingToCloak = 1;  // +0xAD = 1
    // Actual state transition happens in next tick via check_intents
}
```

#### FUN_0055f380 - StopCloaking (user-facing)
Address: `0x0055f380`
```c
void CloakingSubsystem_StopCloaking(this) {
    if (this->state == 1 || this->state == 2 || this->tryingToCloak == 1) {
        BeginDecloaking(this, 0);   // FUN_0055f110(this, 0)
    }
    this->tryingToCloak = 0;        // +0xAD = 0
    this->vtable[0x80/4]();         // virtual call (likely base class StopCloaking hook)
}
```

#### FUN_0055f110 - BeginCloaking/BeginDecloaking (internal)
Address: `0x0055f110`

When `param_1 == 1` (cloaking):
1. Checks energy via FUN_0056c350 (recursive power check)
2. If insufficient energy, returns without transition
3. Creates NiTimeController animation sequences
4. If ship has a shield subsystem (ship+0x2C0), creates a delayed shield-hide event
   with event 0x0080007B and delay = ShieldDelay (`_DAT_008e4e20`)
5. Creates/starts a "Cloak" sound effect (string "Cloak" at 0x008e42c8)
6. Sets state = 2 (CLOAKING), timer = 0
7. Calls FUN_0055f660 -> state=2, plays "Cloak" animation on NiNode

When `param_1 == 0` (decloaking):
1. Posts ET_DECLOAK_BEGINNING event (0x00800079)
2. If state != 2 (not mid-cloak), sets timer = CloakTime (to count down from max)
3. Sets state = 5 (DECLOAKING)
4. Calls FUN_0055f770 -> state=5, plays "Uncloak" animation

#### FUN_0055f6d0 - CloakComplete (timer finished)
Address: `0x0055f6d0`
```c
void CloakComplete(this) {
    this->state = 3;                // CLOAKED
    // Post ET_CLOAK_BEGINNING event (0x00800078)
    this->isFullyCloaked = 1;       // +0xAC = 1
    // Make ship invisible: ship->sceneNode->vtable[0x50](1)
}
```

#### FUN_0055f7f0 - DecloakComplete (timer finished)
Address: `0x0055f7f0`
```c
void DecloakComplete(this) {
    this->state = 0;                // DECLOAKED
    // Post ET_DECLOAK_COMPLETED event (0x0080007A)

    // If ship has shield subsystem (ship+0x2C0):
    //   Create delayed event 0x0080007B at time = gameTime + ShieldDelay
    //   This re-enables the shield visual (flag |= 0x01)
    //   If shield HP <= 0, reset shield to 1.0 HP

    RestoreNiNode(this);            // FUN_0055e800
}
```

## Event IDs

| ID           | Name                  | Fired When                          |
|--------------|-----------------------|-------------------------------------|
| 0x008000E3   | ET_START_CLOAKING     | Network opcode 0x0E received        |
| 0x008000E5   | ET_STOP_CLOAKING      | Network opcode 0x0F received        |
| 0x00800078   | ET_CLOAK_BEGINNING    | CloakComplete: state -> CLOAKED(3)  |
| 0x00800079   | ET_DECLOAK_BEGINNING  | BeginDecloaking: state -> DECLOAKING(5) |
| 0x0080007A   | ET_DECLOAK_COMPLETED  | DecloakComplete: state -> DECLOAKED(0)  |
| 0x0080007B   | (shield visibility)   | Delayed timer event for shield show/hide |
| 0x0080006C   | ET_SUBSYSTEM_STATUS   | Subsystem enabled/disabled           |

## Shield Interaction

### Cloaking (shields go down)

When cloaking begins (FUN_0055f110, param=1):
1. **Shields do NOT immediately drop to 0 HP**
2. Instead, a **delayed event** (0x0080007B) is scheduled with the ship's shield subsystem
   at `ship+0x2C0` as the target. The delay is `ShieldDelay` (`_DAT_008e4e20`)
3. The event has flag `0xFEFF` (bit 8 cleared = non-persistent), meaning the shield
   visual element fades out over the ShieldDelay period
4. The shield subsystem itself is **disabled** via the PoweredSubsystem mechanism:
   - FUN_0055e6b0 (called from FUN_0055f3e0/InstantCloak and FUN_0055f660/CloakingComplete)
     calls `FUN_00593270(ownerShip)` which manipulates the ship's scene graph
   - This effectively turns off shield rendering and prevents shield recharge

### Decloaking (shields come back)

When decloaking completes (FUN_0055f7f0):
1. A **delayed event** (0x0080007B) with flag `|= 0x01` (persistent/enable) is created
2. The event fires at `gameTime + ShieldDelay` -- shields don't return instantly
3. If the shield HP was at or below 0, it gets reset to 1.0
4. The shield subsystem re-enables and begins recharging normally

### Summary

- **During cloak**: Shields are functionally disabled (no absorption, no recharge, hidden)
- **Shield HP is NOT zeroed**: The HP value is preserved, but the subsystem is turned off
- **Re-enable delay**: After decloaking completes (state=0), there is an additional
  `ShieldDelay` seconds before shields become active again
- **All logic is in the cloak code**: FUN_0055f110, FUN_0055f3e0, FUN_0055f7f0.
  The shield code itself does not check cloak state.

## Weapon Interaction

### How weapons are gated by cloak state

Weapon firing is **NOT directly gated by cloak state in C++ weapon code**. Instead:

1. **WeaponSystem::CanFire** (`swig_WeaponSystem_CanFire`) reads a byte at
   `weaponSystem+0xAB`. This is a simple field read, not a computed check.

2. **Weapon::CanFire** (`swig_Weapon_CanFire`) calls `vtable[0x84/4]` -- a virtual
   function that each weapon type implements.

3. The connection between cloak and weapons happens through **subsystem disable**:
   - When cloaking begins, `FUN_00562630` (DisableSubsystem) is called with
     event 0x0080006C (ET_SUBSYSTEM_STATUS)
   - This sets `+0x9C = 0` (isOn = false) on affected subsystems
   - The `PoweredSubsystem::StateChangedHandler` (FUN_00562730) propagates this

4. **The critical check is at the AI/Python level**: The game's AI and UI code checks
   `ShipClass_IsCloaked()` before initiating weapon fire:
   ```python
   # From AI/Preprocessors.py
   pCloakSystem = pShip.GetCloakingSubsystem()
   if pCloakSystem:
       if pCloakSystem.IsCloaked():
           continue  # Skip this target
   ```

5. **ShipClass::IsCloaked** (FUN_005ac450) checks:
   ```c
   CloakingSubsystem* cloak = ship->cloakSubsystem;  // ship+0x2DC
   if (cloak == NULL) return false;
   return cloak->isFullyCloaked;  // +0xAC == 1
   ```
   Note: This returns true ONLY when state==3 (CLOAKED), not during transitions.

### Network handling

The multiplayer cloak opcodes go through the same generic event forwarder FUN_0069fda0:
- Opcode 0x0E -> event 0x008000E3 (ET_START_CLOAKING) -> CloakingSubsystem::StartCloakingHandler
- Opcode 0x0F -> event 0x008000E5 (ET_STOP_CLOAKING) -> CloakingSubsystem::StopCloakingHandler

These handlers are registered in FUN_0055e4d0:
```c
RegisterHandler(0x008000E3, "CloakingSubsystem::StartCloakingHandler");
RegisterHandler(0x008000E5, "CloakingSubsystem::StopCloakingHandler");
```

The actual handler (FUN_00549a50) is the bridge between events and the subsystem:
```c
void CloakEventHandler(TGEvent* event) {
    Ship* playerShip = GetPlayerShip();
    CloakingSubsystem* cloak = playerShip->cloakSubsystem;  // +0x2DC via offset 0xB7*4
    int eventData = GetEventData(event);  // FUN_005494f0
    if (cloak && eventData) {
        if (eventData->field_0x174 == 0) {
            StartCloaking(cloak);    // FUN_0055f360
        } else {
            StopCloaking(cloak);     // FUN_0055f380
        }
    }
}
```

### Network StateUpdate (0x40 flag)

The cloak state is serialized in the StateUpdate packet (FUN_005b17f0) as dirty flag 0x40:

**Writer** (server side, at 0x005b1c48):
```c
CloakingSubsystem* cloak = ship->cloakSubsystem;  // ship+0x2DC
if (cloak != NULL) {
    byte currentState = cloak->isOn;     // +0x9C (PoweredSubsystem::IsOn)
    if (currentState != prevCloakState) {
        dirtyFlags |= 0x40;
        prevCloakState = currentState;
    }
}
```

**Serialized** (at 0x005b1e4a):
```c
if (flags & 0x40) {
    if (ship->cloakSubsystem != NULL) {
        WriteBit(stream, cloakSubsystem->isOn);  // +0x9C
    }
}
```

**Reader** (client side, at 0x005b2660):
```c
if (flags & 0x40) {
    bool cloakOn = ReadBit(stream);
    if (cloakOn)  StartCloaking(cloak);   // FUN_0055f360
    else          StopCloaking(cloak);    // FUN_0055f380
}
```

**Important**: The network serializes the `isOn` byte (+0x9C), NOT the state machine
value (+0xB0). This means the client receives a boolean cloak on/off and runs its own
local state machine transitions, including the visual effects and timer.

## Visual Effect System

### FUN_0055e640 - UpdateVisibility
Address: `0x0055e640`

Called with `progress` (0.0 to 1.0) during transitions:
```c
void UpdateVisibility(this, float progress) {
    if (progress < 0.0f || progress > 1.0f) return;

    Ship* ship = this->ownerShip;
    if (ship == GetPlayerShip()) {
        // For the player's own ship, update cloak effect node
        NiNode* effectNode = this->cloakEffectNode;  // +0xA8
        effectNode->field_0x120 = progress * ALPHA_SCALE;  // DAT_0088ba90
        effectNode->field_0xD4++;
    }

    // Update scene graph alpha for all child nodes
    UpdateNodeAlpha(this, 1.0f - progress, ship->sceneNode);  // FUN_0055ee10
}
```

### FUN_0055ee10 - UpdateNodeAlpha (recursive)
Address: `0x0055ee10`

This is the visual transparency function. It walks the ship's NiNode tree and adjusts
alpha on NiMaterialProperty nodes based on cloak state:

- **States 1/2 or isFullyCloaked**: Cloaking effect
  - If progress <= threshold: alpha = random * progress (shimmer effect)
  - If progress > threshold: alpha = (progress - threshold + random_offset) * progress

- **States 4/5**: Decloaking effect
  - alpha = (progress * scale - threshold + random_offset) * progress
  - Clamped to [0.0, 1.0]

- Uses `rand()` for shimmer/ripple visual effect during transitions
- DAT_0088c5ac = shimmer threshold
- DAT_00892c94 = random scale factor
- DAT_00892c90 = decloak scale factor
- DAT_0088cb58 = alpha offset

## Multiplayer Event Registration

From FUN_0069e590 (MultiplayerGame constructor):
```c
RegisterHandler(ET_START_CLOAKING(0x008000E2), "MultiplayerGame::StartCloakingHandler");
RegisterHandler(ET_STOP_CLOAKING(0x008000E4), "MultiplayerGame::StopCloakingHandler");
```

Note: The MultiplayerGame registers for 0x008000E2 and 0x008000E4 (different from the
subsystem's 0x008000E3 and 0x008000E5). These are the _notify_ versions:
- 0x008000E2 = ET_START_CLOAKING (request from player)
- 0x008000E3 = ET_START_CLOAKING_NOTIFY (forwarded to subsystem)
- 0x008000E4 = ET_STOP_CLOAKING (request from player)
- 0x008000E5 = ET_STOP_CLOAKING_NOTIFY (forwarded to subsystem)

The MultiplayerGame handlers convert local cloak events into network opcodes 0x0E/0x0F.

## Energy Failure Auto-Decloak

In the tick function, when state == 3 (CLOAKED):
```c
if (this->efficiency < ENERGY_THRESHOLD) {  // DAT_0088d4ec
    StopCloaking(this);                      // FUN_0055f380
    BeginDecloaking(this, 0);                // -> state=5
}
```

The efficiency field (+0x94) is computed by the parent PoweredSubsystem::Update as
`actualPower / maxPower`. If the ship's power grid cannot sustain the cloaking device,
efficiency drops below the threshold and the cloak automatically fails.

## Collision While Cloaked

The event `ET_CLOAKED_COLLISION` (0x00910A60) exists in the string table but has
**0 xrefs** -- it is dead/unused content. Collisions while cloaked are handled through
the normal collision damage pipeline with no special cloaked-collision logic.

## Function Address Summary

| Address    | Name                                    | Role                                |
|------------|-----------------------------------------|-------------------------------------|
| 0x00566d10 | CloakingSubsystem::ctor                 | Constructor, inits all fields       |
| 0x00566e50 | CloakingSubsystem::dtor                 | Destructor, frees linked lists      |
| 0x0055e500 | CloakingSubsystem::Update (tick)        | State machine + timer + energy check|
| 0x0055f360 | StartCloaking (user-facing)             | Sets tryingToCloak=1                |
| 0x0055f380 | StopCloaking (user-facing)              | Calls BeginDecloaking, tryingToCloak=0 |
| 0x0055f110 | BeginCloaking/BeginDecloaking           | Creates animations, sets state 2/5  |
| 0x0055f6d0 | CloakComplete                           | State 2->3, fires ET_CLOAK_BEGINNING|
| 0x0055f7f0 | DecloakComplete                         | State 5->0, fires ET_DECLOAK_COMPLETED, shield delay |
| 0x0055f660 | PlayCloakAnimation                      | State=2, "Cloak" sound              |
| 0x0055f770 | PlayUncloakAnimation                    | State=5, "Uncloak" sound            |
| 0x0055f3e0 | InstantCloak                            | Immediate cloak (no timer)          |
| 0x0055f560 | InstantDecloak                          | Immediate decloak (no timer)        |
| 0x0055e640 | UpdateVisibility                        | Sets alpha from progress            |
| 0x0055ee10 | UpdateNodeAlpha                         | Recursive NiNode alpha with shimmer |
| 0x0055e6b0 | SetupCloakEffect                        | Configures NiNode for cloak visual  |
| 0x0055e800 | RestoreNiNode                           | Undoes cloak visual setup           |
| 0x0055e840 | InitCloakProperties                     | Sets up NiMaterial/NiShade properties|
| 0x0055f930 | DeathWhileCloaked                       | Stops cloak + begins decloak on death|
| 0x0055f5f0 | RecalcVisibility                        | Recomputes alpha from current timer |
| 0x005ac450 | ShipClass::IsCloaked                    | Returns cloak+0xAC (isFullyCloaked) |
| 0x00549a50 | CloakEventHandler                       | Bridges events to Start/StopCloaking|
| 0x0055e4d0 | RegisterCloakHandlers                   | Registers 0xE3/0xE5 event handlers  |
| 0x0056c350 | CheckEnergyRecursive                    | Validates power for cloaking        |

## Global Constants

| Address      | Name          | Type  | Notes                                  |
|-------------|---------------|-------|----------------------------------------|
| 0x008e4e1c  | CloakTime     | float | Transition duration (Set/GetCloakTime) |
| 0x008e4e20  | ShieldDelay   | float | Shield re-enable delay (Set/GetShieldDelay) |
| 0x00888860  | FLOAT_1_0     | float | 1.0f (used as clamp max)               |
| 0x00888b54  | FLOAT_0_0     | float | 0.0f (used as clamp min)               |
| 0x0088d4ec  | ENERGY_THRESH | float | Efficiency threshold for auto-decloak  |
| 0x0088c5ac  | SHIMMER_THRESH| float | Alpha threshold for shimmer effect     |
| 0x00892c94  | RANDOM_SCALE  | float | Random multiplier for shimmer          |
| 0x00892c90  | DECLOAK_SCALE | float | Scale factor for decloak alpha         |
| 0x0088cb58  | ALPHA_OFFSET  | float | Base offset for alpha calculation      |
| 0x0088ba90  | ALPHA_SCALE   | float | Multiplier for cloak effect node alpha |

## Comparison with OpenBC Cleanroom Spec

The OpenBC spec claims 4 states: DECLOAKED=0, CLOAKING=1, CLOAKED=2, DECLOAKING=3.

**Actual findings**: The binary uses states 0, 2, 3, 5 (with ghost states 1, 4 checked
but never assigned). The mapping is:

| OpenBC Spec    | Actual Binary | Notes                              |
|----------------|---------------|------------------------------------|
| DECLOAKED=0    | 0             | Correct value                      |
| CLOAKING=1     | 2             | OpenBC wrong: actual value is 2    |
| CLOAKED=2      | 3             | OpenBC wrong: actual value is 3    |
| DECLOAKING=3   | 5             | OpenBC wrong: actual value is 5    |

The transition time claim of "3.0 seconds" cannot be verified from static analysis alone
since `DAT_008e4e1c` is a runtime-modifiable global. Its compiled-in default would need
to be read from the binary's .rdata section.
