# Power & Reactor System — Complete Reverse Engineering

Reverse-engineered from stbc.exe via objdump disassembly, SWIG wrapper analysis, and cross-referenced against shipped hardpoint scripts. All addresses verified against the game binary.

For the clean-room behavioral specification (no addresses, suitable for reimplementation), see the OpenBC repository at `../OpenBC/docs/power-system.md`.

---

## Overview

Bridge Commander's power system uses a three-class architecture:

1. **PowerSubsystem** — the physical warp core/reactor. A ShipSubsystem that stores HP, can be damaged, and whose condition scales power output. Does NOT inherit from PoweredSubsystem.
2. **PoweredSubsystem** — base class for all power-consuming subsystems (shields, engines, weapons, etc.). Each consumer draws power per-frame from the master distributor.
3. **"Powered" master** — a special PoweredSubsystem instance at ship+0x2B0 that acts as the EPS (Electro-Plasma System) distributor. Manages batteries, conduit limits, and the consumer list. Runs the main power simulation tick once per second.

The power flow is: **Reactor generates → Main battery stores → Powered distributor allocates → Each PoweredSubsystem draws**.

---

## Class Hierarchy

```
ShipSubsystem (vtable 0x892FC4)
  │
  ├── PowerSubsystem (vtable 0x892C98)         ← Reactor / "Warp Core"
  │     ctor: FUN_00560470
  │     named slot: ship+0x2C4
  │     type ID: 0x8138
  │     DOES NOT inherit from PoweredSubsystem
  │     DOES NOT override Update (uses base ShipSubsystem::Update)
  │
  └── PoweredSubsystem (vtable 0x892D98)        ← Base for all powered systems
        ctor: FUN_00562240 → FUN_0056b970
        Update: FUN_00562470 (vtable slot 25)
        │
        ├── "Powered" distributor (vtable 0x88A1F0) ← Master power manager / EPS grid
        │     named slot: ship+0x2B0
        │     type ID: 0x813E
        │     Update override: FUN_00563780 (MAIN POWER SIMULATION)
        │
        ├── ShieldGenerator (vtable 0x893598)
        ├── PhaserController (vtable 0x893240)
        ├── SensorArray (vtable 0x893040)
        ├── ImpulseEngineSubsystem (vtable 0x892FC4)
        ├── WarpEngineSubsystem (vtable 0x892E24)
        ├── RepairSubsystem (vtable 0x892F34)
        ├── CloakingSubsystem (vtable 0x892EAC)
        ├── TractorBeamSystem (vtable 0x8936F0)
        ├── TorpedoSystem (vtable 0x893630)
        └── PulseWeaponSystem (vtable 0x893794)
```

**Key architectural insight**: The reactor (ship+0x2C4) and the EPS distributor (ship+0x2B0) are separate objects. The reactor has its own HP (7,000 on Sovereign) and its condition percentage scales the power output. The EPS distributor manages the actual batteries and power delivery. Both are created from the same `PowerProperty` hardpoint definition — the reactor inherits its MaxCondition and position, while the distributor inherits the battery/conduit/output parameters.

---

## PowerProperty Field Offsets

PowerProperty is the read-only template created by `App.PowerProperty_Create()` in hardpoint scripts. It stores the 5 core power parameters.

| Offset | Type | Field | Setter Method |
|--------|------|-------|---------------|
| +0x48 | float | MainBatteryLimit | SetMainBatteryLimit() |
| +0x4C | float | BackupBatteryLimit | SetBackupBatteryLimit() |
| +0x50 | float | MainConduitCapacity | SetMainConduitCapacity() |
| +0x54 | float | BackupConduitCapacity | SetBackupConduitCapacity() |
| +0x58 | float | PowerOutput | SetPowerOutput() |

Example (Sovereign): MainBattery=200,000, BackupBattery=100,000, MainConduit=1,450, BackupConduit=250, PowerOutput=1,200.

---

## PowerSubsystem (Reactor) Runtime Layout

vtable at 0x892C98. Named slot: ship+0x2C4. This is the physical reactor — it takes damage and its HP affects power output.

| Offset | Type | Field | Notes |
|--------|------|-------|-------|
| +0x00 | ptr | vtable | 0x892C98 |
| +0x18 | ptr | property | PowerProperty* (read-only template) |
| +0x30 | float | condition | Current HP (float, not percentage) |
| +0x34 | float | conditionPct | condition / maxCondition (0.0–1.0) |

The reactor itself does NOT store batteries or manage distribution. It serves as a health-scalable proxy — `GetPowerOutput()` returns `property+0x58 * conditionPct`.

---

## "Powered" Master (EPS Distributor) Runtime Layout

vtable at 0x0088A1F0. Named slot: ship+0x2B0. This is the central power management object.

| Offset | Type | Field | Notes |
|--------|------|-------|-------|
| +0x00 | ptr | vtable | 0x0088A1F0 |
| +0x18 | ptr | property | PowerProperty* |
| +0x30 | float | condition | Current HP |
| +0x34 | float | conditionPct | Health ratio (0.0–1.0) |
| +0x40 | ptr | ownerShip | Ship* that owns this subsystem |
| +0x88 | 12 | mainBatteryWatcher | FPU watcher for main battery |
| +0x94 | 12 | backupBatteryWatcher | FPU watcher for backup battery |
| +0xA0 | float | availablePower | Total power available for consumption |
| +0xA4 | float | mainConduitCurrent | Main conduit power remaining this interval |
| +0xA8 | float | backupConduitCurrent | Backup conduit power remaining this interval |
| +0xAC | float | mainBatteryPower | Current main battery charge level |
| +0xB0 | float | mainBatteryPct | mainBatteryPower / mainBatteryLimit |
| +0xB4 | float | backupBatteryPower | Current backup battery charge level |
| +0xB8 | float | backupBatteryPct | backupBatteryPower / backupBatteryLimit |
| +0xBC | float | powerDispensed | Total power dispensed this tick |
| +0xC0 | float | lastUpdateTime | For elapsed time calculation |
| +0xC4 | int | consumerCount | Number of registered power consumers |
| +0xC8 | ptr | consumerListHead | Linked list of PoweredSubsystem* |
| +0xCC | ptr | consumerListTail | |
| +0xD0 | ptr | freeListHead | Pool allocator for list nodes |

Consumer list node layout: `[subsystem_ptr (4), prev (4), next (4)]` — 12 bytes each, allocated from pool at FUN_0054f720.

---

## PoweredSubsystem (Consumer) Field Offsets

Base class for all subsystems that consume power. These fields are inherited by shields, engines, weapons, etc.

| Offset | Type | Field | Notes |
|--------|------|-------|-------|
| +0x18 | ptr | property | Subsystem-specific property |
| +0x30 | float | condition | Current HP |
| +0x34 | float | conditionPct | condition / maxCondition |
| +0x40 | ptr | ownerShip | Ship* |
| +0x88 | float | powerReceived | Actual power received this tick |
| +0x8C | float | powerWanted | Power demanded this tick |
| +0x90 | float | powerPercentageWanted | User slider (0.0–1.0+) |
| +0x94 | float | efficiency | powerReceived / powerWanted (0.0–1.0) |
| +0x98 | float | conditionRatio | powerReceived / (normalPower * dt) |
| +0x9C | byte | isOn | Enable/disable toggle |
| +0xA0 | int | powerMode | 0=main first, 1=backup first, 2=backup only |
| +0xA4 | byte | isNetworkable | Controls MP event forwarding |

---

## Key Function Table

| Address | Name | Signature | Purpose |
|---------|------|-----------|---------|
| 0x00563780 | PoweredMaster::Update | __thiscall(float dt) | **Main power simulation tick** (once per second) |
| 0x00562470 | PoweredSubsystem::Update | __thiscall(float dt) | Per-consumer power draw (every frame) |
| 0x0056BC60 | ShipSubsystem::Update | __thiscall(float dt) | Base: condition tracking |
| 0x00560470 | PowerSubsystem::ctor | __thiscall(int param) | Reactor constructor |
| 0x005634a0 | PowerSubsystem::GetProperty | — | Returns this+0x18 |
| 0x005634b0 | PowerSubsystem::GetPowerOutput | — | property+0x58 * conditionPct |
| 0x005634c0 | PowerSubsystem::GetMainBatteryLimit | — | property+0x48 |
| 0x005634d0 | PowerSubsystem::GetBackupBatteryLimit | — | property+0x4C |
| 0x005634e0 | PowerSubsystem::GetMainConduitCapacity | — | property+0x50 (raw, not scaled) |
| 0x005634f0 | PowerSubsystem::GetMainConduitCapacity_scaled | — | property+0x50 * conditionPct |
| 0x00563520 | PowerSubsystem::GetBackupConduitCapacity | — | property+0x54 (raw, not scaled) |
| 0x00563700 | PoweredMaster::ComputeAvailablePower | __thiscall(float ticks) | Compute conduit limits and available pool |
| 0x005638d0 | PoweredMaster::AddPowerToBatteries | __thiscall(float amount) | Recharge main → overflow to backup |
| 0x00563a70 | PoweredMaster::DrawFromMainBattery | __thiscall(float wanted) | Mode 0: main first, then backup |
| 0x00563bb0 | PoweredMaster::DrawFromBackupBattery | __thiscall(float wanted) | Mode 1: backup first, then main |
| 0x00563cb0 | PoweredMaster::DrawFromBackupOnly | __thiscall(float wanted) | Mode 2: backup only |
| 0x005623D0 | PoweredSubsystem::GetNormalPowerWanted | vslot 30 | Returns property+0x48 if isOn, else 0 |
| 0x00562430 | PoweredSubsystem::SetPowerPercentageWanted | __thiscall(float pct) | Sets +0x90, rescales +0x8C |
| 0x00563ed0 | PoweredMaster::ComputeTotalPowerWanted | — | Sums NormalPowerWanted * dt across all consumers |
| 0x00563d50 | PoweredMaster::SetPowerSource | — | Adds consumer to linked list |
| 0x005644b0 | PowerSubsystem::WriteState | — | Network serialization |
| 0x00564530 | PowerSubsystem::ReadState | — | Network deserialization |

---

## Decompiled Pseudocode

### PoweredMaster::Update (FUN_00563780) — Main Power Simulation

```c
// vtable 0x0088A1F0, slot 25
// this = "Powered" subsystem at ship+0x2B0
// Runs once per INTERVAL (1.0 second, constant at 0x892e20)
void PoweredMaster_Update(PoweredMaster* this, float deltaTime) {
    // Step 1: Call base ShipSubsystem::Update (condition tracking)
    ShipSubsystem_Update(this, deltaTime);   // FUN_0056bc60

    // Step 2: Compute elapsed game time since last update
    float gameTime = g_Clock->gameTime;      // [0x9a09d0]+0x90
    if (gameTime < this->lastUpdateTime)      // +0xC0
        this->lastUpdateTime = gameTime;

    float elapsed = gameTime - this->lastUpdateTime;
    if (elapsed > INTERVAL) {                 // INTERVAL = 1.0f at 0x892e20
        this->powerDispensed = 0.0;           // +0xBC = reset per interval
        int ticks = (int)(elapsed / INTERVAL);

        if (!IsDisabled()) {                  // FUN_0056c350
            // Compute power output (scaled by reactor health)
            float powerOutput = GetPowerOutput();  // prop+0x58 * condPct
            float rechargeAmount = powerOutput * ticks;
            AddPowerToBatteries(rechargeAmount);   // FUN_005638d0
        }

        // Compute available power for this interval
        float availPower = ComputeAvailablePower(ticks);  // FUN_00563700
        this->availablePower = availPower;     // +0xA0

        // Update lastUpdateTime (wraps to prevent drift)
        this->lastUpdateTime = gameTime - fmod(elapsed, INTERVAL);
    }

    // Step 3: Update battery percentages for display/network
    this->mainBatteryPct = this->mainBatteryPower;
    if (GetMainBatteryLimit() > 0)
        this->mainBatteryPct /= GetMainBatteryLimit();

    this->backupBatteryPct = this->backupBatteryPower;
    if (GetBackupBatteryLimit() > 0)
        this->backupBatteryPct /= GetBackupBatteryLimit();

    // Step 4: Update watcher containers
    FPUWatcher_Update(&this->mainWatcher);     // +0x88
    FPUWatcher_Update(&this->backupWatcher);   // +0x94
}
```

### PoweredSubsystem::Update (FUN_00562470) — Per-Consumer Draw

```c
// Called by each powered subsystem's Update (shields, engines, weapons, etc.)
// Runs EVERY FRAME
void PoweredSubsystem_Update(PoweredSubsystem* this, float deltaTime) {
    // Step 1: Call base ShipSubsystem::Update
    ShipSubsystem_Update(this, deltaTime);

    // Step 2: Compute power wanted
    float pctWanted = this->powerPercentageWanted;  // +0x90
    float normalPower = vtable->GetNormalPowerWanted(this); // vslot 30
    float powerWanted = normalPower * pctWanted * deltaTime;
    this->powerWanted = powerWanted;           // +0x8C

    // Step 3: Request power from master via ship+0x2B0
    Ship* ship = this->ownerShip;              // +0x40
    PoweredMaster* master = ship->poweredMaster; // ship+0x2B0

    // Three modes for power draw:
    switch (this->powerMode) {                 // +0xA0
        case 0: // Normal (main battery first, then backup)
            this->powerReceived = master->DrawFromMainBattery(powerWanted);
            break;
        case 1: // Backup first (backup battery, then main)
            this->powerReceived = master->DrawFromBackupBattery(powerWanted);
            break;
        case 2: // Backup only
            this->powerReceived = master->DrawFromBackupOnly(powerWanted);
            break;
    }

    // Step 4: Compute efficiency ratio
    if (this->powerWanted > 0.0)
        this->efficiency = this->powerReceived / this->powerWanted;  // +0x94
    else
        this->efficiency = 0.0;

    // Step 5: Compute conditionRatio
    float fullPower = deltaTime * vtable->GetNormalPowerWanted(this);
    if (fullPower <= 0.0)
        this->conditionRatio = 1.0;            // +0x98
    else
        this->conditionRatio = this->powerReceived / fullPower;
}
```

### ComputeAvailablePower (FUN_00563700)

```c
// Called once per INTERVAL to compute how much power subsystems can draw
float ComputeAvailablePower(PoweredMaster* this, float ticks) {
    // Main conduit: limited by mainConduitCapacity * conditionPct * ticks
    float mainMax = GetMainConduitCapacity_scaled() * ticks;  // prop+0x50 * condPct
    float backupMax = GetBackupConduitCapacity_raw() * ticks; // prop+0x54

    // Main conduit current = min(mainBatteryPower, mainMax)
    float mainAvail = min(this->mainBatteryPower, mainMax);   // +0xAC
    this->mainConduitCurrent = mainAvail;                     // +0xA4

    // Backup conduit current = min(backupBatteryPower, backupMax)
    float backupAvail = min(this->backupBatteryPower, backupMax); // +0xB4
    this->backupConduitCurrent = backupAvail;                 // +0xA8

    return mainAvail + backupAvail;
}
```

**Key insight**: Main conduit capacity is health-scaled (`condPct`), backup conduit capacity is NOT. A damaged reactor reduces main power delivery but backup delivery stays constant.

### AddPowerToBatteries (FUN_005638d0)

```c
// Recharges batteries from reactor output
// HOST-ONLY in multiplayer (gated on g_IsHost at 0x0097FA89)
void AddPowerToBatteries(PoweredMaster* this, float amount) {
    // Main battery first
    float mainSpace = GetMainBatteryLimit() - this->mainBatteryPower;

    if (amount <= mainSpace) {
        // All goes to main battery
        this->mainBatteryPower += amount;      // +0xAC
        this->availablePower += amount;        // +0xA0
    } else {
        // Fill main battery, remainder goes to backup
        this->mainBatteryPower = GetMainBatteryLimit();
        this->availablePower += mainSpace;
        float remainder = amount - mainSpace;

        float backupSpace = GetBackupBatteryLimit() - this->backupBatteryPower;
        if (remainder <= backupSpace) {
            this->backupBatteryPower += remainder; // +0xB4
            this->availablePower += remainder;
        } else {
            this->backupBatteryPower = GetBackupBatteryLimit();
            this->availablePower += backupSpace;
            // Excess power is wasted
        }
    }
}
```

### DrawFromMainBattery (FUN_00563a70) — Mode 0

```c
// Returns actual power drawn (may be less than requested)
float DrawFromMainBattery(PoweredMaster* this, float wanted) {
    // Check if mainConduitCurrent can supply
    if (this->mainConduitCurrent >= wanted) {   // +0xA4
        // Fully satisfied from main conduit
        this->mainConduitCurrent -= wanted;
        this->mainBatteryPower -= wanted;       // +0xAC (host only)
        this->powerDispensed += wanted;         // +0xBC
        return wanted;
    }

    // Main conduit partially satisfied; try backup
    float fromMain = this->mainConduitCurrent;
    this->mainConduitCurrent = 0;

    float remaining = wanted - fromMain;
    if (this->backupConduitCurrent >= remaining) {  // +0xA8
        this->backupConduitCurrent -= remaining;
        this->backupBatteryPower -= remaining;  // +0xB4 (host only)
        this->powerDispensed += wanted;
        return wanted;  // fully satisfied
    }

    // Both conduits depleted — return partial
    float fromBackup = this->backupConduitCurrent;
    this->backupConduitCurrent = 0;
    this->powerDispensed += fromMain + fromBackup;
    return fromMain + fromBackup;
}
```

### DrawFromBackupBattery (FUN_00563bb0) — Mode 1

Same logic as DrawFromMainBattery but tries backup conduit first, then falls back to main. Used by subsystems that prefer backup power (e.g., cloaking device).

### DrawFromBackupOnly (FUN_00563cb0) — Mode 2

Only draws from backup conduit. If backup is depleted, returns 0 — does NOT fall back to main. Used for subsystems that must not touch main power.

---

## Power Flow Diagram

```
Per-second tick (FUN_00563780 "Powered" Master Update):
  1. GENERATE: powerOutput * condPct  →  add to main battery, overflow to backup
  2. COMPUTE:  mainConduit = min(mainBattery, mainCapacity * condPct)
              backupConduit = min(backupBattery, backupCapacity)
              availablePower = mainConduit + backupConduit
  3. (consumers run their own Updates)

Per-frame (FUN_00562470 each PoweredSubsystem Update):
  1. DEMAND: normalPowerPerSecond * percentageWanted * deltaTime
  2. DRAW:   mode 0 → main first, then backup
            mode 1 → backup first, then main
            mode 2 → backup only
  3. RATIO:  efficiency = received / wanted (0.0–1.0)
  4. EFFECT: subsystem performance scales by efficiency
```

---

## Consumer Registration (SetPowerSource, FUN_00563d50)

Each PoweredSubsystem registers itself with the "Powered" master during `SetupFromProperty` (vtable slot 22). The master maintains a doubly-linked list of all consumers at +0xC4/+0xC8/+0xCC. List nodes are 12 bytes: `[subsystem_ptr, prev, next]`, allocated from a pool at FUN_0054f720.

---

## Low-Power Behavior

- **Graceful degradation**: Each PoweredSubsystem gets partial power. The `efficiency` field (+0x94) = `powerReceived / powerWanted`, which scales subsystem performance.
- **No hard cutoff**: Subsystems don't turn off at zero power. They get `efficiency = 0.0` which makes them non-functional through their own logic (shields don't recharge, weapons don't charge, engines provide no thrust).
- **Battery depletion**: When both batteries hit zero, `mainConduitCurrent` and `backupConduitCurrent` both go to zero, so all subsystems receive 0 power.
- **Priority by draw order**: Since consumers draw per-frame and the conduit pools deplete as they draw, the order in which subsystems run their Update determines who gets power first during shortages. This is effectively the linked list insertion order.
- **Health scaling asymmetry**:
  - Reactor `PowerOutput` is scaled by `conditionPct`
  - Main conduit capacity IS scaled by `conditionPct` (via FUN_005634f0)
  - Backup conduit capacity is NOT scaled (via FUN_00563520, returns raw property+0x54)

---

## Power Initialization on Ship Spawn

Every ship spawns with all subsystems at 100% power, batteries full, and all consumers enabled. This is established through a three-stage initialization sequence:

### Stage 1: PoweredSubsystem Constructor (FUN_00562240)

The constructor chain (FUN_00562240 → FUN_0056b970) initializes every powered subsystem with these defaults:

| Offset | Type | Value | Field | Notes |
|--------|------|-------|-------|-------|
| +0x88 | float | 0.0 | powerReceived | No power received yet |
| +0x8C | float | 0.0 | powerWanted | No demand computed yet |
| +0x90 | float | 1.0 | powerPercentageWanted | 100% slider (IEEE 0x3F800000) |
| +0x94 | float | 1.0 | efficiency | Starts at full efficiency |
| +0x98 | float | 1.0 | conditionRatio | Starts at full condition |
| +0x9C | byte | 1 | isOn | Subsystem enabled |
| +0xA0 | int | 0 | powerMode | Mode 0 (main-first) |

**Key**: `powerPercentageWanted = 1.0f` at construction means every slider defaults to 100% without any explicit setter call.

### Stage 2: SetupFromProperty (FUN_00562390)

When `SetupFromProperty` (vtable slot 22) runs for each PoweredSubsystem, it reads the already-initialized `+0x90` value and computes `powerWanted = normalPower * powerPercentageWanted`. Since `+0x90 = 1.0` from the constructor, this naturally produces `powerWanted = normalPower * 1.0`.

For the PoweredMaster (EPS distributor), `SetupFromProperty` (FUN_005636d0) also fills both batteries to maximum capacity:
- `+0xAC = property+0x48` (mainBatteryPower = MainBatteryLimit)
- `+0xB4 = property+0x4C` (backupBatteryPower = BackupBatteryLimit)

### Stage 3: Ship::SetupProperties (FUN_005b0110)

After all subsystems are constructed and linked, `SetupProperties` redundantly iterates ALL powered subsystems and calls `SetPowerPercentageWanted(1.0)` on each one. This is a safety net — the constructor already set 1.0, so this is a no-op in normal operation.

### Safety Guard (FUN_0055f7f0)

When the reactor is enabled, a guard check at FUN_0055f7f0 forces `powerPercentageWanted = 1.0` if the current value is `<= 0.0`. This prevents a subsystem from remaining at 0% after being re-enabled.

### Initialization Order Summary

```
1. PoweredSubsystem ctor (FUN_00562240)
   └── +0x90=1.0, +0x9C=1, +0xA0=0    ← defaults baked in constructor

2. SetupFromProperty (FUN_00562390 / FUN_005636d0)
   ├── PoweredSubsystem: powerWanted = normalPower * 1.0
   └── PoweredMaster: mainBattery=limit, backupBattery=limit

3. Ship::SetupProperties (FUN_005b0110)
   └── ForEach(subsystem): SetPowerPercentageWanted(1.0)  ← redundant safety

4. Reactor enable guard (FUN_0055f7f0)
   └── if (pctWanted <= 0.0) → force 1.0  ← catch-all
```

**Result**: Ship spawns with 100% power to all subsystems, batteries full, mode 0 (main-first), all enabled. This is what the player sees on the F5 Engineering panel immediately after spawn.

---

## Player Power Adjustment

Players adjust power via the F5 Engineering panel (Power Transmission Grid). Two input paths converge on the same setter function, and the 0%–125% range is enforced client-side.

### Input Paths

#### Path A: C++ Slider (EngPowerCtrl widget)

The mouse-draggable slider bars in the F5 panel are C++ `EngPowerCtrl` widgets. When the player drags a slider:

```
EngPowerCtrl::HandlePowerChange (FUN_0054dde0)
  → identifies subsystem from slider bar (hash table at +0x58)
  → resolves subsystem group (weapons/engines/single)
  → calls SetPowerPercentageWanted (FUN_00562430) for each subsystem in group
  → posts ET_SUBSYSTEM_POWER_CHANGED (0x0080008c) event
    source = subsystem, destination = ship, float = new percentage
  → calls CallNextHandler (event chain)
```

The C++ slider performs its own range validation in `HandlePowerChange`, preventing values outside the valid range. The maximum of 1.25 comes from a float constant at 0x0088bec0 (`1.25f`).

#### Path B: Keyboard Hotkeys (Python)

Keyboard shortcuts fire `ET_MANAGE_POWER` events, handled by `EngineerMenuHandlers.ManagePower()`:

```python
# EngineerMenuHandlers.py:376-461
def ManagePower(pObject, pEvent):
    group = int(pEvent.GetInt() / 2)    # 0=weapons, 1=engines, 2=sensors, 3=shields
    direction = pEvent.GetInt() % 2     # 0=decrease, 1=increase

    fPercentWanted += (-0.25 if direction==0 else +0.25)

    # Hard clamp
    if fPercentWanted < 0.0:  fPercentWanted = 0.0
    if fPercentWanted > 1.25: fPercentWanted = 1.25

    SetPowerToSubsystem(pSubsystem, fPercentWanted)
```

### ET_MANAGE_POWER Int Encoding

The `pEvent.GetInt()` value encodes both group and direction:

| Int Value | int/2 → Group | int%2 → Direction | Meaning |
|-----------|---------------|-------------------|---------|
| 0 | 0 → Weapons | 0 → Decrease | Weapons −25% |
| 1 | 0 → Weapons | 1 → Increase | Weapons +25% |
| 2 | 1 → Engines | 0 → Decrease | Engines −25% |
| 3 | 1 → Engines | 1 → Increase | Engines +25% |
| 4 | 2 → Sensors | 0 → Decrease | Sensors −25% |
| 5 | 2 → Sensors | 1 → Increase | Sensors +25% |
| 6 | 3 → Shields | 0 → Decrease | Shields −25% |
| 7 | 3 → Shields | 1 → Increase | Shields +25% |

Values ≥ 8 are ignored (early return at line 377).

### Subsystem Grouping

- **Weapons group** (int/2 == 0): ALL weapon subsystems (phasers, torpedoes, pulse weapons) are set to the same percentage simultaneously
- **Engines group** (int/2 == 1): Impulse AND warp engines are set together
- **Sensors** (int/2 == 2): Standalone
- **Shields** (int/2 == 3): Standalone

### Bounds Enforcement (0.0–1.25)

The valid power range is **0% to 125%** (0.0 to 1.25f). Enforcement occurs at three levels:

| Level | Mechanism | Notes |
|-------|-----------|-------|
| Python keyboard | Explicit `if fPercentWanted < 0.0` / `> 1.25` clamp | EngineerMenuHandlers.py:425-428 |
| C++ slider | HandlePowerChange (FUN_0054dde0) validates range | Uses constant 1.25f at 0x0088bec0 |
| Network wire | Power byte encodes `(int)(pct * 100.0)`, range 0-125 | Byte naturally caps at 255, but 125 is practical max |
| Server | **No enforcement** | Host applies whatever the client sends |

The 125% overload mechanic is visible in the F5 panel as an orange/red zone past the 100% mark. Overclocking increases demand above the normal power budget, accelerating battery drain.

### SetPowerToSubsystem Boundary Behavior

The Python `SetPowerToSubsystem()` function (EngineerMenuHandlers.py:442-461) handles the on/off transition at boundaries:

```python
def SetPowerToSubsystem(pSubsystem, fPercentWanted):
    pSubsystem.SetPowerPercentageWanted(fPercentWanted)
    if (not pSubsystem.IsOn() and fPercentWanted > 0.0):
        pSubsystem.TurnOn()       # → fires SubsystemStatus opcode 0x0A
    if (fPercentWanted == 0.0):
        pSubsystem.TurnOff()      # → fires SubsystemStatus opcode 0x0A
```

- Setting to 0% → `TurnOff()` → SubsystemStatus (opcode 0x0A) is network-forwarded immediately
- Setting to >0% on a disabled subsystem → `TurnOn()` → opcode 0x0A forwarded immediately
- The on/off toggle has **instant network propagation** (dedicated opcode), while the power percentage propagates via StateUpdate round-robin (1-2 second delay)

---

## Confirmed Constants

| Address | Value | Used As |
|---------|-------|---------|
| 0x892e20 | 1.0f | INTERVAL — power sim runs once per second |
| 0x888b54 | 0.0f | Zero constant for float comparisons |
| 0x888860 | 1.0f | Used in GetCombinedConditionPercentage |
| 0x0088bec0 | 1.25f | Maximum powerPercentageWanted (125% overload cap) |
| 0x0088ce78 | 100.0f | WriteState: `(int)(pct * 100.0)` encoding multiplier |
| 0x0088d4e4 | 0.01f | ReadState: `byte * 0.01f` decoding multiplier |
| 0x0088b9ac | 255.0f | Condition byte: `(condition/maxCondition) * 255.0` |

---

## Python API Surface

### PowerSubsystem (SWIG, `reference/scripts/App.py` lines 5710-5760)

**Getters:**
- `GetMainBatteryPower()` — Current main battery charge level
- `GetBackupBatteryPower()` — Current backup battery charge level
- `GetPowerOutput()` — Reactor power generation rate (health-scaled)
- `GetMainBatteryLimit()` — Maximum main battery capacity
- `GetBackupBatteryLimit()` — Maximum backup battery capacity
- `GetMaxMainConduitCapacity()` — Max main conduit (raw, not health-scaled)
- `GetMainConduitCapacity()` — Current main conduit remaining this interval
- `GetBackupConduitCapacity()` — Current backup conduit remaining this interval
- `GetAvailablePower()` — Total available (main + backup conduit)
- `GetPowerWanted()` — Total power requested by all subsystems
- `GetPowerDispensed()` — Total power delivered this interval
- `GetConditionPercentage()` — Reactor health (0.0–1.0)

**Setters:**
- `SetMainBatteryPower(float)` — Set current main battery charge
- `SetBackupBatteryPower(float)` — Set current backup battery charge
- `SetAvailablePower(float)` — Set available power reserve

**Battery manipulation:**
- `AddPower(float)` — Add power to main battery
- `DeductPower(float)` — Remove power from system
- `StealPower(float)` — Drain from main battery
- `StealPowerFromReserve(float)` — Drain from backup battery

**Watchers:**
- `GetMainBatteryWatcher()` — Event trigger on main battery changes
- `GetBackupBatteryWatcher()` — Event trigger on backup battery changes

### PowerProperty (SWIG, lines 9776-9802)

- `Get/SetMainBatteryLimit(float)`
- `Get/SetBackupBatteryLimit(float)`
- `Get/SetMainConduitCapacity(float)`
- `Get/SetBackupConduitCapacity(float)`
- `Get/SetPowerOutput(float)`

### PoweredSubsystem (inherited by all consumers)

- `GetNormalPowerWanted()` — Base power requirement from hardpoint
- `GetPowerPercentageWanted()` — User slider (0.0–1.0+)
- `SetPowerPercentageWanted(float)` — Set user slider
- `GetNormalPowerPerSecond()` — Same as NormalPowerWanted (alias)

---

## Ship Power Parameters (All Hardpoints)

### Playable Ships

| Ship | Faction | MainBattery | BackupBattery | MainConduit | BackupConduit | PowerOutput |
|------|---------|-------------|---------------|-------------|---------------|-------------|
| Enterprise-E | Fed | 300,000 | 120,000 | 1,900 | 300 | 1,600 |
| Galaxy | Fed | 250,000 | 80,000 | 1,200 | 200 | 1,000 |
| Sovereign | Fed | 200,000 | 100,000 | 1,450 | 250 | 1,200 |
| Geronimo | Fed | 240,000 | 80,000 | 1,200 | 200 | 1,000 |
| Nebula | Fed | 100,000 | 150,000 | 1,000 | 200 | 800 |
| Akira | Fed | 150,000 | 50,000 | 900 | 100 | 800 |
| Ambassador | Fed | 200,000 | 50,000 | 700 | 100 | 600 |
| Peregrine | Fed | 50,000 | 200,000 | 900 | 100 | 800 |
| Shuttle | Fed | 20,000 | 10,000 | 140 | 40 | 100 |
| Warbird | Rom | 100,000 | 200,000 | 1,700 | 300 | 1,500 |
| Vor'cha | Kli | 100,000 | 100,000 | 900 | 200 | 800 |
| Bird of Prey | Kli | 80,000 | 40,000 | 470 | 70 | 400 |
| Keldon | Card | 140,000 | 50,000 | 700 | 100 | 600 |
| Galor | Card | 120,000 | 50,000 | 550 | 150 | 500 |
| Matan Keldon | Card | 160,000 | 50,000 | 1,200 | 600 | 900 |
| Cardassian Hybrid | Card | 160,000 | 50,000 | 1,100 | 100 | 1,000 |
| Kessok Heavy | Kes | 100,000 | 100,000 | 1,500 | 100 | 1,400 |
| Kessok Light | Kes | 120,000 | 80,000 | 1,000 | 50 | 900 |
| Marauder | Fer | 140,000 | 100,000 | 900 | 200 | 700 |
| Sunbuster | — | 200,000 | 50,000 | 1,550 | 100 | 1,500 |
| Transport | — | 120,000 | 50,000 | 800 | 100 | 700 |
| Freighter | — | 70,000 | 40,000 | 650 | 400 | 600 |
| Cardassian Freighter | Card | 50,000 | 10,000 | 400 | 200 | 400 |
| Escape Pod | — | 50,000 | 20,000 | 200 | 100 | 100 |
| Probe | — | 8,000 | 4,000 | 100 | 100 | 15 |
| Probe 2 | — | 8,000 | 4,000 | 100 | 100 | 15 |

### Stations

| Station | MainBattery | BackupBattery | MainConduit | BackupConduit | PowerOutput |
|---------|-------------|---------------|-------------|---------------|-------------|
| Federation Starbase | 800,000 | 200,000 | 5,500 | 500 | 5,000 |
| Federation Outpost | 100,000 | 20,000 | 1,700 | 200 | 1,500 |
| Cardassian Starbase | 200,000 | 200,000 | 2,500 | 500 | 2,000 |
| Cardassian Station | 150,000 | 150,000 | 1,300 | 300 | 1,000 |
| Cardassian Outpost | 50,000 | 100,000 | 1,600 | 200 | 1,500 |
| Cardassian Facility | 400,000 | 50,000 | 1,000 | 600 | 1,500 |
| Space Facility | 400,000 | 200,000 | 3,000 | 1,500 | 2,000 |
| Drydock | 50,000 | 5,000 | 650 | 50 | 600 |
| Comm Array | 10,000 | 5,000 | 700 | 200 | 600 |
| Comm Light | 180,000 | 5,000 | 1,000 | 400 | 600 |
| Kessok Mine | 40,000 | 20,000 | 350 | 50 | 300 |

### Non-Combatants (Generic Template / Asteroids)

All use: MainBattery=70,000, BackupBattery=10,000, MainConduit=400, BackupConduit=200, PowerOutput=100.

---

## Subsystem Power Consumption (NormalPowerPerSecond)

### Federation Ships

| Subsystem | Sovereign | Enterprise-E | Galaxy | Nebula | Akira | Ambassador |
|-----------|-----------|-------------|--------|--------|-------|------------|
| Shields | 450 | 300 | 400 | 250 | 300 | 200 |
| Sensors | 150 | — | 100 | 100 | 150 | 50 |
| Impulse | 200 | — | 150 | 100 | 50 | 100 |
| Phasers | 400 | — | 300 | 200 | 200 | 150 |
| Torpedoes | 150 | — | 100 | 150 | 100 | 100 |
| Tractors | 700 | — | 600 | 400 | 600 | 600 |
| Repair | 1 | 1 | 1 | 1 | 1 | 1 |
| Warp | 0 | — | 0 | 0 | 0 | 0 |
| **Total** | **2,051** | **301+** | **1,651** | **1,201** | **1,301** | **1,101** |

*Enterprise-E inherits most values from Sovereign parent; only overrides shown.*

### Klingon Ships

| Subsystem | Vor'cha | Bird of Prey |
|-----------|---------|-------------|
| Shields | 250 | 180 |
| Sensors | 100 | 50 |
| Impulse | 100 | 50 |
| Disruptor Beams | 50 | — |
| Disruptor Cannons | 150 | 80 |
| Torpedoes | 150 | 50 |
| Tractors | 700 | — |
| Cloak | 700 | 380 |
| Repair | 1 | 1 |
| Warp | 0 | 0 |
| **Total (no cloak)** | **1,301** | **411** |
| **Total (cloaked)** | **2,001** | **791** |

### Romulan

| Subsystem | Warbird |
|-----------|---------|
| Shields | 400 |
| Sensors | 200 |
| Impulse | 300 |
| Disruptor Beams | 100 |
| Disruptor Cannons | 200 |
| Torpedoes | 150 |
| Tractors | 800 |
| Cloak | 1,000 |
| Repair | 1 |
| Warp | 0 |
| **Total (no cloak)** | **2,151** |
| **Total (cloaked)** | **3,151** |

### Cardassian Ships

| Subsystem | Keldon | Galor |
|-----------|--------|-------|
| Shields | 200 | 200 |
| Sensors | 50 | 50 |
| Impulse | 70 | 50 |
| Torpedoes | 70 | 50 |
| Compressors | 200 | 150 |
| Tractors | 400 | — |
| Repair | 1 | 1 |
| Warp | 0 | 0 |
| **Total** | **991** | **501** |

### Ferengi

| Subsystem | Marauder |
|-----------|----------|
| Shields | 200 |
| Sensors | 100 |
| Impulse | 50 |
| Phasers | 100 |
| Plasma Emitters | 200 |
| Tractors | 2,000 |
| Repair | 1 |
| Warp | 0 |
| **Total** | **2,651** |

*Note: Marauder tractors draw 2,000/sec — highest single-subsystem draw in the game.*

### Kessok

| Subsystem | Kessok Heavy |
|-----------|-------------|
| Shields | 500 |
| Sensors | 200 |
| Impulse | 200 |
| Positron Beams | 200 |
| Torpedoes | 200 |
| Cloak | 1,300 |
| Repair | 50 |
| Warp | 0 |
| **Total (no cloak)** | **1,350** |
| **Total (cloaked)** | **2,650** |

---

## Power Budget Analysis

Ships are designed to run at a power deficit under full combat load, slowly draining batteries:

| Ship | Output | Total Draw | Deficit | Main Battery Drain Time |
|------|--------|-----------|---------|------------------------|
| Sovereign | 1,200 | 2,051 | -851 | ~235s (3m 55s) |
| Enterprise-E | 1,600 | ~2,051 | -451 | ~665s (11m 5s) |
| Galaxy | 1,000 | 1,651 | -651 | ~384s (6m 24s) |
| Warbird | 1,500 | 2,151 | -651 | ~154s (2m 34s) |
| Warbird (cloaked) | 1,500 | 3,151 | -1,651 | ~61s (1m 1s) |
| Vor'cha | 800 | 1,301 | -501 | ~200s (3m 20s) |
| Bird of Prey | 400 | 411 | -11 | ~7,273s (~2h) |
| Keldon | 600 | 991 | -391 | ~358s (5m 58s) |
| Marauder | 700 | 2,651 | -1,951 | ~72s (1m 12s) |

*Drain time = MainBatteryLimit / deficit. Real drain is slower because some subsystems are not always active (tractors, torpedoes).*

---

## AdjustPower Algorithm (PowerDisplay.py, Python-Side)

The `AdjustPower` function in `PowerDisplay.py` (lines 876–956) runs on the client to auto-balance power when demand exceeds supply:

```python
def AdjustPower(lSystems):
    # 1. Calculate each subsystem's share of total normal power
    for pSystem in lSystems:
        dPower[pSystem] = pSystem.GetNormalPowerWanted()
        fNormTotalPower += dPower[pSystem]

    # Normalize to percentages
    for pSystem in lSystems:
        dPower[pSystem] = dPower[pSystem] / fNormTotalPower

    # 2. Check for deficit
    fTotalPower = SUM(GetNormalPowerWanted() * GetPowerPercentageWanted())
    fPowerDeficit = fTotalPower - (MainConduit + BackupConduit)

    # 3. If deficit > 1% of total power:
    if fPowerDeficit > fTotalPower * 0.01:
        for pSystem in lSystems:
            fPowerReduction = dPower[pSystem] * fPowerDeficit  # proportional
            fNewPower = max(NormalPower * NormalPercentage - fPowerReduction, 0.0)
            # Never reduce below 20% or user's desired setting
            SetPowerPercentageWanted(max(fNewPower / NormalPower, min(0.2, current)))

        # 4. Sync weapon types to same percentage
        pTorps.SetPowerPercentageWanted(pPhasers.GetPowerPercentageWanted())
        pDisruptors.SetPowerPercentageWanted(pPhasers.GetPowerPercentageWanted())

        # 5. Sync engine types to same percentage
        pWarp.SetPowerPercentageWanted(pImpulse.GetPowerPercentageWanted())
```

---

## Multiplayer Network Propagation of Power Distribution

### Summary

Power distribution slider changes have **NO dedicated network message**. There is no event-forwarding opcode, no Python-level TGMessage, and no C++ network send call for power changes. Instead, power percentages propagate **exclusively through the StateUpdate (opcode 0x1C)** subsystem health round-robin (flag 0x20), via the `PoweredSubsystem::WriteState` / `ReadState` virtual functions.

This is a purely state-replication design: each client sets power locally, their StateUpdate includes the current power percentages, and other peers apply them on receipt.

### Complete Code Path

#### 1. Client-side: Slider Interaction

Two input paths converge on the same setter:

**Path A: Mouse slider (C++ EngPowerCtrl widget)**
```
EngPowerCtrl::HandlePowerChange (FUN_0054dde0)
  → identifies subsystem from slider bar (hash table at +0x58)
  → resolves ship (FUN_00562210) and subsystem group (weapons/engines/single)
  → calls SetPowerPercentageWanted (FUN_00562430) for each subsystem
  → calls FUN_0054e690: posts ET_SUBSYSTEM_POWER_CHANGED (0x0080008c) event
    source = subsystem, destination = ship, float = new percentage
  → calls CallNextHandler (event chain propagation)
```

**Path B: Keyboard hotkeys (Python EngineerMenuHandlers.ManagePower)**
```
ManagePower handler (ET_MANAGE_POWER event)
  → adjusts fPercentWanted by +/- 0.25
  → calls pSubsystem.SetPowerPercentageWanted(fPercentWanted) [SWIG → FUN_00562430]
  → posts TGFloatEvent with ET_SUBSYSTEM_POWER_CHANGED, same as Path A
```

Both paths end with `SetPowerPercentageWanted` (FUN_00562430), which is a **pure local setter**:
```c
void SetPowerPercentageWanted(PoweredSubsystem* this, float pct) {
    float oldPct = this->powerPercentageWanted;  // +0x90
    this->powerPercentageWanted = pct;
    if (oldPct != 0.0)
        this->powerWanted = (this->powerWanted * pct) / oldPct;  // +0x8C rescale
}
```
No network call. No TGEvent posting (the event is posted by the *caller*, not the setter).

#### 2. ET_SUBSYSTEM_POWER_CHANGED (0x0080008c) is LOCAL ONLY

The event `0x0080008c` is registered with two handlers:
- `EngPowerCtrl::HandlePowerChange` (0x0054dde0) — registered at EngPowerCtrl ctor via FUN_006d92b0
- Mission script handlers (E5M4, E7M6, E2M2) — single-player campaign use only

**Critically, `0x0080008c` is NOT registered in the MultiplayerGame constructor (FUN_0069e590).** It does not appear in any network forwarding table. The complete list of forwarded event types is:

| Event Code | Handler Name | Network Opcode |
|------------|--------------|----------------|
| 0x008000d8 | StartFiring | 0x07 |
| 0x008000da | StopFiring | 0x08 |
| 0x008000dc | StopFiringAtTarget | 0x09 |
| 0x008000dd | SubsystemStatus | 0x0A |
| 0x00800076 | RepairListPriority | 0x11 |
| 0x008000e0 | SetPhaserLevel | 0x12 |
| 0x008000e2 | StartCloaking | 0x0E |
| 0x008000e4 | StopCloaking | 0x0F |
| 0x008000ec | StartWarp | 0x10 |
| 0x008000fe | TorpedoTypeChange | 0x1B |

**0x0080008c is absent.** Power slider changes do NOT generate any network message.

#### 3. Network Propagation via StateUpdate (0x1C)

Power percentages are serialized in the **StateUpdate flag 0x20 block** by `PoweredSubsystem::WriteState` (FUN_00562960):

**WriteState (sender):**
```c
void PoweredSubsystem_WriteState(PoweredSubsystem* this, Stream* stream, bool isOwnShip) {
    ShipSubsystem_WriteState(this, stream);  // condition byte + children
    if (!isOwnShip) {
        WriteBit(stream, 1);                                    // hasData = true
        int pctByte = (int)(this->powerPercentageWanted * 100.0);  // +0x90 → 0-100
        WriteByte(stream, pctByte);
    } else {
        WriteBit(stream, 0);                                    // hasData = false (owner has local state)
    }
    EndMarker(stream);
}
```

**ReadState (receiver):**
```c
void PoweredSubsystem_ReadState(PoweredSubsystem* this, Stream* stream, float timestamp) {
    float lastUpdate = this->lastNetworkUpdate;  // +0x84
    ShipSubsystem_ReadState(this, stream, timestamp);   // condition byte + children
    bool hasData = ReadBit(stream);
    if (hasData) {
        int pctByte = ReadByte(stream);
        if (lastUpdate < timestamp) {  // only apply if newer
            SetPowerPercentageWanted(this, (float)pctByte * 0.01f);  // byte/100 → 0.0-1.0
        }
    }
    EndMarker(stream);
}
```

**The `isOwnShip` parameter determines whether power data is included:**
- When sending state about ship X to the player who owns ship X: `isOwnShip = 1`, power data SKIPPED
- When sending state about ship X to any other player: `isOwnShip = 0`, power data INCLUDED

This is determined in `Ship_WriteStateUpdate` (FUN_005b17f0) by comparing `ship->objectID` (ship+0x04) against the target peer's `shipObjectID` (peer+0x0C). See the "isOwnShip Determination" subsection below for details.

#### 4. Data Flow in Star Topology

```
Client A adjusts power sliders
  → SetPowerPercentageWanted() changes local subsystem +0x90
  → Client A's Ship_WriteStateUpdate sends 0x1C to host
    → PoweredSubsystem::WriteState writes powerPctWanted byte (isOwnShip=0)

Host receives 0x1C from Client A
  → Ship_ReadStateUpdate → PoweredSubsystem::ReadState
    → SetPowerPercentageWanted() applies to host's copy of Client A's ship

Host broadcasts 0x1C to Client B
  → Ship_WriteStateUpdate for Client A's ship
    → PoweredSubsystem::WriteState writes powerPctWanted byte (isOwnShip=0)

Client B receives 0x1C
  → Ship_ReadStateUpdate → PoweredSubsystem::ReadState
    → SetPowerPercentageWanted() applies to Client B's copy of Client A's ship

Host sends 0x1C back to Client A (for Client A's own ship)
  → PoweredSubsystem::WriteState writes hasData=0 bit (isOwnShip=1)
  → Client A DOES NOT overwrite its own local power settings
```

#### 5. Wire Format Detail

Within the flag 0x20 (subsystem health) block of a 0x1C StateUpdate packet, each PoweredSubsystem writes:

```
[condition: byte]          // health 0-255
[child_0 condition: byte]  // recursive children (individual weapons/engines)
[child_1 condition: byte]
...
[hasData: 1 bit]           // 1 if remote ship, 0 if own ship
[if hasData=1:]
  [powerPctWanted: byte]   // (int)(powerPercentageWanted * 100.0), range 0-125
```

The powerPctWanted byte uses range 0-100 for normal (0%-100%) and can go up to 125 for 125% overload. Values above 100 indicate the player has overclocked that subsystem.

#### 6. Encoding Precision

- **Write**: `(int)(powerPercentageWanted * 100.0)` — truncation toward zero
- **Read**: `(float)byte * 0.01f` — reconstructs approximate ratio
- **Resolution**: 1% steps (0.01 increments)
- **Range**: 0.00 to 1.25 (0% to 125%)
- **Loss**: Values like 0.33 (33%) encode to byte 33, decode to 0.33 exactly. But 0.256 encodes to 25, decodes to 0.25 — a 0.006 error (max 0.009).
- **Update rate**: Round-robin at ~10Hz per ship, so subsystem power percentages converge within 1-2 seconds for a full cycle of all 11 top-level subsystems.

#### 7. Implications

1. **No instant sync**: Power changes propagate at StateUpdate rate (~10Hz round-robin), not on-demand. A slider change takes up to 1-2 seconds to fully propagate to all peers.
2. **No server authority**: The host does not validate or enforce power percentages. It applies whatever the client sends.
3. **Auto-balance is client-side only**: The `AdjustPower` function in `PowerDisplay.py` runs locally. Other peers see the final result via StateUpdate, not the intermediate balancing.
4. **EngPowerCtrl refresh is local**: The C++ EngPowerCtrl periodic refresh (event 0x0080008d, every ~0.5s) only updates the local UI. It does not trigger any network send.
5. **TurnOn/TurnOff IS forwarded**: While power percentage is StateUpdate-only, toggling a subsystem on/off uses event 0x008000dd (SubsystemStatus, opcode 0x0A), which IS network-forwarded. The on/off state also propagates in the WriteState sign bit.

### Sign Bit Encoding (On/Off State)

In `FUN_00562900` (an alternate ReadState path), the power byte has a sign encoding:
```c
if (pctByte < 1) {
    pctByte = -pctByte;       // negate
    this->isOn = 0;           // +0x9C: subsystem OFF
} else {
    this->isOn = 1;           // +0x9C: subsystem ON
}
this->powerPercentageWanted = (float)pctByte * 0.01f;
```

This allows on/off state to be packed into the same byte as the power percentage: negative = off, positive = on. This is a secondary propagation path for on/off state alongside the dedicated SubsystemStatus opcode (0x0A).

### Two Serialization Interfaces

PoweredSubsystem has two distinct serialization interfaces, each invoked through different vtable slots:

#### Interface A: Round-Robin (flag 0x20, vtable+0x70 / vtable+0x74)

Used in the **StateUpdate flag 0x20 block** (subsystem health round-robin). This is the primary path for ongoing power state replication:

```c
// WriteState (vtable+0x70, FUN_00562960):
ShipSubsystem_WriteState(this, stream);       // condition byte + children (recursive)
if (!isOwnShip) {
    WriteBit(stream, 1);                       // hasData = 1
    int pctByte = (int)(this->powerPercentageWanted * 100.0);  // 0x0088ce78
    WriteByte(stream, pctByte);                // power percentage as 0-125
} else {
    WriteBit(stream, 0);                       // hasData = 0 (owner has local state)
}
EndMarker(stream);

// ReadState (vtable+0x74, FUN_005629d0):
float savedTimestamp = this->lastNetworkUpdate;  // +0x84 — saved BEFORE base ReadState
ShipSubsystem_ReadState(this, stream, timestamp);  // condition byte + children
bool hasData = ReadBit(stream);
if (hasData) {
    int pctByte = ReadByte(stream);
    if (savedTimestamp < timestamp) {           // only apply if packet is newer
        SetPowerPercentageWanted(this, (float)pctByte * 0.01f);  // 0x0088d4e4
    }
}
EndMarker(stream);
```

**Timestamp detail**: ReadState saves `this->lastNetworkUpdate` BEFORE calling the base class ReadState. This is critical because the base class updates `lastNetworkUpdate` from the incoming timestamp. The saved value represents the timestamp of the *previous* update, allowing the receiver to correctly determine whether the incoming data is newer.

#### Interface B: ObjCreate / Full Snapshot (vtable+0x68 / vtable+0x6c)

Used during **ObjCreate (opcode 0x02/0x03)** for initial object state transmission and in weapon round-robin (flag 0x80). This path uses sign-bit encoding:

```c
// WriteState_SignBit (vtable+0x68, FUN_005628a0):
ShipSubsystem_WriteState(this, stream);       // condition byte + children
int pctByte = (int)(this->powerPercentageWanted * 100.0);
if (!this->isOn)                               // +0x9C
    pctByte = -pctByte;                        // negate to encode OFF state
WriteByte(stream, pctByte);                    // signed byte: positive=ON, negative=OFF
EndMarker(stream);

// ReadState_SignBit (vtable+0x6c, FUN_00562900):
ShipSubsystem_ReadState(this, stream, timestamp);
int pctByte = ReadByte(stream);               // signed
if (pctByte < 1) {                            // 0 or negative
    pctByte = -pctByte;                        // absolute value
    this->isOn = 0;                            // subsystem OFF
} else {
    this->isOn = 1;                            // subsystem ON
}
this->powerPercentageWanted = (float)pctByte * 0.01f;
EndMarker(stream);
```

**Key difference from Interface A**: Interface B always includes power data (no `isOwnShip` skip), and packs the on/off state into the sign bit. This is used for initial sync where the receiver needs both the power percentage AND the on/off state in a single byte.

### Round-Robin Algorithm Detail

The round-robin serializer maintains a per-peer write cursor that persists across ticks:

```c
// From Ship_WriteStateUpdate (FUN_005b17f0), flag 0x20 section:
// Per-peer tracking structure (iVar7):
//   +0x30: linked list cursor (SubsystemListNode*)
//   +0x34: subsystem index counter (int)

if (cursor == 0) {                             // First time or reset
    cursor = ship->subsystemListHead;          // ship+0x284
    index = 0;
}

initialCursor = cursor;                        // Remember for wrap detection
WriteByte(stream, index);                      // startIndex byte — tells receiver where we start

bytesWritten = 0;
while (bytesWritten < 10) {                    // 10-byte budget per tick
    node = cursor;
    if (node == NULL) { subsystem = NULL; }
    else { subsystem = node->data; cursor = node->next; }

    subsystem->WriteState(stream, isOwnShip);  // vtable+0x70

    index++;
    if (cursor == 0) {                         // End of list: wrap
        cursor = ship->subsystemListHead;
        index = 0;
    }
    if (cursor == initialCursor) break;        // Full cycle: stop
    bytesWritten = stream.position - startPosition;
}
```

**Budget**: 10 bytes per flag 0x20 block per tick. With a Sovereign's 11 top-level subsystems (some with children), a full cycle takes ~3-5 ticks. At ~10Hz StateUpdate rate, this means ~0.3-0.5 seconds for all subsystem power percentages to be transmitted.

### isOwnShip Determination

The `isOwnShip` flag is determined in `Ship_WriteStateUpdate` (FUN_005b17f0) by comparing object IDs:

```c
// isOwnShip = (ship->objectID == peer->shipObjectID) && IsMultiplayer
// ship+0x04 = objectID (assigned at creation)
// peer+0x0C = shipObjectID (set when player selects ship)
// 0x0097FA8A = IsMultiplayer flag
```

This is an **object ID comparison**, not a connection ID comparison. When the host is writing state for ship X and sending it to the player who owns ship X, `isOwnShip = 1` and power data is omitted. This prevents the server from overwriting the owner's local slider settings with potentially stale data.

---

## Open Questions

1. **Event IDs**: 0x80006c likely = "power state changed", 0x800072 = "subsystem disabled", 0x800073 = "subsystem enabled", 0x8000dd = "powered subsystem state changed". Need Ghidra verification.
2. **PowerProperty ownership**: The PowerProperty (type 0x813E) creates the "Powered" master (+0x2B0). The "Power" reactor at +0x2C4 (type 0x8138) may use a different generic property. Need to trace `SetupFromProperty` for both. *(Partially answered: SetupFromProperty at FUN_005636d0 initializes battery levels from property+0x48 and +0x4C. Batteries start full at spawn.)*
3. **Default powerMode values**: Which subsystems default to mode 0/1/2? The cloaking device likely defaults to mode 2 (backup only) given the backup-heavy power design. Base PoweredSubsystem ctor initializes +0xA0 to 0 (mode 0 = main-first). *(Confirmed: ctor sets mode 0 for all subsystems. Specific overrides in SetupFromProperty need verification.)*
4. ~~**FUN_005636D0** (PoweredMaster::SetupFromProperty): How does it initialize battery levels from property? Are batteries full at spawn?~~ **ANSWERED**: Yes. `mainBatteryPower = property+0x48` (MainBatteryLimit), `backupBatteryPower = property+0x4C` (BackupBatteryLimit). Batteries start at maximum capacity.
5. **Conduit scaling correction**: Need to verify which conduit is health-scaled. The analysis shows MainConduit scaled via FUN_005634f0 (property+0x50 * condPct) and BackupConduit raw via FUN_00563520 (property+0x54). This needs Ghidra confirmation.

1. **Event IDs**: 0x80006c likely = "power state changed", 0x800072 = "subsystem disabled", 0x800073 = "subsystem enabled", 0x8000dd = "powered subsystem state changed". Need Ghidra verification.
2. **PowerProperty ownership**: The PowerProperty (type 0x813E) creates the "Powered" master (+0x2B0). The "Power" reactor at +0x2C4 (type 0x8138) may use a different generic property. Need to trace `SetupFromProperty` for both.
3. **Default powerMode values**: Which subsystems default to mode 0/1/2? The cloaking device likely defaults to mode 2 (backup only) given the backup-heavy power design. Base PoweredSubsystem ctor likely initializes +0xA0 to 0.
4. **FUN_005636D0** (PoweredMaster::SetupFromProperty, slot 22): How does it initialize battery levels from property? Are batteries full at spawn?
5. **Conduit scaling correction**: Need to verify which conduit is health-scaled. The analysis shows MainConduit scaled via FUN_005634f0 (property+0x50 * condPct) and BackupConduit raw via FUN_00563520 (property+0x54). This needs Ghidra confirmation.

---

## Related Documentation

- [combat-mechanics-re.md](combat-mechanics-re.md) — Damage pipeline (references power efficiency for subsystem performance)
- [cloaking-state-machine.md](cloaking-state-machine.md) — Cloak power draw and energy failure auto-decloak
- [shield-system.md](shield-system.md) — Shield recharge is power-budget based (efficiency affects recharge rate)
- [repair-tractor-analysis.md](repair-tractor-analysis.md) — Repair and tractor power consumption
- [stateupdate-subsystem-wire-format.md](stateupdate-subsystem-wire-format.md) — PowerSubsystem::WriteState serialization
