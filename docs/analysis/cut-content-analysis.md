> [docs](../README.md) / [analysis](README.md) / cut-content-analysis.md

# Bridge Commander Cut, Incomplete, and Hidden Feature Analysis

**Date**: 2026-02-17 (verified)
**Binary**: stbc.exe (32-bit, ~5.9MB, base 0x400000)
**Method**: Ghidra decompilation, string analysis, SWIG binding enumeration, Python script cross-reference, developer context analysis
**Verification**: All claims verified against Ghidra MCP (54 binary items, 50 TRUE, 2 address swaps fixed, 2 clarified) and reference scripts (12 categories checked). Shipped features (self-destruct, damage volumes) confirmed and reclassified.

---

## Executive Summary

Bridge Commander contains a remarkable amount of partially-implemented, disabled, and developer-only functionality. The multiplayer design documents clearly planned at least 9 game modes, but only 4 shipped. The code references to unshipped modes (cooperative Borg Hunt, asymmetric Enterprise Assault) survive in `MissionShared.py`. The AI fleet command system, starbase docking/repair, tractor beam docking, and ship class scoring modifiers were all built for a multiplayer experience far more ambitious than the deathmatch that shipped.

### Top Findings

1. **Ghost Missions 7 and 9** -- Cooperative "Destroy the Borg Cube" and asymmetric "Destroy the Enterprise" modes. End-game constants, shared handler code, species definitions, and string lookups all survive. Only the mission script folders are missing.
2. **Fleet Command AI** -- A complete tactical vocabulary (DefendTarget, DestroyTarget, DisableTarget, DockStarbase, HelpMe) designed for commanding AI wingmen. Never used in multiplayer.
3. **Tractor Beam Docking System** -- A complete tractor-beam-based docking mechanic with 6 modes including 2-stage docking, push, pull, tow, and hold. Tied to starbase repair/reload events. No multiplayer network support.
4. **Starbase Docking/Repair** -- ~660 lines of polished docking code in `AI/Compound/DockWithStarbase.py` (approach, cutscene, repair/rearm, undocking) that works for any ship and any starbase. Single-player only.
5. **Ship Class Scoring** -- A modifier table in `Modifier.py` that multiplies score based on attacker/victim ship class. Fully plumbed through the scoring path but all ships are assigned the same class (no-op).
6. **Friendly Fire Penalty** -- Complete tracking system with progressive warnings and game-over threshold. Campaign-only.
7. **Developer Tools** -- Python REPL console, in-game 3D level editor, god mode, kill target, instant repair, load quantums. All fully functional, gated behind a single flag.
8. **Object Emitter System** -- Ships can emit probes, shuttles, and decoys. Probes work in SP; shuttles and decoys are enum-only.
9. **Multi-Set Multiplayer** -- Opcode 0x1F (EnterSet) handles cross-set movement over the network. Never used in MP maps.

---

## Category 0: Cut Multiplayer Modes (Ghost Missions)

The multiplayer design planned at least 9 game modes. The shipped game has missions 1, 2, 3, and 5. The shared multiplayer code in `MissionShared.py` contains end-game handlers, score constants, and string lookups for unshipped modes. The evidence:

### End-Game Reason Constants (MissionShared.py)

```python
END_ITS_JUST_OVER = 0
END_TIME_UP = 1
END_NUM_FRAGS_REACHED = 2
END_SCORE_LIMIT_REACHED = 3
END_STARBASE_DEAD = 4        # Used by Mission5
END_BORG_DEAD = 5            # Mission7 (CUT)
END_ENTERPRISE_DEAD = 6      # Mission9 (CUT)
```

### Mission Map

| Mission | What Shipped | Evidence |
|---------|-------------|----------|
| Mission1 | Free-for-all Deathmatch | SHIPPED |
| Mission2 | Team Deathmatch | SHIPPED |
| Mission3 | Team Deathmatch variant | SHIPPED |
| **Mission4** | **Unknown** | Gap in numbering, no code references survive |
| Mission5 | Assault/Defend Starbase | SHIPPED |
| **Mission6** | **Starbase variant** | Referenced in MissionShared.py line 242 alongside Mission5: `if pcMissionName == "...Mission5..." or pcMissionName == "...Mission6..."`. Shares `g_bStarbaseDead` flag. Likely reversed teams or different victory conditions. |
| **Mission7** | **Cooperative Borg Hunt** | Referenced at MissionShared.py line 253. Checks `g_bBorgDead`. Uses `END_BORG_DEAD = 5`. String lookup: `g_pDatabase.GetString("Borg Destroyed")`. BORGCUBE species (index 45) exists in `SpeciesToShip.py`. All infrastructure in place -- only the mission folder is missing. |
| **Mission8** | **Unknown** | Gap in numbering, no code references survive |
| **Mission9** | **Destroy the Enterprise** | Referenced at MissionShared.py line 264. Checks `g_bEnterpriseDead`. Uses `END_ENTERPRISE_DEAD = 6`. String lookup: `g_pDatabase.GetString("Enterprise Destroyed")`. ENTERPRISE species (37, Sovereign-class variant) in `SpeciesToShip.py`. Asymmetric mode -- one team/all players try to destroy a specific named ship. |

### Restoration Feasibility

**Mission7 (Borg Hunt)** is the highest-value restoration target. The framework handles everything:
- MissionShared.py already processes `END_BORG_DEAD` and `g_bBorgDead`
- BORGCUBE species exists with ship definition
- The `ObjectGroupWithInfo` class (used in Mission5) provides team grouping
- The AI fleet command system could give the Borg Cube AI behaviors
- Only needed: a `Multiplayer/Episode/Mission7/` folder with mission script, menus, and map setup

**Mission9 (Enterprise Assault)** is similarly close:
- MissionShared.py already processes `END_ENTERPRISE_DEAD` and `g_bEnterpriseDead`
- ENTERPRISE species (37) exists
- Asymmetric scoring could use the existing `Modifier.py` class system
- Only needed: mission script folder

---

## Category 0.5: Cut Multiplayer Systems

### Fleet Command AI

The AI directory at `reference/scripts/AI/Fleet/` contains a complete tactical vocabulary for commanding AI wingmen:

| Command | File | What It Does |
|---------|------|-------------|
| DefendTarget | `AI/Fleet/DefendTarget.py` | Orders wingman to defend a specific target |
| DestroyTarget | `AI/Fleet/DestroyTarget.py` | Orders attack on a specific target |
| DisableTarget | `AI/Fleet/DisableTarget.py` | Orders to disable (not destroy) a target |
| DockStarbase | `AI/Fleet/DockStarbase.py` | Orders docking with a starbase |
| HelpMe | `AI/Fleet/HelpMe.py` | Distress call -- wingman comes to your aid |

These were designed for commanding AI wingmen. The SWIG API exposes them generically -- they work on any ship with any AI. However, no shipped campaign mission imports the AI/Fleet/ scripts directly (the AI system uses them indirectly through compound AI behaviors). In multiplayer, these could power:
- **Cooperative missions with AI wingmen**: Each human player commanding a small fleet
- **Fleet battles**: Human commanders with AI-controlled escorts
- **Asymmetric modes**: One player as commander, others as wingmen

The `ObjectGroupWithInfo` class provides dynamic ship grouping. The AI already takes group-level orders. None of this is used in multiplayer.

**Restoration feasibility**: MODERATE. The AI commands work. Needs Python UI for issuing fleet orders in MP context and network messages to sync orders.

### Ship Class Scoring Modifiers

`Modifier.py` contains a ship class multiplier table:

```python
g_kModifierTable = (
    (1.0, 1.0, 1.0),    # Class 0 (unknown)
    (1.0, 1.0, 1.0),    # Class 1
    (1.0, 3.0, 1.0))    # Class 2
```

`GetModifier(attackerClass, killedClass)` returns a score multiplier. Class 2 killing Class 1 gets 3x score bonus. The scoring path calls `GetModifier` on every kill in Mission5's `DamageHandler`.

**The problem**: Every flyable ship in `SpeciesToShip.py` is assigned class 1 (some non-player entries like UNKNOWN are class 0, but all player-selectable ships are class 1). The modifier system is a no-op for actual gameplay. This was a balance feature designed to incentivize diverse ship choices (small ship kills big ship = bonus points) that was never tuned.

**Restoration feasibility**: TRIVIAL. Assign class values in `SpeciesToShip.py`. The multiplier table and scoring path already work.

### Multi-Set Multiplayer Maps

Opcode 0x1F (EnterSet) handles moving objects between sets over the network. The "Set" system allows multiple playable areas connected by warp points. In single-player, missions use multiple sets (e.g., warp from one system to another). In multiplayer, all maps are single-set.

The infrastructure for multi-set multiplayer exists:
- Network opcode for set transitions
- WarpDrive subsystem on every ship
- Opcode 0x10 (StartWarp) for warp state forwarding
- `WarpHandler` in MissionShared.py processes warp events

**Potential**: "Defend the convoy as it warps between systems", multi-arena battles, strategic retreats to repair at a different set. All networking code exists.

**Restoration feasibility**: MODERATE. Create multi-set MP maps with warp routes. The network protocol already handles it.

### Sensor Array in Multiplayer

The SensorArray subsystem (vtable 0x00893040) exists on every ship. The `ScanHandler` in MissionShared.py processes scan events in MP. But scanning has no gameplay effect in multiplayer -- it plays a voice line and nothing else.

In cooperative/objective modes, scanning could reveal:
- Enemy positions (mini-map pings)
- Objective target information
- Environmental hazards
- Cloaked ship detection

**Restoration feasibility**: MODERATE. Subsystem exists. Needs game logic for scan results in MP context.

### Maps

`SpeciesToSystem.py` defines 9 multiplayer map systems: Multi1 through Multi7 (generic MP maps), plus Albirea and Poseidon (SP locations reused for MP). Seven dedicated MP maps for four shipped modes -- the extra maps were for the cut modes.

---

## Category 1: Developer Tools (Left in Binary)

### 1.1 Python Debug Console (TGConsole)

**Completeness**: FULLY FUNCTIONAL (shipped in retail, just not exposed to players)

| Item | Address/Location |
|------|-----------------|
| TGConsole class | CT_CONSOLE_WINDOW (0x00911638) |
| EvalString method | swig_TGConsole_EvalString @ 0x005d8c70 |
| ToggleConsole | swig_TopWindow_ToggleConsole @ 0x006210c0 -> FUN_0050d7e0 |
| AddConsoleString | swig_TGConsole_AddConsoleString |
| SetConsoleFont | swig_TGConsole_SetConsoleFont |
| SimpleAPI.Edit() | `reference/scripts/SimpleAPI.py:12` |

**How it works**: The console is a full Python REPL window. `TopWindow.ToggleConsole()` creates/shows it. `TGConsole.EvalString(string)` evaluates arbitrary Python code. The `SimpleAPI.py` module provides convenience functions: `Edit()` toggles edit mode and console together, `Speed(f)` sets game speed, `Save(filename)` saves game state.

**Access method**: From the Python console or by calling `App.TopWindow_GetTopWindow().ToggleConsole()`. In debug mode (TestMenuState >= 2), the main menu exposes additional options. The console appears as `MWT_CONSOLE` in the main window tree.

**Restoration feasibility**: TRIVIAL. Call `ToggleConsole()` from any Python handler. Could be bound to a key or triggered from our dedicated server scripts.

---

### 1.2 Debug Cheat Commands

**Completeness**: FULLY FUNCTIONAL (shipped, bound to keys, gated on TestMenuState >= 2)

| Cheat | Event | Handler |
|-------|-------|---------|
| Kill Target (25% damage to targeted subsystem) | ET_INPUT_DEBUG_KILL_TARGET | `TacticalInterfaceHandlers.KillTarget` |
| Quick Repair (fully repair targeted ship) | ET_INPUT_DEBUG_QUICK_REPAIR | `TacticalInterfaceHandlers.RepairShip` |
| God Mode (invulnerability + full repair) | ET_INPUT_DEBUG_GOD_MODE | `TacticalInterfaceHandlers.ToggleGodMode` |
| Load Quantum Torpedoes (+10) | ET_INPUT_DEBUG_LOAD_QUANTUMS | `TacticalInterfaceHandlers.LoadQuantums` / `BridgeHandlers` |
| Toggle Edit Mode | ET_INPUT_DEBUG_TOGGLE_EDIT_MODE | Enables placement editor |

**Key bindings**: The debug key bindings (Shift+K, Shift+R, Shift+G, Ctrl+Q) are present in `KeyboardConfig.py` but **commented out** in the shipped scripts. Only `ET_INPUT_SELF_DESTRUCT` (Ctrl+D) has an active binding. The debug cheats can still be triggered programmatically via Python event posting.

**Gate mechanism**: All cheats check `App.g_kUtopiaModule.GetTestMenuState() < 2` and return immediately if true. The TestMenuState is stored at `g_Clock + 0xB8` (SWIG wrapper at 0x005EB1B0). In the shipped game, this value is 0 (disabled).

**God Mode implementation**: `Game.SetGodMode(bool)` writes to `game_object + 0x60`. `Game.InGodMode()` reads the same field. When enabled, displays "GOD MODE" text overlay and fully repairs the player's ship.

**How to enable**: Call `App.g_kUtopiaApp.SetTestMenuState(2)` from Python. This unlocks all debug keys and additional main menu options (quick-start missions, skip to episodes, etc.).

**Restoration feasibility**: TRIVIAL. One Python call enables everything. The keyboard bindings are already configured in all language variants.

---

### 1.3 Placement Editor (In-Game Level Editor)

**Completeness**: FULLY FUNCTIONAL (developer tool left in binary)

| Item | Evidence |
|------|----------|
| PlacementEditor class | String "PlacementEditor" at 0x008da444 |
| Handler methods | MenuHandler, SaveDialogHandler, DeleteDialogHandler, SwitchSetsDialogHandler, HandleLightConfig, HandleAsteroidFieldConfig, HandleWaypointConfig, EditNameDialogHandler |
| Serialization | Full Python serialization: `App.PlacementObject_Create(name, setName, parent)` |
| Object types | Waypoints (linked-list paths with speed), LightPlacements, AsteroidFieldPlacements |
| Camera support | PlacementWatchMode (camera tracks placement objects) |

**What it can do**: Create and position objects in 3D space, configure asteroid fields (radius, tile count, asteroid density, size factor), place waypoints with speed values, place lights, save/load scene configurations, switch between sets. The editor generates Python code that can recreate the placement.

**Access**: Enabled via `TopWindow.ToggleEditMode()` (exposed through `SimpleAPI.Edit()`). Requires TestMenuState >= 2 for keyboard trigger, but can be called directly from Python.

**Restoration feasibility**: MODERATE. The editor is fully functional but designed for the single-player scene creation workflow. Useful for creating multiplayer maps.

---

### 1.4 CPyDebug (Debug Print System)

**Completeness**: FUNCTIONAL but minimal

| Item | Address |
|------|---------|
| Constructor | swig_new_CPyDebug @ 0x005F9F20 |
| Print method | swig_CPyDebug_Print @ 0x005FA050 |
| Class type | "CPyDebug" at 0x008d9878 |

**Implementation**: `CPyDebug` is a tiny class (4 bytes) that wraps debug output. `CPyDebug_Print` takes a string, converts it via `FUN_007507d0` (PyString_AsString), and calls `func_0x00437350` -- likely OutputDebugString or a log writer.

**Restoration feasibility**: TRIVIAL. Useful for debugging.

---

### 1.5 VoxelizerDebug

**Evidence**: Strings ";_VoxelizerDebug.txt" at 0x0088c5b7 and "VoxelizerDebug.txt" at 0x0088c5cc.

**What it is**: A collision mesh voxelizer that can dump debug output to a text file. The voxelizer converts 3D ship models into volumetric grids for collision detection. The debug output would show the voxelization process.

**Completeness**: The filename strings are compiled in but no named function references the feature. Likely a `#ifdef` debug path in the voxelizer.

**Restoration feasibility**: LOW (would need to find the conditional branch and force it).

---

## Category 2: Cut/Incomplete Game Features

### 2.1 Tractor Beam Docking System

**Completeness**: DEEPLY IMPLEMENTED (C++ classes, SWIG bindings, events, multiplayer message types, campaign usage)

This is the most substantial "hidden" system in the game. While tractor beams work in the shipped game, the full docking mechanic is only used in specific campaign missions.

#### C++ Infrastructure

| Component | Evidence |
|-----------|----------|
| TractorBeamSystem class | 6 modes: TBS_HOLD, TBS_TOW, TBS_PULL, TBS_PUSH, TBS_DOCK_STAGE_1, TBS_DOCK_STAGE_2 |
| TractorBeamProperty | 40+ SWIG getters/setters for beam visual properties (radius, taper, colors, texture) |
| TractorBeamProjector | Separate projector object with orientation/arc properties |
| Mode storage | TractorBeamSystem+0xF4 (written by SetMode) |
| Ship docked flag | ship+0x1E6 (boolean, written by SetDocked, read by IsDocked) |
| Friendly tractor tracking | UtopiaModule: Get/SetFriendlyTractorTime, FriendlyTractorWarning, MaxFriendlyTractorTime |

#### Events

| Event | String Address |
|-------|---------------|
| ET_TRACTOR_BEAM_STARTED_FIRING | 0x00910628 |
| ET_TRACTOR_BEAM_STOPPED_FIRING | 0x009105E8 |
| ET_TRACTOR_BEAM_STARTED_HITTING | 0x00910608 |
| ET_TRACTOR_BEAM_STOPPED_HITTING | 0x009105C8 |
| ET_TRACTOR_TARGET_DOCKED | 0x0091053C |
| ET_FRIENDLY_TRACTOR_REPORT | 0x0090F8A4 |
| ET_DOCK | 0x00910D74 |
| ET_PLAYER_DOCKED_WITH_STARBASE | 0x00910EA4 |

#### Campaign Usage

Docking IS used in the single-player campaign:
- Episode 1 Mission 1 (E1M1): Tutorial teaches docking at starbase, sets `pPlayer.SetDocked(1)` / `SetDocked(0)`
- Episode 3 Mission 1 (E3M1): Undocking sequence
- Episode 6 Mission 2 (E6M2): Tractor target docking event
- Episode 7: Multiple dock/undock sequences
- `AI/PlainAI/EvilShuttleDocking.py`: AI-driven shuttle docking via tractor beam
- `AI/Compound/UndockFromStarbase.py`: AI undocking behavior

#### Multiplayer Status

The docking system has NO multiplayer support. There is no network opcode for dock state synchronization. The IsDocked flag is purely local. The TBS_DOCK_STAGE_1/2 modes suggest a planned 2-phase network-synchronized docking sequence that was never completed for MP.

**Restoration feasibility**: HIGH for single-player enhancement, MODERATE for multiplayer. The C++ code is complete. Adding MP support would require a new opcode or Python message to sync dock state.

---

### 2.2 Self-Destruct

**Completeness**: FULLY FUNCTIONAL (shipped and working in both single-player and multiplayer)

| Item | Evidence |
|------|----------|
| Keyboard binding | Ctrl+D -> ET_INPUT_SELF_DESTRUCT (all language keyboard configs) |
| Input event | "ET_INPUT_SELF_DESTRUCT" at 0x00953920 |
| Network message | "SELF_DESTRUCT_REQUEST_MESSAGE" at 0x00952F44 |
| C++ handler | "TopWindow::SelfDestructHandler" at 0x008E2354 |

**Status**: Self-destruct is a SHIPPED FEATURE that works in both single-player (with voice lines) and multiplayer. In multiplayer, it serves a critical gameplay purpose -- it is the only way to die if you are alone in a match or if an opponent disables your ship and leaves you floating.

**Note**: `TacticalInterfaceHandlers.py` has a commented-out Python handler for `ET_INPUT_SELF_DESTRUCT`, but the actual implementation is in the C++ handler (`TopWindow::SelfDestructHandler`). The commented-out Python code may be an earlier prototype that was superseded by the C++ implementation.

---

### 2.3 Friendly Fire Penalty System

**Completeness**: DEEPLY IMPLEMENTED (C++ tracking, events, Python-accessible API)

| Item | SWIG Function |
|------|--------------|
| Current FF points | UtopiaModule_GetCurrentFriendlyFire / SetCurrentFriendlyFire |
| Max tolerance | UtopiaModule_GetFriendlyFireTolerance / SetMaxFriendlyFire |
| Warning threshold | UtopiaModule_GetFriendlyFireWarningPoints / SetFriendlyFireWarningPoints |
| Tractor FF time | UtopiaModule_GetFriendlyTractorTime / Set |
| Tractor warning | UtopiaModule_GetFriendlyTractorWarning / Set |
| Max tractor time | UtopiaModule_GetMaxFriendlyTractorTime / Set |

| Event | Address |
|-------|---------|
| ET_FRIENDLY_FIRE_DAMAGE | 0x0090F8D8 |
| ET_FRIENDLY_FIRE_REPORT | 0x0090F8C0 |
| ET_FRIENDLY_FIRE_GAME_OVER | 0x0090F888 |
| ET_FRIENDLY_TRACTOR_REPORT | 0x0090F8A4 |

**How it works**: When the player damages friendly ships, friendly-fire points accumulate. When they hit a warning threshold, a report event fires. If they exceed the maximum tolerance, ET_FRIENDLY_FIRE_GAME_OVER fires and the mission fails. The same system tracks how long you hold a tractor beam on a friendly ship.

**Campaign usage**: Used in some missions to punish attacking allies. The thresholds are configurable via Python.

**Multiplayer status**: MissionShared.py calls `MissionLib.SetupFriendlyFireNoGameOver()` on MP mission init, so the basic point tracking IS active in multiplayer. However, no MP mission scripts register event handlers for ET_FRIENDLY_FIRE events, so there are no consequences (no warnings, no kicks). Could be used by the dedicated server to auto-kick team-killers.

**Restoration feasibility**: HIGH. The system is already running in MP. Just needs event handlers registered for warnings and consequences.

---

### 2.4 In-System Warp

**Completeness**: FULLY IMPLEMENTED (C++ + Python, used in campaign)

| Item | Evidence |
|------|----------|
| ShipClass_InSystemWarp | swig @ 0x0060ADF0, calls FUN_005AC6E0 with destination + speed (default 575.0) |
| ShipClass_IsDoingInSystemWarp | swig @ 0x0060AEB0 |
| ShipClass_StopInSystemWarp | swig @ 0x0060AF30 |
| Event | ET_IN_SYSTEM_WARP at 0x0090FAC8 |
| String | "InSystemWarp" at 0x008e61a8 |

**What it does**: Allows a ship to warp to a location WITHIN the current combat set, rather than warping to a different set/mission. The ship accelerates to warp speed (575.0 units default), travels to the destination, and drops out of warp. Different from the full warp-between-sets mechanic.

**Multiplayer potential**: Could enable tactical warping within MP combat arenas. The network opcode 0x10 (StartWarp) already exists. InSystemWarp would need its own message or could reuse the existing warp opcode with a flag.

**Restoration feasibility**: HIGH. The C++ code is complete. Needs a Python trigger and possibly MP state synchronization.

---

### 2.5 Object Emitter System (Probes, Shuttles, Decoys)

**Completeness**: FULLY IMPLEMENTED for probes, ENUM-ONLY for shuttles and decoys

| Emitter Type | Constant | Status |
|-------------|----------|--------|
| OEP_PROBE | ObjectEmitterProperty_OEP_PROBE | FULLY FUNCTIONAL -- used in E6M4 campaign mission |
| OEP_SHUTTLE | ObjectEmitterProperty_OEP_SHUTTLE | Enum constant exists, no campaign usage found |
| OEP_DECOY | ObjectEmitterProperty_OEP_DECOY | Enum constant exists, no campaign usage found |
| OEP_UNKNOWN | ObjectEmitterProperty_OEP_UNKNOWN | Default/placeholder |

**Probe system**: Ships have a SensorSubsystem with GetNumProbes/SetNumProbes/AddProbe. The bridge science menu has a "Launch Probe" button (`ScienceMenuHandlers.py`). Probes are launched as objects into the scene and tracked by the sensor subsystem. However, the probe launch button is **explicitly disabled in multiplayer** (`pLaunch.SetDisabled()` in ScienceMenuHandlers.py lines 104-106).

**Shuttles and Decoys**: The ObjectEmitterProperty type enums exist for shuttles and decoys, but no Python scripts use them. SPECIES_SHUTTLE and SPECIES_ESCAPEPOD exist as object species types. The infrastructure to launch shuttles/decoys exists in the emitter system but was never connected to UI or game logic.

**Restoration feasibility**: MODERATE. The probe launch system is a working template. Shuttles and decoys would need hardpoint definitions, AI behavior, and UI buttons, but the underlying emitter framework is complete.

---

### 2.6 Starbase Repair and Reload

**Completeness**: PARTIALLY IMPLEMENTED (events exist, SWIG accessors exist, limited campaign integration)

| Event/Function | Address |
|-------|---------|
| ET_SB12_REPAIR | 0x00910CF8 |
| ET_SB12_RELOAD | 0x00910CE8 |
| swig_UtopiaModule_GetCurrentStarbaseTorpedoLoad | 0x005ea810 |
| swig_UtopiaModule_SetCurrentStarbaseTorpedoLoad | 0x005ea790 |
| SPECIES_FED_STARBASE | 0x0090F464 |
| SPECIES_CARD_STARBASE | 0x0090F438 |
| SPECIES_DRYDOCK | 0x0090F3F8 |

**What it is**: "SB12" = Starbase 12, a specific campaign location. The events suggest a mechanic where docking at a starbase triggers repair and torpedo reloading. The `CurrentStarbaseTorpedoLoad` tracking suggests torpedoes were meant to be a finite starbase resource.

**Restoration feasibility**: MODERATE. Could be implemented as a multiplayer feature where docking at a station repairs and rearms.

---

### 2.7 Damage Volume System

**Completeness**: FULLY FUNCTIONAL (SHIPPED AND WORKING) -- Visual hull damage with configurable geometry deformation

| Item | Evidence |
|------|----------|
| SWIG function | swig_DamageableObject_AddObjectDamageVolume @ 0x00608CB0 |
| Signature | `Offfff:DamageableObject_AddObjectDamageVolume` (object, x, y, z, radius, damage) |
| Graphics setting | Main menu "Visible Damage" with 4 levels (off / basic / volume / breakable parts) |
| API functions | `SetDamageGeometryEnabled()`, `SetVolumeDamageGeometryEnabled()`, `SetBreakableComponentsEnabled()` |
| Network message | "DAMAGE_VOLUME_MESSAGE" at 0x00952D24 |
| Campaign usage | **25 damage scripts across 8 missions in 7 episodes** (E2M1, E3M2, E3M4, E3M5, E4M6, E5M2, E6M2, E6M4) |

**What it does**: Creates spherical damage zones at specific coordinates on a ship model. `AddObjectDamageVolume(x, y, z, radius, damage)` registers a deformation zone, then `DamageRefresh(1)` commits all zones to the 3D model, creating visible hull damage (chunks missing). Ships like the E3M5 Vor'cha have 31 damage volumes; the E6M2 hulk derelicts have up to 105.

**Graphics setting levels** (mainmenu.py lines 2865-2882):
- Level 0: No visible damage
- Level 1: Basic hull damage geometry (`SetDamageGeometryEnabled`)
- Level 2: + Volume damage deformation (`SetVolumeDamageGeometryEnabled`)
- Level 3: + Breakable components (`SetBreakableComponentsEnabled`)

**Multiplayer status**: DAMAGE_VOLUME_MESSAGE exists as a network message type, so the system could be used in MP maps (area-of-effect mechanics, environmental hazards, pre-damaged derelicts). No stock MP maps use it, but the infrastructure is ready.

**NOT cut content** -- this is a core visual feature used extensively in the campaign.

---

### 2.8 Nebula Damage

**Completeness**: FULLY IMPLEMENTED (C++ + Python, used in campaign)

| Item | Evidence |
|------|----------|
| SWIG function | swig_Nebula_SetupDamage @ 0x00613AE0, calls func_0x00598380 |
| Events | ET_ENTERED_NEBULA (0x00910914), ET_EXITED_NEBULA (0x00910900) |
| Python usage | `Nebula.SetDamageResolution(15.0)` in GlobalPropertyTemplates.py |
| Ship hardpoint | `nebula.py:961` -- `Nebula.SetDamageResolution(10.0)` |

**What it does**: Ships inside nebulae take continuous damage at a configurable rate. `SetupDamage(damagePerTick, -1.0)` configures the damage. `SetDamageResolution` controls damage tick interval. The default resolution of 15.0 is set in `GlobalPropertyTemplates.py` for all ship and object types.

**Campaign usage**: The nebula damage infrastructure is set up globally via templates (all objects have `SetDamageResolution(15.0)`), but no specific campaign mission was found that creates a damaging nebula. The system is ready to use but may only have been used in cut content or testing.

**Multiplayer status**: Nebulae exist as game objects but are not used in MP maps. The damage system would work if a nebula is placed in a MP set.

**Restoration feasibility**: HIGH. Create a nebula object in a MP map and call `SetupDamage()`. The infrastructure is complete.

---

## Category 3: Network Protocol Gaps

### 3.1 Jump Table Opcode Analysis

The MultiplayerGame dispatcher at 0x0069F2A0 uses a jump table at 0x0069F534 with 41 entries (opcodes 0x02 through 0x2A). From the disassembly:

| Opcode | Handler Address | What it does |
|--------|----------------|-------------|
| 0x04 | Falls to default (0x0069F525) | **DEAD** -- no handler code |
| 0x05 | Falls to default (0x0069F525) | **DEAD** -- no handler code |
| 0x16 | Dispatched to MultiplayerWindow | UI collision toggle (separate dispatcher) |
| 0x17 | 0x006a1360 | DeletePlayerUI -- **REAL CODE**: reads stream, creates message object, posts to event queue, then destroys |
| 0x18 | 0x006a1420 | **REAL CODE**: Loads "data/TGL/Multiplayer.tgl", reads "Delete Player" entry, creates text display with 5.0 alpha, adds to scene. This is a "Player X has left" floating text notification |
| 0x1C | 0x006a02a0 | **REAL CODE**: StateUpdate response handler. Reads object ID from stream, looks up ship, checks if shields are up, gets model bounds, serializes ship state, creates network message, sends to specific peer. Also calls FUN_00595c60 (handles shield notification). NOTE: This jump table index maps to opcode 0x1E (RequestObj response), see opcode table in CLAUDE.md for verified mapping. |

**Key findings**:
- Opcodes 0x04 and 0x05 are truly dead -- the jump table entries point to the default handler that just clears the processing flag and returns
- Opcode 0x17 is a "delete player UI notification" handler with real code
- Opcode 0x18 creates floating text showing "Player X has left" -- a player disconnect notification that was implemented but may not trigger in all disconnect scenarios
- Opcode 0x1C is a substantial handler that responds to object data requests by serializing and sending ship state

### 3.2 Unused Network Message Types

From the message type string table, these message types have names registered but limited or no usage:

| Message | Used? |
|---------|-------|
| SELF_DESTRUCT_REQUEST_MESSAGE | YES -- used by C++ handler (TopWindow::SelfDestructHandler) |
| DAMAGE_VOLUME_MESSAGE | YES -- shipped feature, used by AddObjectDamageVolume/DamageRefresh (25 campaign scripts) |
| CLIENT_READY_MESSAGE | Unknown -- may be used in initial handshake |
| CHANGED_TARGET_MESSAGE | Used by targeting system but undocumented |
| TORPEDO_POSITION_MESSAGE | Likely used for torpedo sync (opcode 0x19) |
| CREATE_PULSE_MESSAGE | Used by pulse weapon system |

---

## Category 4: Notable Species/Object Types

The following SPECIES_ constants represent object types with varying levels of usage. Some are fully used in campaign, others exist as infrastructure only.

| Species | Status | Notes |
|---------|--------|-------|
| SPECIES_ESCAPEPOD | **UNUSED** | Escape pod entity type. No Python scripts create or reference escape pods. |
| SPECIES_SUNBUSTER | **UNUSED** | Unknown weapon/object. No scripts reference it. Name suggests a superweapon. |
| SPECIES_SHUTTLE | Campaign | Shuttle entity. Used in campaign missions as dockable objects and AI-controlled craft. |
| SPECIES_TRANSPORT | Campaign | Transport ship. Used in escort missions. |
| SPECIES_PROBETYPE2 | **UNUSED** | Second probe variant. Only SPECIES_PROBE is used in scripts. |
| SPECIES_DRYDOCK | Campaign | Drydock station. Exists as a species with limited campaign usage. |
| SPECIES_KESSOKMINE | Campaign | Kessok mine entity. Used in E7M3 and E3M2 campaign missions. Also in QuickBattle. |

---

## Category 5: Conditional Compilation / Feature Flags

### 5.1 TestMenuState (Developer Menu Gate)

**Address**: g_Clock + 0xB8 (read by swig_UtopiaModule_GetTestMenuState at 0x005EB1B0)

| State | What it enables |
|-------|----------------|
| 0 | Normal retail mode (default) |
| 1 | Partial debug (some main menu options) |
| >= 2 | Full debug: god mode, kill target, quick repair, load quantums, PlacementEditor, episode skip, quick mission start |
| >= 3 | Additional tactical menu options |

**Main menu extras at TestMenuState >= 2** (from mainmenu.py): Quick-start any mission, skip to specific episodes, bypass normal game flow.

### 5.2 TGMEMORY_DEBUG

**String**: "Define TGMEMORY_DEBUG if you want to see mem-info.\n" at 0x0095C598

This is a compile-time flag. When defined, the memory allocator (NiAlloc/NiFree at 0x00717840/0x00717960) would output allocation statistics. In the shipped binary, this flag was NOT defined, so the message is just an informational string.

### 5.3 Assert System

The game has a full assert dialog system (strings at 0x0095C7CC-0x0095C854) that copies assertion info to clipboard and debugger log. In release builds, asserts are likely compiled out, but the dialog code remains.

---

## Restoration Priority Ranking

### Tier 1: Trivial (Python-only, no binary changes, days of work)

1. **Ship Class Scoring** -- Assign class values in `SpeciesToShip.py`. Modifier table and scoring path already work.
2. **Friendly Fire Tracking** -- Register event handlers in MP Python scripts. System fully works.
3. **Debug Console** -- Call `TopWindow.ToggleConsole()`. Instant Python REPL.
4. **Debug Cheats** -- Call `UtopiaApp.SetTestMenuState(2)`. God mode, kill, repair, load quantums.

### Tier 2: Write New Mission Scripts (Python-only, 1-2 weeks)

6. **Mission7: Cooperative Borg Hunt** -- All infrastructure exists in MissionShared.py. Write the mission folder with setup script, menus, and Borg Cube spawn logic. Highest value restoration target.
7. **Mission9: Destroy the Enterprise** -- Same deal. Asymmetric PvP/PvE mode. Write the mission folder.
8. **Mission6: Starbase Variant** -- Clone Mission5 with modified rules (reversed teams, different victory conditions).
9. **Nebula Damage in MP Maps** -- Place nebula objects, configure damage. Existing system just needs map content.

### Tier 3: Moderate Effort (Python + new network messages, 2-4 weeks)

10. **Starbase Docking/Repair** -- Wire the ~660-line `DockWithStarbase.py` to multiplayer. Needs dock state sync message. Game-changing for longer matches.
11. **In-System Warp** -- Add warp points to MP maps, Python trigger, MP state sync. Enables tactical repositioning.
12. **Fleet Command in MP** -- Expose the DefendTarget/DestroyTarget/DisableTarget/HelpMe AI commands to human players in MP. Needs command UI + network sync.
13. **Probe Launch in MP** -- Science menu button exists. Need MP sync for probe objects.
14. **Damage Volumes in MP** -- Damage volumes are a shipped SP feature. For MP, use AddObjectDamageVolume in map scripts for pre-damaged derelicts, environmental hazards, or minefields. Infrastructure exists (DAMAGE_VOLUME_MESSAGE), just needs map content.

### Tier 4: Significant Effort (New game logic, months)

15. **Tractor Beam Docking in MP** -- Need network sync for beam state + 2-stage docking sequence. 80+ SWIG bindings exist but no MP opcodes.
16. **Multi-Set MP Maps** -- Create multi-set maps with warp routes between combat areas. Network protocol already handles set transitions.
17. **Shuttle/Decoy Launch** -- Emitter framework exists but needs AI behaviors, models, and UI.
18. **Escape Pods** -- Species type exists but no game logic. Could tie into player death (eject before destruction).
19. **Cooperative Fleet Battles** -- The dream: human commanders with AI wingmen, fleet orders, starbase docking for repair, tractor beams for rescue. Every piece exists in code -- it was never wired together.

### The Dream Feature

A cooperative Borg Hunt (Mission7) with:
- 4 human players each commanding a small task group (Fleet AI)
- AI wingmen following tactical orders (DefendTarget, DestroyTarget, HelpMe)
- Starbase docking for repair and rearm between engagements (DockWithStarbase)
- Tractor beams for rescuing escape pods (TractorBeamSystem)
- Nebula as tactical cover with damage zones (Nebula.SetupDamage)
- Ship class scoring bonuses for smaller ships engaging the Cube (Modifier.py)

Every single piece of this existed in the Bridge Commander codebase. It was never wired together.

---

## Appendix: Complete Event ID Catalog (Debug/Hidden)

| Event | String Address | Used in Scripts? |
|-------|---------------|-----------------|
| ET_INPUT_DEBUG_KILL_TARGET | 0x009534CC | YES (keyboard bound, gated) |
| ET_INPUT_DEBUG_QUICK_REPAIR | 0x009534B0 | YES (keyboard bound, gated) |
| ET_INPUT_DEBUG_GOD_MODE | 0x00953498 | YES (keyboard bound, gated) |
| ET_INPUT_DEBUG_LOAD_QUANTUMS | 0x00953478 | YES (keyboard bound, gated) |
| ET_INPUT_DEBUG_TOGGLE_EDIT_MODE | 0x00953458 | YES (registered in App.py, commented out in KeyboardConfig.py) |
| ET_INPUT_SELF_DESTRUCT | 0x00953920 | YES (Ctrl+D, functional in SP + MP) |
| ET_SB12_REPAIR | 0x00910CF8 | Unknown |
| ET_SB12_RELOAD | 0x00910CE8 | Unknown |
| ET_CONTACT_STARFLEET | 0x00910CC4 | Campaign only |
| ET_CONTACT_ENGINEERING | 0x00910CAC | Campaign only |
| ET_CLOAKED_COLLISION | 0x00910A60 | Unknown |
| ET_FRIENDLY_FIRE_GAME_OVER | 0x0090F888 | Campaign only |
| ET_FRIENDLY_FIRE_REPORT | 0x0090F8C0 | Campaign only |
| ET_FRIENDLY_FIRE_DAMAGE | 0x0090F8D8 | Campaign only |
| ET_FRIENDLY_TRACTOR_REPORT | 0x0090F8A4 | Campaign only |

## Appendix: Full Tractor Beam Mode Enum

```
TBS_HOLD         = 0  # Hold target in place
TBS_TOW          = 1  # Tow target behind ship
TBS_PULL         = 2  # Pull target toward ship
TBS_PUSH         = 3  # Push target away from ship
TBS_DOCK_STAGE_1 = 4  # First stage of docking approach
TBS_DOCK_STAGE_2 = 5  # Final docking alignment/lock
```
