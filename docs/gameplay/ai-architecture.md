# AI Architecture

Reverse-engineered implementation details of Bridge Commander's hierarchical behavior tree AI system. Covers the C++ runtime classes, Python scripting bridge, tick scheduling, and shipped behavior catalog.

---

## 1. C++ Class Hierarchy

```
BaseAI (0x0088bb54)
├── PlainAI (0x0088c0d8)
├── ConditionalAI (0x0088bc84)
├── PriorityListAI (0x0088c188)
├── RandomAI (0x0088c1dc)
├── SequenceAI (0x0088c230)
└── PreprocessingAI (0x0088c12c)
      └── BuilderAI (0x0088bbe0)
```

All AI classes inherit from BaseAI. PreprocessingAI extends BaseAI, and BuilderAI extends PreprocessingAI. The remaining five (PlainAI, ConditionalAI, PriorityListAI, RandomAI, SequenceAI) are direct children of BaseAI.

### Constructor Addresses

| Class | Constructor | Vtable | AllocAndConstruct |
|-------|-----------|--------|-------------------|
| BaseAI | 0x00470520 | 0x0088bb54 | (abstract — no factory) |
| PlainAI | 0x0048cc40 | 0x0088c0d8 | cdecl wrapper exists |
| ConditionalAI | 0x00478a50 | 0x0088bc84 | cdecl wrapper exists |
| PriorityListAI | 0x0048fcb0 | 0x0088c188 | cdecl wrapper exists |
| RandomAI | 0x00491370 | 0x0088c1dc | cdecl wrapper exists |
| SequenceAI | 0x004927d0 | 0x0088c230 | cdecl wrapper exists |
| PreprocessingAI | 0x0048e2b0 | 0x0088c12c | cdecl wrapper exists |
| BuilderAI | 0x00475fb0 | 0x0088bbe0 | cdecl wrapper exists |

Each AI class has both a `__thiscall` constructor and a `__cdecl` AllocAndConstruct wrapper that calls `NiAlloc()` then the constructor. The SWIG API (`App.PlainAI_Create`, etc.) calls the AllocAndConstruct wrappers.

---

## 2. Virtual Method Table

The BaseAI vtable defines the core dispatch points for the behavior tree:

| Slot | Method | Description |
|------|--------|-------------|
| 0 | SetActive | Called when the node becomes active in the tree |
| 1 | SetInactive | Called when the node is deactivated |
| 2 | GotFocus | Called when this node gains execution focus from its parent |
| 3 | LostFocus | Called when this node loses focus (higher priority sibling took over) |
| 4 | Update | Main tick method — returns state (ACTIVE/DORMANT/DONE) |
| 5 | IsDormant | Returns whether this node is currently dormant |

Derived classes override these methods. PlainAI dispatches `Update` to the Python script's `Update()` method. ConditionalAI's `Update` evaluates conditions before calling the contained child. PriorityListAI iterates children by priority.

### Node Return States

```c
enum UpdateStatus {
    US_ACTIVE  = 0,  // Currently executing
    US_DORMANT = 1,  // Temporarily inactive
    US_DONE    = 2   // Completed or failed
};
```

Exposed to Python as `App.ArtificialIntelligence.US_ACTIVE`, `US_DORMANT`, `US_DONE`.

---

## 3. Ship AI Tick Scheduling

Each ship has an AI tick scheduler that invokes the root AI node's `Update()` at a configurable rate.

| Function | Address | Description |
|----------|---------|-------------|
| Ship__AITickScheduler | 0x004721b0 | Checks elapsed time, decides whether to call ProcessAITick |
| Ship__ProcessAITick | 0x004722d0 | Calls the root AI node's Update(), processes return value |

The tick rate is not fixed — individual AI scripts can request their next update interval. For example, `CircleObject.GetNextUpdateTime()` returns 0.5 seconds, while `Intercept.GetNextUpdateTime()` returns 0.4 ± 0.2 seconds (randomized to prevent synchronized updates across ships).

The scheduler is called from the main game loop's update pass. Each ship's AI is independent — there is no global AI coordinator.

---

## 4. Python/C++ Bridge

### pCodeAI Handle

Every Python AI script receives a `pCodeAI` reference to its C++ AI object. This is the bridge between Python behavior logic and C++ runtime:

```python
class BaseAI:
    def __init__(self, pCodeAI):
        self.pCodeAI = pCodeAI
```

Key methods on `pCodeAI`:
- `GetShip()` — returns the ship this AI controls
- `RegisterExternalFunction(name, dict)` — registers a callable for the C++ runtime
- `StopCallingActivate()` — optimization: tells C++ to stop calling `Activate()` if the base class version has nothing to do

### Script Lifecycle

1. **Creation**: `App.PlainAI_Create(pShip, "Name")` → C++ allocates PlainAI → Python script `__init__(pCodeAI)` called
2. **Configuration**: Python code calls setup methods (e.g., `SetFollowObjectName`, `SetCircleSpeed`)
3. **Activation**: When the node becomes active in the tree, `Activate()` is called — validates required params
4. **Update loop**: `Update()` called each AI tick — returns US_ACTIVE/US_DORMANT/US_DONE
5. **Deactivation**: `LostFocus()` called when interrupted, `SetInactive()` when fully removed

### Save/Load

AI state is serialized via Python's `pickle` protocol:
- `__getstate__()` — returns `__dict__` copy, converts module references to strings
- `__setstate__(dict)` — restores dict, re-imports modules
- `FixCodeAI(pCodeAI)` — called after load to update the C++ pointer (which is invalid after deserialization)

Save/load helpers:
| Function | Address | Role |
|----------|---------|------|
| SaveGame__InitPickler | 0x006f9fb0 | Creates cPickle.Pickler |
| SaveGame__FlushPickler | 0x006fa020 | marshal.dump + writes pickled data |

---

## 5. AI Node Behaviors

### PlainAI (Leaf Nodes)

PlainAI wraps a Python script class. The C++ runtime calls the script's `Update()` method each tick, which controls the ship via SWIG API calls (SetImpulse, TurnTowardLocation, etc.).

**27 shipped PlainAI scripts** (from `reference/scripts/AI/PlainAI/`):

| Script | Behavior |
|--------|----------|
| CircleObject | Orbit target using fuzzy logic for distance/facing decisions |
| IntelligentCircleObject | CircleObject with shield-aware facing (turns damaged shield away) |
| Intercept | Fly to predicted intercept point of moving target, with obstacle avoidance |
| Flee | Disengage from combat, fly away from target |
| FollowObject | Maintain formation distance behind a leader |
| FollowThroughWarp | Follow a target through warp transitions between sets |
| FollowWaypoints | Follow a sequence of waypoints with per-waypoint speed |
| GoForward | Fly straight ahead at configured speed |
| Stay | Hold position (zero throttle) |
| TorpedoRun | Approach from optimal torpedo angle, fire, break away |
| PhaserSweep | Maintain phaser firing arc, sweep beam across target |
| StationaryAttack | Attack without moving (turret mode) |
| StarbaseAttack | Attack approach optimized for large stationary targets |
| Ram | Direct collision course with target |
| Defensive | Defensive maneuvering (shield management priority) |
| ManeuverLoop | Execute pre-defined maneuver pattern |
| MoveToObjectSide | Position on specific side of target |
| TurnToOrientation | Rotate to face specific direction |
| Warp | Engage warp drive to destination set |
| SelfDestruct | AI-triggered self-destruct (calls `DestroySystem(hull)` instead of Ctrl+D path) |
| TriggerEvent | Fire a game event |
| RunAction | Execute a timed action sequence |
| RunScript | Run arbitrary Python script as AI behavior |
| EvadeTorps | Dodge incoming torpedoes |
| EvilShuttleDocking | Hostile shuttle docking approach |

### ConditionalAI

Contains one child AI and one or more `ConditionScript` objects. Each tick:
1. All conditions evaluated → boolean results
2. Evaluation function (Python) maps results to US_ACTIVE/US_DORMANT/US_DONE
3. If ACTIVE, child AI's Update() is called

### PriorityListAI

Ordered list of children with priorities. Evaluates highest-priority first. First child returning US_ACTIVE wins; lower-priority children are interrupted (if `SetInterruptable(1)`).

### SequenceAI

Runs children in order. When one returns US_DONE, advances to next. Sequence completes when all children are done.

### RandomAI

Randomly selects one child to execute. When that child completes, picks another randomly.

### PreprocessingAI

Wraps a child AI with a preprocessing step. The preprocessor runs before the child each tick. Used for cross-cutting concerns:
- `FireScript` — auto-fire weapons at target
- `AvoidObstacles` — steer away from nearby objects
- `ShieldManager` — adjust shield facing
- `WarpBeforeDeath` — emergency warp at low hull

### BuilderAI

Meta-node extending PreprocessingAI. Used by compound AI scripts (FedAttack, NonFedAttack) to declaratively build ~30-node behavior trees. Assembles named blocks with dependency relationships:

```python
pBuilderAI = App.BuilderAI_Create(pShip, "Name", __name__)
pBuilderAI.AddAIBlock("TorpRun", "BuilderCreate1")
pBuilderAI.AddDependencyObject("TorpRun", "sTarget", sTarget)
```

---

## 6. Compound AI Behaviors

**15 shipped Compound AI scripts** (from `reference/scripts/AI/Compound/`):

| Script | Purpose |
|--------|---------|
| BasicAttack | Entry point: selects FedAttack/NonFedAttack/CloakAttackWrapper based on species+cloak |
| FedAttack | Federation attack — torpedo runs, phaser sweeps, shield management (~30 nodes via BuilderAI) |
| NonFedAttack | Non-Federation attack — more aggressive maneuvering |
| CloakAttack | Cloak → approach → decloak → alpha strike → recloak cycle |
| CloakAttackWrapper | Wraps CloakAttack with fallback to non-cloak attack |
| Defend | Protect a target ship — follow + engage attackers |
| DockWithStarbase | Full docking sequence (approach, dock, repair/rearm, undock) |
| UndockFromStarbase | Undocking sub-behavior |
| StarbaseAttack | Attack stationary targets with varied approach angles |
| ChainFollow | Follow leader ship in formation |
| ChainFollowThroughWarp | Follow leader through warp transitions |
| FollowThroughWarp | Follow target through warp (simpler than ChainFollow) |
| TractorDockTargets | Tractor beam docking behavior |
| CallDamageAI | Switch to damage-appropriate AI when hit |

**5 Compound Parts** (sub-behaviors reused by multiple compounds):
- `EvadeTorps`, `ICOMove`, `SweepPhasers`, `WarpBeforeDeath`, `NoSensorsEvasive`

### BasicAttack Difficulty System

AI difficulty is a 0.0–1.0 float. The `g_lFlagThresholds` table maps difficulty ranges to enabled behavior flags:

| Difficulty | Enabled Flags |
|-----------|---------------|
| 1.0 | All 18 flags enabled (torpedo selection, phaser optimization, subsystem targeting, etc.) |
| 0.5 | 8 flags: UseRearTorps, UseSideArcs, SmartShields, ChooseSubsystemTargets, AvoidTorps, NeverSitStill, PowerManagement, SmartTorpSelection |
| 0.0 | InaccurateTorps + DumbFireTorps only |

Three difficulty presets (Easy_, default, Hard_) with per-game-difficulty overrides.

---

## 7. Fleet Commands

**5 shipped Fleet command scripts** (from `reference/scripts/AI/Fleet/`):

| Command | Script | Behavior |
|---------|--------|----------|
| DefendTarget | AI.Fleet.DefendTarget | Compound.Defend wrapped in ConditionalAI (target exists + same set) |
| DestroyTarget | AI.Fleet.DestroyTarget | BasicAttack wrapped in ConditionalAI |
| DisableTarget | AI.Fleet.DisableTarget | BasicAttack with DisableOnly=1 |
| HelpMe | AI.Fleet.HelpMe | Come to player's aid |
| DockStarbase | AI.Fleet.DockStarbase | Order wingman to dock for repair |

Each command wraps its core AI in a ConditionalAI checking `ConditionAllInSameSet` (target + player + ship).

---

## 8. Player AI

**26 Player AI scripts** (from `reference/scripts/AI/Player/`):

Used when the human player issues high-level commands from the tactical UI. These are full behavior trees that auto-pilot the player's ship.

Categories:
- **Destroy** variants: DestroyFreely, DestroyFore, DestroyAft, DestroyFromSide, DestroyFaceSide + Close/Maintain/Separate range variants
- **Disable** variants: mirror of Destroy but with DisableOnly=1
- **Movement**: FlyForward, InterceptTarget, OrbitPlanet, PlayerWarp, Stay, StaySelectTarget
- **Defense**: Defense, DefenseNoTarget

---

## 9. Condition System

36 shipped condition scripts (from `reference/scripts/Conditions/`). Used by ConditionalAI nodes.

Created via: `App.ConditionScript_Create("Conditions.ConditionName", "Name", ...args)`

Key conditions: ConditionInRange, ConditionFacingToward, ConditionAttacked, ConditionSystemBelow, ConditionTorpsReady, ConditionIncomingTorps, ConditionShipDisabled, ConditionAllInSameSet, ConditionInLineOfSight, ConditionInNebula, ConditionTimer, ConditionFlagSet.

---

## 10. AI Preloading

`AI.Setup.GameInit()` (called from C++ via `CreateMultiplayerGame` at 0x00504F10) pre-imports 73 AI modules to prevent hitching during gameplay:
- 27 PlainAI scripts
- 15 Compound AI scripts + 5 Parts
- 5 Fleet commands
- 36 Condition scripts (no DockStarbase — likely intentional omission)

---

## 11. Fuzzy Logic

`CircleObject` uses `App.FuzzyLogic()` for distance/facing decisions. The fuzzy system has 4 input sets (far-facing-away, far-facing-toward, near-facing-good, near-facing-bad) and 4 output sets (stop-turn-toward, fast-turn-toward, stop-turn-side, fast-turn-side). Percentage membership is computed from dot products and distance, then the output is a blended speed/turn command.

Other AIs use simpler threshold-based logic rather than fuzzy sets.

---

## 12. Multiplayer Relevance

**Stock multiplayer has NO AI opponents.** AI is single-player/campaign only in the shipped game. There is no bot system, no AI-controlled ships in MP matches, and no fleet command network synchronization.

The AI system is entirely client-local — the C++ AI tick scheduler runs only on the machine that owns the ship. In single-player, all ships are local. For future MP AI (OpenBC #158), AI state would need to be replicated or AI decisions would need to be server-authoritative.

---

## Related Documents

- [ship-navigation.md](ship-navigation.md) — Ship movement/targeting functions that AI scripts call
- [damage-system.md](damage-system.md) — Damage pipeline that AI combat behaviors interact with
- [weapon-firing-mechanics.md](weapon-firing-mechanics.md) — Weapon systems controlled by FireScript preprocessor
- [cloaking-state-machine.md](cloaking-state-machine.md) — Cloak states used by CloakAttack compound AI
- [self-destruct-pipeline.md](self-destruct-pipeline.md) — Self-destruct path (AI uses different entry point)
