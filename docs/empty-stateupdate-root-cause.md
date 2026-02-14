# Root Cause Analysis: Empty StateUpdates (flags=0x00 vs 0x20) — RESOLVED

Date: 2026-02-10 (analysis), 2026-02-14 (resolved)
Source: Agent analysis of FUN_005b17f0 code path + stock-dedi comparison

## The Problem

| Aspect | Stock Server | Our Server |
|--------|-------------|------------|
| NIF model loading | Works (real D3D7) | Fails (stubbed renderer) |
| Ship subsystem list (+0x284) | Populated (10+ subsystems) | NULL |
| FUN_005b17f0 called | Yes | Yes |
| 0x20 flag initially set | Yes | Yes |
| PatchNetworkUpdateNullLists | N/A (stock has no patch) | Clears 0x20 because +0x284 is NULL |
| Final flags sent | 0x20 (SUB) or 0x9D (full) | 0x00 (empty) |

## 5-Step Causal Chain

### Step 1: FUN_005b17f0 IS called, and 0x20 (SUB) IS set

The flags logic at line 54190-54207 of `reference/decompiled/05_game_mission.c`:

```c
bVar19 = DAT_0097fa8a == '\0';  // IsMultiplayer == 0? false for us

if (bVar19) { bVar6 |= 0x80; goto LAB_005b1cd1; }  // SKIPPED (MP mode)

if (DAT_0097faa2 != '\0') { ... }  // SKIPPED (friendlyFire=0)

bVar6 = bVar6 | 0x20;  // flags now include 0x20 (SUB)
```

When friendlyFire=0 (both servers), the player-count throttle is bypassed entirely.
0x20 always gets set. Identical behavior on both servers.

### Step 2: The "early abort" does NOT fire

```c
if (bVar6 == 0) { return NULL; }  // bVar6 = 0x20, NOT zero, continues
```

### Step 3: PatchNetworkUpdateNullLists clears the 0x20 flag

Our binary patch at 0x005b1d57 (`ddraw_main.c` PatchNetworkUpdateNullLists):

```asm
MOV EAX,[ESI+0x284]   ; load subsystem list head pointer
TEST EAX,EAX          ; is it NULL?
JNZ .has_lists         ; if not NULL, skip clearing
AND byte [ESP+0x18],0x5F  ; CLEAR bits 0x20 and 0x80 from flags
.has_lists:
```

On headless server, `ship+0x284` is NULL (no subsystem linked list).
Patch correctly clears flags to prevent malformed packet.
Result: flags = 0x00 (only 0x20 was set, and it got cleared).

### Step 4: Position flags are also zero

Position delta-checking at line 54135 is guarded by dirty-tracking state.
For a ship deserialized from network with zeroed tracking state, no dirty flags fire.
On stock server, real NIF model = real position data = dirty checks find changes.

### Step 5: Ship has no subsystem list because NIF models don't load headlessly

Subsystem creation chain:
1. **Python hardpoint file** defines SubsystemProperty objects
2. **AddToSet("Scene Root", prop)** (C++ FUN_006c9520) links each property to NiNode named "Scene Root" in NIF model
3. **FUN_005b3fb0** iterates linked properties, creates runtime subsystem objects at `ship+0x284`

Step 2 is the bottleneck:
- `AddToSet` searches the NIF model for NiNode named "Scene Root"
- No renderer -> NIF models can't load properly -> no "Scene Root" node
- AddToSet returns 0 (failure)
- No properties linked -> FUN_005b3fb0 finds nothing -> subsystem list stays NULL

## Fix Approaches (ordered by complexity)

### 1. Enable NIF model loading on headless server (MEDIUM complexity, HIGH impact)
NIF loading (NiStream::Load) is file I/O, not renderer-dependent. If the NiDX7Renderer
pipeline can be restored enough to not crash during NIF loading, the entire subsystem
chain works automatically. This would produce flags=0x20 with real subsystem data.

### 2. Synthesize subsystem data in StateUpdate packet (HIGH complexity)
Binary patch to intercept flags byte write and inject synthetic subsystem data
(all 0xFF = full health). Requires understanding exact wire format for subsystem updates.

### 3. Accept flags=0x00 and fix client-side consequences (LOW complexity, PARTIAL)
If client can tolerate 0x1C with flags=0x00, session may function.
But client likely treats missing SUB data as connection failure.

**Recommended: Option 1** - get NIF models to load on the headless server.
The subsystem chain is entirely file-I/O-based once the NiStream is functional.

## Resolution (2026-02-14)

**Option 1 was implemented** via DeferredInitObject — a Python-driven ship creation path:

1. C-side `GameLoopTimerProc` detects new ship objects (polls after InitNetwork fires)
2. Python `DeferredInitObject(playerID)` determines ship class from SpeciesToShip mapping
3. Calls `ship.LoadModel(nifPath)` on the ship object via SWIG API
4. Engine's AddToSet/SetupProperties pipeline runs, creating 33 runtime subsystem objects
5. Ship+0x284 linked list is now populated
6. StateUpdate sends `flags=0x20` with real subsystem health data

**Key insight**: NIF loading works on the headless server because the full NiDX7Renderer
pipeline was restored (PatchNullSurface JNZ fix). The renderer doesn't draw frames (render
tick is patched), but the pipeline objects exist, so NIF loading and scene graph construction
succeed.

**Combined with InitNetwork timing fix**: The `bc` flag at peer+0xBC was unreliable (200+
ticks to flip, or never). Replaced with peer-array appearance detection, bringing InitNetwork
timing from ~13s to ~1.4s (stock is ~2s).

**Result**: Collision damage and subsystem damage both work. Client stays connected for
extended sessions.
