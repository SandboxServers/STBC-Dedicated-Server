# Alternative Approaches to Headless Dedicated Server

## Analysis Date: 2026-02-09
## Context: Current DDraw proxy approach has ~100 VEH crashes/sec, cascade failures

## Approach Ranking (Least Effort to Most)

### 1. DAT_00995a3c Render Suppression Flag (INVESTIGATE FIRST)
- In FUN_0043b4f0 (MainTick) at decompiled line 5053: `if (DAT_00995a3c < 1)` gates render path
- If this is a counter/flag, writing 1 to 0x00995a3c skips ALL rendering in MainTick
- Simulation, events, timers, networking all still run (they execute BEFORE the render gate)
- Still need DDraw proxy for initial D3D setup, but per-frame VEH crashes should stop
- RISK: May have side effects (is it a "loading" flag? a "minimized" flag?)
- ACTION: Use Ghidra to find all writes to 0x00995a3c and understand its lifecycle

### 2. Stub Only Final Draw Calls (Current Approach, Corrected)
- Let renderer initialize FULLY (remove PatchSkipRendererSetup - already done)
- Let NIF loading run normally (scene graphs will be complete)
- Let SetupProperties run (subsystems/weapons will be populated)
- Stub ONLY in D3D7 proxy: DrawPrimitive, DrawIndexedPrimitive, Flip, Blt-for-present
- Remove PatchRenderTick (let render tick run as fast no-op chain)
- Remove most VEH targeted skips (should be unnecessary with complete scene graphs)
- Keep PatchTGLFindEntry (TGL UI data legitimately missing)
- KEY METRIC: Zero VEH fires during steady-state gameplay = correct implementation

### 3. Small Hidden Window + Real D3D (Simplest Possible)
- Create real window (64x64 or minimum), hide/minimize immediately
- Real DirectDraw7, real D3D7, real device, real surfaces (system memory)
- Only stub Present/Flip (return S_OK, never display)
- Everything else runs completely stock
- Higher CPU/GPU cost but zero risk of cascade failures
- Good as a validation step: "does the game work headless if rendering is a no-op?"

### 4. Full Reimplementation of Network Protocol (Nuclear Option)
- Write a standalone server from scratch
- Implement TGWinsockNetwork UDP protocol
- Implement checksum exchange
- Implement game state management
- Implement simulation (or skip it and relay client state)
- MASSIVE effort, months of work, likely more than fixing current approach
- Only makes sense if BC's engine is truly unfixable (it is not)

## Why the Current VEH Cascade Happens
Root cause chain:
1. PatchSkipRendererSetup (now removed) skipped renderer pipeline at 0x007C39CF
2. NIF loader needs renderer internal state (texture dict, geometry group mgr)
3. Without those, NIF loads produce incomplete scene graphs
4. Incomplete scene graphs -> NULL subsystem/weapon linked lists
5. FUN_005b17f0 (network state update) iterates those lists with NO null checks
6. NULL deref -> VEH handler redirects to dummy -> vtable through zeroed memory -> cascade

Fix: Let the renderer pipeline complete. Scene graphs will be complete. Lists will be
populated. VEH handler becomes a safety net that never fires, not a per-tick necessity.

## Key Architectural Facts
- NetImmerse 3.1: scene graph = render graph, no separation possible
- Ship hardpoints are NiNode children found by name in the geometry tree
- NiBound (collision volumes) computed from child geometry vertices
- NIF loader requires renderer+0xC8 (geometry group mgr) for vertex buffer allocation
- Simulation reads from scene graph (positions, rotations, bounds) but never writes pixels
- The "dedicated server" has always been "full engine minus one player ship"
