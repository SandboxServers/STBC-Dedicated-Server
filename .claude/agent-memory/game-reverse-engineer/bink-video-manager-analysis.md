# DAT_00995a3c Analysis: Bink Video Active Count

## Identity
- **Address**: 0x00995a3c
- **Type**: `int` (4 bytes, signed)
- **Semantics**: Active Bink video count -- number of currently playing Bink video overlays
- **Parent structure**: BinkVideoManager at 0x00995a00, field at offset +0x3C
- **NOT a boolean or enum** -- it's a count, ranges from 0 to 5 (max enforced by FUN_006aeeb0)

## Structure: BinkVideoManager (at 0x00995a00)

```
Offset  Size  Field
+0x00   0x3C  BinkEntry[5] array, each entry is 12 bytes (0x0C):
              +0x00: int   sceneObject (NiObject ptr or 0)
              +0x04: int   binkHandle (from BinkOpen)
              +0x08: char  flags/status byte
+0x3C   4     activeCount (DAT_00995a3c) -- number of active video entries
+0x40   1     needsRendererInit (bool) -- set by FUN_006af650, cleared by FUN_006afa40
+0x44   4     binkBuffer (from BinkBufferOpen, or standalone BinkOpen handle)
+0x48   4     loadingBinkHandle (for loading screen video, from BinkOpen)
+0x4C   4     videoConfigObj (allocated 0x1C bytes, has vtable at 0x0088b9f8)
+0x50   4     screenWidth
+0x54   4     screenHeight
+0x58   4     colorDepth (0x10=16bit or 0x20=32bit)
+0x5C   1     flag (related to fullscreen mode)
+0x5D   1     flag2
+0x5E   1     enabled (set to 1 in FUN_006aecd0 init)
+0x60   4     float (1.0f = 0x3f800000, volume/scale?)
```

## Write Sites (Who Sets activeCount)

### 1. FUN_006aecd0 -- Initialization (sets to 0)
- Called from: FUN_006aeca0 (wrapper)
- Code: `*(undefined4 *)(param_1 + 0x3c) = 0;`
- When: During BinkVideoManager construction/reset
- Also sets: +0x5E=1 (enabled), +0x60=1.0f, allocates videoConfigObj at +0x4C

### 2. FUN_006aeeb0 -- Add Video (increments by 1)
- Called from: FUN_006b0820 (video start handler)
- Code: `*(int *)((int)this + 0x3c) = *(int *)((int)this + 0x3c) + 1;`
- Guard: `if (5 < (int)uVar1) return;` -- max 5 videos
- When: A Bink video starts playing (cutscene, intro, etc.)
- Also: Opens Bink file with BinkOpen, stores handle at entries[count].binkHandle

### 3. FUN_006aee10 -- Remove Video (decrements by 1)
- Called from: FUN_006af5d0 (cleanup), FUN_006af140 (render tick when video finishes)
- Code: `*(int *)((int)this + 0x3c) = *(int *)((int)this + 0x3c) + -1;`
- When: A Bink video finishes playing or is explicitly stopped
- Also: Calls BinkClose, shifts remaining entries down in array

### 4. FUN_006afd40 -- Serialization (save/load)
- Serializes activeCount via vtable stream call, then iterates entries
- Called during game save (FUN_00443ac0 save path)

## Read Sites (Who Checks activeCount)

### 1. FUN_0043b4f0 (MainTick) at 0x0043b59b
```c
if (DAT_00995a3c < 1) {
    // D3D surface lock, Present/Flip path (normal rendering)
    // Gets renderer, locks surface, calls IDirectDrawSurface7::BltFast
}
```
- When activeCount >= 1: SKIPS the normal D3D Present/Flip render path
- When activeCount < 1 (0): Runs normal rendering

### 2. FUN_0043b4f0 (MainTick) at 0x0043b6f6
```c
if ((DAT_0097e9c4 == 0) || (0 < DAT_00995a3c)) {
    // Normal scene update: calls FUN_004433e0 (render tick)
} else {
    // Alternative path: FUN_007ef300 (clear stats), FUN_00418660 (scene update), FUN_007ef320 (get stats)
}
```
- When activeCount > 0: Forces the normal scene update path regardless of DAT_0097e9c4
- DAT_0097e9c4 appears to be a scene/camera object pointer

### 3. FUN_004433e0 (render tick) at 0x00443409
```c
if (0 < DAT_00995a3c) {
    FUN_006af140(&DAT_00995a00);  // Bink video render tick
}
```
- When activeCount > 0: Runs the Bink video renderer (BinkDoFrame, BinkCopyToBuffer, etc.)
- FUN_006af140 is a FULL Bink render pipeline: surface lock, frame decode, blit, Present

## Lifecycle

1. **Boot**: FUN_006aeca0 -> FUN_006aecd0 initializes to 0
2. **Video start**: FUN_006b0820 -> FUN_006aeeb0 increments to 1 (or more)
3. **During video**: MainTick skips normal D3D flip, instead runs Bink render in FUN_006af140
4. **Video end**: FUN_006af140 detects finished video -> FUN_006aee10 decrements
5. **All videos done**: Count returns to 0, normal D3D rendering resumes

## Critical Analysis: Effect of Setting to 1

Setting `*(int*)0x00995a3c = 1` would:

1. **SKIP** the D3D Present/Flip path in MainTick (the `if (DAT_00995a3c < 1)` block)
   - This avoids: IDirectDrawSurface7 method calls, surface locking, BltFast
   - This is the path that crashes in headless mode (no real surfaces)

2. **FORCE** the normal scene update path in MainTick
   - Calls FUN_004433e0 -> FUN_007e7f70 (scene begin), FUN_007e7fa0 (scene render), FUN_007e81b0 (scene end)
   - BUT: FUN_004433e0 also checks DAT_00995a48 (loading bink handle) -- if 0, it skips everything

3. **ACTIVATE** FUN_006af140 (Bink video render) in the render tick
   - This function also does D3D surface operations (BinkCopyToBuffer, surface Lock/Present)
   - Would try to render a Bink video that doesn't exist -> likely crash or no-op
   - Checks `param_1[0xf]` (activeCount at +0x3C) and `param_1+0x5e` (enabled flag)
   - If entries[0].binkHandle is 0 (no actual video loaded), the entry loop may skip safely

### DANGER: Setting to 1 without a real Bink video
- FUN_006af140 iterates entries[0..count-1] and calls BinkWait/BinkDoFrame on binkHandle
- If entries[0].binkHandle == 0 (which it would be since no video was loaded): `if (iVar1 != 0)` guard skips BinkWait/BinkDoFrame -- SAFE
- BUT: the function still does D3D surface Lock/Present operations OUTSIDE the entry loop
- It calls BinkDDSurfaceType, then enters a D3D Flip loop
- These surface operations would hit the proxy surfaces

### VERDICT: NOT a simple "skip rendering" flag
Setting to 1 does NOT cleanly skip rendering. It REPLACES normal rendering with Bink video rendering, which ALSO requires D3D surfaces. The flag means "render Bink video overlay instead of normal scene" not "skip rendering entirely."
