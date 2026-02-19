# Game-Over Screen Analysis (2026-02-09)

## Issue: Client Shows Game-Over/Scoreboard After Ship Selection

### Timeline
- Tick 293: Client connects (players 0->1)
- Tick 383: NewPlayerInGame called, scoring dict fix rc=-1
- Tick 705: Client disconnects (players 1->0)

### What "Game-Over Screen" Really Is
The client shows the end-game dialog built by `MissionMenusShared.DoEndGameDialog()`.
This could be triggered by:
1. Server sends `END_GAME_MESSAGE` (MissionShared.EndGame sends to all clients)
2. Client's `MissionShared.g_bGameOver` gets set to 1 locally
3. MultiplayerWindow.IsGameOver() returns true (native C++ flag)
4. Client Python exception in BuildMission1Menus -> falls through to end-game path

### Root Cause: Empty State Update Packets
Server sends StateUpdate packets with flags=0x00 (empty) instead of flags=0x20
(subsystem health data). This happens because NIF ship models don't fully load
without GPU texture backing, so the subsystem list at ship+0x284 is NULL.
PatchNetworkUpdateNullLists correctly clears the flags to prevent sending garbage,
but the client expects subsystem data and disconnects after ~3 seconds without it.

### Alternative: Scoring Dict Fix rc=-1
The PyRun_SimpleString for scoring dict fix returns -1, meaning it threw an
exception. If the scoring dicts aren't properly initialized, the client's
ProcessMessageHandler may fail to parse SCORE_MESSAGE, or the server's
NewPlayerHandler event (which initializes kills/deaths dicts) may not have
fired before InitNetwork sends score data.

### FUN_004360c0 = GetBoundingBox (confirmed)
- `this` = NiAVObject* (or derived game object)
- vtable[0xe4/4] = slot 57 = GetWorldBound(), returns NiBound*
- NiBound layout: float center[3], float radius (16 bytes)
- GetBoundingBox computes AABB from bound sphere: min = center - radius, max = center + radius
- Returns NULL when no geometry is loaded (headless mode)

### FUN_005b17f0 = NetworkObjectStateUpdate
- Builds per-tick state update packet for each networked ship
- Uses vtable+0x94 for GetPosition, vtable+0xac for GetOrientation
- Uses vtable+0xe4 (GetWorldBound) at 0x004360c0 for bounding radius
- Flags byte: 0x01=position, 0x02=compressed-position, 0x04=orientation,
  0x08=rotation, 0x10=speed, 0x20=subsystems, 0x40=target, 0x80=weapons

### 0x00419963 Crash
- At vtable base + 0xe0 (slot just below GetWorldBound)
- Fires 3x on client connect then stops
- Likely related to initial object setup calling a vtable method on
  an object whose NiAVObject base is not fully initialized
- In same vtable as GetBoundingBox (0x00888c68 -> 0x00419960)

## Fix Priority
1. **HIGH: GetBoundingBox crash** - Root cause of malformed packets
2. **HIGH: State update packet correctness** - Even with dummy bounds,
   position/velocity data may be wrong
3. **MEDIUM: Scoring dict initialization** - Ensures clean handoff
4. **LOW: 0x00419963 crash** - Only fires 3x, self-resolving
