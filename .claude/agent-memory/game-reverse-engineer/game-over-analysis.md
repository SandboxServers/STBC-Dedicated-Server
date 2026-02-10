# Game Over Screen After Ship Selection - Analysis

## Symptom
Client selects ship, server sends 73-byte response, client shows "game over" screen.

## Server-Side VEH Fixes During Ship Selection
- 0x00419963: Unknown function (not in Ghidra function DB)
- 0x004360CB: FUN_004360c0 - bounding box calc (reads ship geometry, NULL in headless)
- 0x005b1edb: FUN_005b17f0 - network object state update, subsystem loop skip
  - First loop (subsys): 0x005b1edb -> 0x005b1f1f
  - Second loop (weapons): 0x005b1f82 -> 0x005b2105

## Root Cause Analysis

### Hypothesis 1: Truncated network state packet (MOST LIKELY)
FUN_005b17f0 writes ship state to a buffer stream. The data includes:
- Header: opcode 0x1c, object ID, timestamp, flags byte (bVar6)
- Position/orientation data (if bVar6 bits 1-4)
- Shield throttle (if bVar6 & 0x40)
- **Subsystem data (if bVar6 & 0x20)** - SKIPPED by VEH
- **Weapon data (if bVar6 & 0x80)** - SKIPPED by VEH

The flags byte (bVar6) is written BEFORE the loop data. When VEH skips
the loops, the stream claims data follows (bits set in flags) but the
actual bytes are missing. Client reads garbage or underflows the stream.

73 bytes = header + position/orient + flags - but missing subsystem/weapon data
that the flags byte promises should be there.

### Hypothesis 2: g_bGameStarted=1 before player connects (LESS LIKELY)
Server sets MissionMenusShared.g_bGameStarted=1 during init. In the
normal flow, this is set by StartMission (Mission1Menus.py:871) AFTER
the host selects their ship. The flag controls whether CreateSystemFromSpecies
is called (line 757). Setting it early should NOT cause game over.

### Hypothesis 3: Empty Set = no objects to replicate (NOT THE CAUSE)
NewPlayerInGameHandler (FUN_006a1e70) iterates objects at DAT_0097e9c8.
If no objects exist, the loop is a no-op. This causes no state update
for existing ships but shouldn't cause game over on the client.

## EndGame/DoEndGameDialog Flow
- EndGame() sends END_GAME_MESSAGE via broadcast (SendTGMessage(0,...))
- Client MissionShared.ProcessMessageHandler dispatches on first byte
- END_GAME_MESSAGE = App.MAX_MESSAGE_TYPES + 13
- Only triggered by: CheckFragLimit, UpdateTimeLeftHandler (timer), or direct call
- Neither CheckFragLimit nor timer should fire (limits set to -1)

## SetGameOver C++ Flag
- MultiplayerWindow has SetGameOver(int)/IsGameOver() methods
- These are SWIG-exposed but NEVER called from Python
- Must be set by C++ code internally
- ShowShipSelectScreen checks IsGameOver() on client side (line 1856)
- If IsGameOver() returns true, the else branch (game over dialog) runs

## Key Question
Is the 73-byte response being misinterpreted by the client as containing
an END_GAME_MESSAGE? Or is the C++ MultiplayerWindow.SetGameOver flag being
set by some internal C++ path after ET_START fires?
