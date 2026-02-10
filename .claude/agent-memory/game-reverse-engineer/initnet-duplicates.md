# Bug Analysis: InitNetwork Duplicate Sends

## Problem
When a new player joins, InitNetwork is sent to ALL connected players, not just
the new one. Previously-connected players receive duplicate MISSION_INIT_MESSAGE
packets, potentially causing UI glitches or kicks.

## Root Cause: Two Independent InitNetwork Call Sites

### Call Site 1: Native C++ Engine (CORRECT)
The engine has a built-in mechanism for calling InitNetwork on new peers:
1. Checksums pass -> FUN_006a4bb0 posts 0x8000e8
2. SystemChecksumPassedHandler verifies -> FUN_006a5860 posts 0x8000e6
3. ChecksumCompleteHandler (FUN_006a1b10) sends opcodes 0x00 + 0x01
4. NewPlayerInGameHandler (FUN_006a1e70) calls Python InitNetwork(peerID) at line 979-980
   - Uses FUN_006f8ab0 (SWIG bridge) with s_InitNetwork_0095a354 string
   - Passes the SPECIFIC new peer's ID only
   - Also replicates game objects and registers peer in Forward table

### Call Site 2: C-side Harness (REDUNDANT + BUGGY)
`ddraw_main.c` lines 1581-1687 independently schedules InitNetwork:
1. Every game loop tick, checks if playerCount > lastPlayerCount (line 1582)
2. Iterates ALL peers in the player array (lines 1584-1608)
3. Checks `g_pendingInitNet[j].active` for duplicates (lines 1592-1597)
4. Schedules via g_pendingInitNet with INITNET_DELAY_TICKS delay
5. Fires via RunPyCode calling `_m1.InitNetwork(peerID)` (lines 1662-1684)

### The Double Bug
1. **Redundancy**: Native C++ already calls InitNetwork for the specific new peer.
   The C-side scheduling duplicates this, sending MISSION_INIT_MESSAGE twice.

2. **Re-scheduling**: The `already` check at line 1592-1597 only checks entries where
   `g_pendingInitNet[j].active == 1`. Once an entry fires, active is set to 0
   (line 1661). When the NEXT player joins and playerCount increases again, the
   loop iterates ALL peers, finds no active entry for previously-fired peers,
   and re-schedules them. This sends InitNetwork to EVERY player, not just the new one.

## Evidence
- FUN_006a1e70 line 979-980: `FUN_006f8ab0(module_name, "InitNetwork", format, peerID)`
- ddraw_main.c line 1672: `_m1.InitNetwork(%u)\n`
- Both call the same Python function with the same peer ID

## Recommendation
Remove the C-side InitNetwork scheduling entirely (lines 1581-1687 of ddraw_main.c).
The native C++ NewPlayerInGameHandler already handles this correctly, calling
InitNetwork for the specific new peer at exactly the right time (after checksum
verification, after opcodes 0x00+0x01 are sent, before object replication).

The C-side scheduling was a workaround added before we understood the native flow.
It is now known to be both redundant and harmful.
