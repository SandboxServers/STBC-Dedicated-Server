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

### Call Site 2: GameLoopTimerProc Manual Call (REDUNDANT + HARMFUL)
GameLoopTimerProc independently called FUN_006a1e70 after NEWPLAYER_DELAY_TICKS=90.
This duplicated the engine's own call triggered by the client's 0x2A opcode.

### The Double Bug
1. **Redundancy**: Native C++ already calls FUN_006a1e70 when it receives opcode 0x2A.
   The manual call duplicated this, sending duplicate 0x35/0x37/0x17 packets.

2. **Re-scheduling**: Each time playerCount increased, the manual call fired again
   for ALL peers, not just the new one.

## Evidence
- FUN_006a1e70 at 0x006a1e70: engine calls this when receiving opcode 0x2A from client
- GameLoopTimerProc also called FUN_006a1e70 directly after delay
- Result: duplicate packets, ACK storms, double ObjNotFound

## Resolution
The manual FUN_006a1e70 call was identified as the root cause of duplicate post-join
packets. The native C++ NewPlayerInGameHandler already handles this correctly, calling
FUN_006a1e70 for the specific new peer at exactly the right time (after checksum
verification, after opcodes 0x00+0x01 are sent, before object replication).
