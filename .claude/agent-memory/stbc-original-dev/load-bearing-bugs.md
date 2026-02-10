# Load-Bearing Bugs and Behaviors

## PatchNetworkUpdateNullLists (0x005b1d57)
**Status:** Active and necessary.
**What it does:** Clears flag bits 0x20 and 0x80 when subsystem/weapon lists are NULL, preventing the client from expecting data that doesn't exist in the packet.
**Why it's not enough:** The vtable calls at 54099-54112 (position, rotation, scale) still fire on every tick and go through scene-graph-dependent code. The real fix is to have valid scene graphs so the lists are populated.
**Load-bearing?** Yes, because NIF ship models don't fully load without GPU texture backing. Without this patch, the server would send garbage subsystem data.

## PatchTGLFindEntry (0x006D1E10)
**Status:** Safety net for missing TGL files. When this==NULL (TGL database failed to load), returns NULL instead of garbage pointer this+0x1C.
**Load-bearing?** Will still be needed even with full renderer, because Multiplayer.tgl loading happens in Python (MissionShared.py:160) and may fail if the TGL data directory is incomplete. Keep this patch.

## IsClient/IsHost Flag Semantics
0x0097FA88 is IsClient (NOT IsHost). 0x0097FA89 is the real IsHost.
**Stock dedicated host:** IsClient=0, IsHost=1, IsMp=1
**Our server:** IsClient=0, IsHost=1, IsMp=1 (correct)
Having IsClient=1 on the host would cause the engine to take client code paths, including creating the GameSpy client timer and changing the subsystem update thresholds.
