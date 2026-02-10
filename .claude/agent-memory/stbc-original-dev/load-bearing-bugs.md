# Load-Bearing Bugs and Behaviors

## PatchNetworkUpdateNullLists (0x005b1d57)
**Status:** Correct band-aid, but addresses symptom not cause.
**What it does:** Clears flag bits 0x20 and 0x80 when subsystem/weapon lists are NULL, preventing the client from expecting data that doesn't exist in the packet.
**Why it's not enough:** The vtable calls at 54099-54112 (position, rotation, scale) still fire on every tick and go through scene-graph-dependent code. The real fix is to have valid scene graphs so the lists are populated.
**Load-bearing?** Yes, until the renderer pipeline fix is applied. After that, subsystem lists should be populated and this patch becomes a safety net.

## VEH Targeted EIP Skips for Subsystem Loops
- 0x005b1edb -> skip to 0x005b1f1f (subsystem list at EDI+0x30)
- 0x005b1f82 -> skip to 0x005b2105 (weapon list at EDI+0x38)
**Status:** Required only because scene graph is incomplete. Should become unnecessary after renderer pipeline fix.
**Risk:** These skips silently swallow what would be fatal errors. They should be converted to asserts (log + continue) rather than silent skips once the root cause is fixed.

## VEH at 0x00419963 (AsteroidField ctor) - 100/sec
**Status:** Needs investigation. Likely related to procedural asteroid generation trying to compute bounds from non-existent geometry. Should resolve with full NIF loading.

## VEH at 0x004360CB (GetBoundingBox / vtable+0xe4 = GetWorldBound)
**Status:** Direct consequence of NULL NiBound. FUN_004360c0 (02_utopia_app.c:3063) calls vtable+0xe4 which returns NiBound data. With incomplete scene graphs, the bound pointer is NULL and the subsequent float reads crash.
**Load-bearing?** The VEH skip prevents crashes but means all objects have zero-size bounding volumes, which breaks collision detection, target selection, and spatial queries.

## PatchTGLFindEntry (0x006D1E10)
**Status:** Safety net for missing TGL files. When this==NULL (TGL database failed to load), returns NULL instead of garbage pointer this+0x1C.
**Load-bearing?** Will still be needed even with full renderer, because Multiplayer.tgl loading happens in Python (MissionShared.py:160) and may fail if the TGL data directory is incomplete. Keep this patch.

## IsClient/IsHost Flag Fix
**The critical correction:** 0x0097FA88 is IsClient (NOT IsHost). 0x0097FA89 is the real IsHost.
**Stock dedicated host:** IsClient=0, IsHost=1, IsMp=1
**This was the most impactful bug** - having IsClient=1 caused the engine to take client code paths on the host, including creating the GameSpy client timer and changing the subsystem update thresholds.
