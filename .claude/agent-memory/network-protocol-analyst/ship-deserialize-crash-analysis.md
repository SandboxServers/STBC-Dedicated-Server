# Ship_Deserialize Crash Analysis (2026-02-21)

## Crash Summary

**REPRODUCIBLE**: Client crashes at `Ship_Deserialize+0x99` (0x005A1FE9) when receiving
a malformed ObjCreateTeam (opcode 0x03) from the server. The crash is a NULL pointer
dereference: `MOV EDX, [ESI]` where ESI=NULL. Occurred twice in the same session
(18:04:20 and 18:31:24), both with identical registers.

## Root Cause

`Ship_Deserialize` (0x005A1F50) reads `[factory_class_id:4][objectID:4]` from the
serialized object data. The crash ObjCreateTeam payload is missing the 4-byte
`factory_class_id` field. Ship_Deserialize reads the objectID (0x3FFFFFFF) as the
classID, which has no registered factory. `FUN_006f13e0(0x3FFFFFFF)` returns NULL.
Ship_Deserialize then dereferences NULL at `*piVar3 + 0x118`.

**Bug in Ship_Deserialize**: No NULL check on `FUN_006f13e0()` return value before
calling `vtable+0x118`. The stock game never hits this because ObjCreateTeam always
has a valid classID in normal gameplay.

## Malformed ObjCreateTeam Payload

The crash packet is sent by the server (direction=0x01, seq=26, reliable) at 18:04:20.172.
It arrives 5 seconds after the player's ship was destroyed by collision damage.

### Original ObjCreateTeam (working, at 18:03:24.000)
```
03 00 02              opcode=0x03 owner=0 team=2
08 80 00 00           factory_class_id = 0x00008008 (Ship)
FF FF FF 3F           objectID = 0x3FFFFFFF
05                    species = 5 (Sovereign)
00 00 18 42           pos_x = 38.0
00 00 44 C2           pos_y = -49.0
00 00 0C C2           pos_z = -35.0
[quat:16] [speed:4] [padding:3] [name:6] [set:7] [subsys_health:~50]
Total object data: 110 bytes
```

### Crash ObjCreateTeam (malformed, at 18:04:20.172)
```
03 01 00              opcode=0x03 owner=1 team=0  <-- DIFFERENT
FF FF FF 3F           MISSING classID -- objectID in classID position
05                    species = 5 (Sovereign)
00                    unknown byte (0x00)
[pos:12]              (-1959.0, -51.0, 333.0) <-- OFF-MAP
[quat:16]             (1,0,0,0) identity
[speed:4]             0.0
[unknown:24]          3x identity matrix rows (extra rotation data)
[shield_HPs:28]       12000, 11000, 5500, 11000, 11000, 5500, 5500
[count:2]             26 (u16 LE)
[current_HPs:32]      8x 1000.0
[maxHP_table:104]     12000, 10000, 8000, 7000, 3000, 2200x6, 8000x2, 10000, 1500x4
Total object data: 198 bytes
```

### Key Differences
| Field | Original | Crash |
|-------|----------|-------|
| factory_class_id | 0x00008008 | MISSING |
| owner | 0 | 1 |
| team | 2 | 0 |
| position | (38, -49, -35) | (-1959, -51, 333) OFF-MAP |
| orientation | actual quat | identity |
| speed | 0.0 | 0.0 |
| player name | "Cady2" | MISSING |
| set name | "Multi1" | MISSING |
| subsystem data | round-robin health | full maxHP table |
| total object data | 110 bytes | 198 bytes |

## Different Serialization Format

The crash ObjCreateTeam uses a COMPLETELY different serialization than the original:
1. No factory_class_id prefix (4 bytes missing)
2. Extra byte after species (offset 5)
3. Extra rotation data (24 bytes beyond quaternion)
4. No player name or set name strings
5. Full subsystem MaxHP table (not round-robin health)
6. Shield per-facing MaxHP values (7 floats)
7. 26-entry subsystem table with current and max HP values

This is NOT the normal `Ship::vtable+0x10c` (WriteStream) output. It appears to be
output from a different WriteStream override (possibly a base class or corrupted vtable)
on a ship object that was in a destroyed/invalid state.

## Timeline (with corrected directions)

The client packet trace has inverted direction labels (sendto="S->C", recvfrom="C->S").

```
18:04:15.146  S->C  Last SUB StateUpdate: obj=0x3FFFFFFF t=63.30 subsystems normal
18:04:15.165  C->S  CollisionEffect (0x15): collision damage event
18:04:15.221  C->S  StateUpdate: obj=0x3FFFFFFF t=63.30 pos=(24.9,-49.3,-71.1)
18:04:15.249  S->C  DEATH BURST (packet #1095, 338 bytes, 16 messages):
                     - 13x PythonEvent (eventCode=0x00000101, subsystem damage)
                     - 1x PythonEvent (eventCode=0x00008129, collision)
                     - 1x Explosion (0x29): obj=0x3FFFFFFF dmg=1.5 radius=5189.0
                     - 1x ScoreChange (0x36)
18:04:15.253  C->S  Client ACKs seq 11-25
18:04:15.321+ C->S  Client continues sending StateUpdates (ship NOT destroyed on client)
18:04:15.321  ----  Server STOPS sending SUB (0x20) updates
18:04:19.071  S->C  Two CollisionEffect (0x15) packets
18:04:20.122  C->S  Last client StateUpdate: t=68.20 flags=0x9E
18:04:20.172  S->C  *** CRASH PACKET: ObjCreateTeam with malformed data ***
18:04:20.366  ----  CRASH: Ship_Deserialize NULL dereference at 0x005A1FE9
```

## Open Questions

1. **What code path generated this ObjCreateTeam?** The server sent it. Possible sources:
   - NewPlayerInGame (FUN_006a1e70) iterates game objects and calls vtable+0x10c on each
   - Some other serialization path triggered by ship death/respawn
   - The ship's vtable may have been corrupted after destruction

2. **Why is the classID missing?** The serialization function is different from normal
   Ship::WriteStream. Possible explanations:
   - Destroyed ship has a different vtable (base class override)
   - The vtable+0x10c points to a parent class version that doesn't write classID
   - Memory corruption after explosion/death changed the vtable pointer

3. **Why the off-map position?** (-1959, -51, 333) is far outside normal game bounds.
   This may be where the ship object was moved after destruction (death cleanup).

## Suggested Fixes

### Fix 1: NULL check in Ship_Deserialize (client-side defense)
Add a code cave after `FUN_006f13e0` call at 0x005A1FDE to check if ESI (return value)
is NULL, and if so, skip the vtable calls and return NULL.

### Fix 2: Validate ObjCreateTeam on server before sending
In the NewPlayerInGame handler, check that the ship object is alive/valid before
calling vtable+0x10c and sending the ObjCreateTeam.

### Fix 3: Skip destroyed objects in NewPlayerInGame loop
Add a health/alive check before serializing each object in the game set iteration
within FUN_006a1e70.
