> [docs](../README.md) / [protocol](README.md) / game-opcodes.md

# Game Opcodes (0x02-0x2A)

These are dispatched by the MultiplayerGame ReceiveMessageHandler (at `0x0069f2a0`). The first payload byte is the opcode, which indexes a 41-entry jump table at `0x0069F534` (opcode minus 2, covering opcodes 0x02-0x2A).

**NOTE**: Opcodes 0x00 and 0x01 are NOT in this jump table. They are handled by the MultiplayerWindow dispatcher (`FUN_00504c10`) which processes them on the client side.

**NOTE**: Opcodes 0x07-0x0F are EVENT FORWARD messages (weapon state changes, cloak, warp), NOT Python messages or combat actions. The actual combat opcodes are 0x19 (TorpedoFire) and 0x1A (BeamFire). Python messages use opcode 0x06/0x0D.

## 0x00 - Settings (Server -> Client, MultiplayerWindow dispatcher)

**Sender**: `FUN_006a1b10` (ChecksumCompleteHandler)
**Client handler**: `FUN_00504d30`

Sent after all 5 checksum rounds pass (rounds 0-3 + 0xFF). Carries game settings and player slot assignment.

```
Offset  Size  Type     Field                    Notes
------  ----  ----     -----                    -----
0       1     u8       opcode = 0x00
1       4     f32      game_time                Current game clock (from DAT_009a09d0+0x90)
2       bit   bool     settings_byte1           DAT_008e5f59 (collision damage toggle)
3       bit   bool     settings_byte2           DAT_0097faa2 (friendly fire toggle)
4       1     u8       player_slot              Assigned player index (0-15)
5       2     u16      map_name_length
7       var   string   map_name                 Mission TGL file path
+0      bit   bool     checksum_result_flag     1 = checksums passed with corrections
[if flag == 1:]
+1      var   data     checksum_correction_data Written by FUN_006f3f30
```

**Stream write sequence** (from FUN_006a1b10):
```c
WriteByte(stream, 0x00);           // opcode
WriteFloat(stream, gameTime);      // from clock+0x90
WriteBit(stream, DAT_008e5f59);    // settings 1
WriteBit(stream, DAT_0097faa2);    // settings 2
WriteByte(stream, playerSlot);     // assigned slot
WriteShort(stream, mapNameLen);    // strlen of map name
WriteBytes(stream, mapName, len);  // map name string
WriteBit(stream, checksumFlag);    // did any checksums need correction?
if (checksumFlag) {
    FUN_006f3f30(checksumData, stream);  // correction data
}
```

## 0x01 - Game Init Trigger (Server -> Client)

**Sender**: `FUN_006a1b10` (sent immediately after opcode 0x00)
**Client handler**: `FUN_00504f10`

```
Offset  Size  Type    Field
------  ----  ----    -----
0       1     u8      opcode = 0x01
```

Single byte, no additional payload. Triggers:
1. `AI.Setup.GameInit` Python call
2. Creates `Multiplayer.MultiplayerGame` Python object (with max 16 players)
3. Reads `g_iPlayerLimit` from `MissionMenusShared`
4. Shows "Connection Completed" UI

## 0x02 / 0x03 - Object Create/Update (Server -> Client)

**Sender**: `FUN_006a1e70` (NewPlayerInGameHandler) - creates and sends to joining player
**Receiver**: `FUN_0069f620` (processes object creation on client)

These carry serialized game objects (ships, torpedoes, asteroids, etc.).

```
Offset  Size  Type    Field
------  ----  ----    -----
0       1     u8      type_tag           2 = standard object, 3 = object with team
1       1     u8      owner_player_slot  Which player owns this object
[if type_tag == 3:]
2       1     u8      team_id            Team assignment
[end if]
+0      var   data    serialized_object  vtable+0x10C serialization output
```

The `type_tag` is determined by checking if the object has a "player controller" (`FUN_005ab670`) with `FUN_005ae140` returning true (team info available).

The `serialized_object` data is produced by calling `obj->vtable[0x10C](buffer, maxlen)` which serializes the full game object state including:
- Object type ID
- Position, rotation
- Health, shields
- Subsystem states
- Weapon loadouts
- AI state

## 0x04 / 0x05 - Dead Opcodes (jump table default)

These opcode slots in the game jump table point to the DEFAULT handler (clears processing flag and returns). They are NOT used for game messages.

**Boot/kick is handled at the transport layer** via `TGBootPlayerMessage` (sent by `FUN_00506170`, the BootPlayerHandler registered for `ET_BOOT_PLAYER`), not as a game opcode.

## 0x06 / 0x0D - Python Event (Bidirectional)

**Handler**: `FUN_0069f880` (dispatches to Python event system)

```
Offset  Size  Type    Field
------  ----  ----    -----
0       1     u8      opcode (0x06 or 0x0D)
1       4     u32     event_code        (e.g. MISSION_INIT, SCORE_MESSAGE)
5+      var   data    Python event payload
```

Strips the opcode byte, creates a `TGBufferStream` from the remaining data, constructs a `TGEvent` via `FUN_006d6200`, and posts it to the event manager at `DAT_0097f838`. Both 0x06 and 0x0D route to the same handler.

This is the mechanism for `MISSION_INIT_MESSAGE`, `SCORE_MESSAGE`, `PLAYER_ACTION`, and all other Python multiplayer messages.

See [pythonevent-wire-format.md](pythonevent-wire-format.md) for the 4 event classes and their serialization.

## 0x07-0x0C, 0x0E-0x12, 0x1B - Event Forward Messages

**Handler**: `FUN_0069FDA0` (generic event forwarder) or `FUN_006a17c0` (sender thunk)

These opcodes forward engine-level events (weapon state, cloak, warp, repair, phaser power) to all connected peers. They all share the same generic format:

```
Offset  Size  Type    Field
------  ----  ----    -----
0       1     u8      opcode
1       4     i32     object_id         (the ship/object generating the event)
5+      var   data    event-specific payload (variable)
```

| Opcode | Event Name | Recv Event Code | Description | Stock 15-min count |
|--------|-----------|-----------------|-------------|--------------------|
| 0x07 | StartFiring | 0x008000D7 | Weapon subsystem begins firing | 2282 |
| 0x08 | StopFiring | 0x008000D9 | Weapon subsystem stops firing | common |
| 0x09 | StopFiringAtTarget | 0x008000DB | Beam/phaser stops tracking target | common |
| 0x0A | SubsystemStatusChanged | 0x0080006C | Subsystem health/state change | common |
| 0x0B | AddToRepairList | 0x008000DF | Crew repair assignment | occasional |
| 0x0C | ClientEvent | (from stream) | Generic event forward (preserve=0) | occasional |
| 0x0E | StartCloaking | 0x008000E3 | Cloaking device activated | occasional |
| 0x0F | StopCloaking | 0x008000E5 | Cloaking device deactivated | occasional |
| 0x10 | StartWarp | 0x008000ED | Warp drive activated | occasional |
| 0x11 | RepairListPriority | 0x00800076 | Repair priority ordering — see [dedicated analysis](../gameplay/repair-system.md) | occasional |
| 0x12 | SetPhaserLevel | 0x008000E0 | Phaser power/intensity setting — see [dedicated analysis](set-phaser-level-protocol.md) | 33 |
| 0x1B | TorpedoTypeChange | 0x008000FD | Torpedo type selection changed | occasional |

**Sender/receiver event code pairing**: The sender uses one event code locally, the receiver uses a paired code:
- D8->D7 (StartFiring), DA->D9, DC->DB, DD->6C, E2->E3, E4->E5, EC->ED, FE->FD
- **Exception**: 0x12 (SetPhaserLevel) uses the same code 0x008000E0 on both sides (no pairing, no override)

## 0x13 - Host Message

**Handler**: `FUN_006A01B0`

Host-specific message dispatch. Used for self-destruct and other host-authority actions. Processes damage via `obj+0x2C4` subsystem. See [self-destruct-pipeline.md](../gameplay/self-destruct-pipeline.md).

## 0x14 - Destroy Object

**Handler**: `FUN_006A01E0`

```
Offset  Size  Type    Field
------  ----  ----    -----
0       1     u8      opcode (skipped)
1       4     i32     object_id         (ReadInt32v)
```

Finds the object by ID, then either:
- If object has no owner (`obj[8] == NULL`): calls cleanup + destroy
- If object has owner: calls `owner->vtable[0x5C](object_id)` to notify

> **Stock trace note**: Not observed in stock MP traces (0 occurrences across 138,695 packets
> in a 33.5-minute combat session with 59 ship deaths). Ships die via Explosion (0x29) +
> ObjCreateTeam (0x03) respawn. DestroyObject may only be used for non-ship objects or
> player disconnects.

## 0x15 - CollisionEffect (Client -> Server)

**Sender**: Collision detection system via `FUN_006a17c0` (event forwarder, event code `0x00800050`)
**Handler**: `FUN_006a2470` (Handler_CollisionEffect_0x15)
**Write method**: `0x005871a0` (CollisionEvent::Write, vtable+0x34)
**Read method**: `0x00587300` (CollisionEvent::Read, vtable+0x38)

Collision damage relay. Client detects a collision locally and sends this to the host for authoritative damage processing. 84 times in a 15-minute 3-player stock session (4th most common combat opcode).

See [collision-effect-protocol.md](collision-effect-protocol.md) for the complete wire format, contact point compression, handler validation chain, and decoded packet examples.

```
Offset  Size  Type    Field                    Notes
------  ----  ----    -----                    -----
0       1     u8      opcode = 0x15
1       4     i32     event_type_class_id      Always 0x00008124 (collision event factory ID)
5       4     i32     event_code               Always 0x00800050 (ET_COLLISION_EFFECT)
9       4     i32v    source_object_id         Other colliding object (0 = environment/NULL)
13      4     i32v    target_object_id         Ship reporting the collision (BC object ID)
17      1     u8      contact_count            Number of contact points (typically 1-2)
[repeated contact_count times:]
  +0    1     s8      dir_x                    Compressed direction X (signed, normalized * scale)
  +1    1     s8      dir_y                    Compressed direction Y
  +2    1     s8      dir_z                    Compressed direction Z
  +3    1     u8      magnitude_byte           Compressed distance from ship center
[end repeat]
+0      4     f32     collision_force          IEEE 754 float: impact force magnitude
```

**Total size**: 22 + contact_count * 4 bytes (typically 26 for 1 contact, 30 for 2)

## 0x16 - UI Settings Update (Server -> Client)

**Handler**: `FUN_00504c70` (in MultiplayerWindow)

```
Offset  Size  Type    Field
------  ----  ----    -----
0       1     u8      opcode = 0x16
1       bit   bool    collision_damage_flag   Stored to DAT_008e5f59
```

Updates the collision button state in the main menu UI.

## 0x17 - Delete Player UI

**Handler**: `FUN_006A1360`

Removes a player's UI elements from the game display.

## 0x18 - Delete Player Animation

**Handler**: `FUN_006A1420`

Plays the player deletion animation sequence.

## 0x19 - Torpedo/Projectile Fire (Owner -> All)

**Sender**: `FUN_0057CB10` (TorpedoSystem::SendFireMessage)
**Handler**: `FUN_0069F930`

```
Offset  Size  Type    Field
------  ----  ----    -----
0       1     u8      opcode = 0x19
1       4     i32     object_id         (torpedo subsystem object ID)
+0      1     u8      flags1            (subsystem index / type info)
+0      1     u8      flags2            (bit 0=has_arc, bit 1=has_target)
+0      3     cv3     velocity          CompressedVector3 (torpedo direction, 3 bytes)

if has_target (flags2 bit 1):
  +0    4     i32     target_id         (ReadInt32v)
  +0    5     cv4     impact_point      CompressedVector4 (3 dir bytes + CF16 magnitude)

Then calls FUN_0057d110 to create the torpedo projectile locally.
```

**Observed field values** (from packet trace verification):
- `flags1=0x02` for all torpedo types
- `flags2=0x05` for photon torpedoes (has_arc, no target)
- `flags2=0x07` for quantum torpedoes with target lock (has_arc + has_target)
- Dual-spread torpedoes send 2 TorpedoFire messages simultaneously (paired object IDs)
- Torpedoes are also replicated as game objects via 0x02/0x03 and tracked via 0x1C StateUpdate

## 0x1A - Beam/Phaser Fire (Owner -> All)

**Sender**: `FUN_00575480` (PhaserSystem::SendFireMessage)
**Handler**: `FUN_0069FBB0`

```
Offset  Size  Type    Field
------  ----  ----    -----
0       1     u8      opcode = 0x1A
1       4     i32     object_id         (phaser subsystem object ID)
+0      1     u8      flags             (single byte)
+0      3     cv3     target_position   CompressedVector3 (3 bytes direction)
+0      1     u8      more_flags        (bit 0 = has_target_id)

if has_target_id (more_flags bit 0):
  +0    4     i32     target_object_id  (ReadInt32v)

Then calls FUN_005762b0 to start beam rendering.
```

**Observed field values**:
- Ships with 2 turrets send 2 BeamFire messages simultaneously (e.g., Klingon BoP)
- `flags=0x02` observed for all beam types

## 0x1D - Object Not Found

**Handler**: `FUN_006A0490`

```
Offset  Size  Type    Field
------  ----  ----    -----
0       1     u8      opcode (skipped)
1       4     i32     object_id
```

## 0x1E - Request Object State

**Handler**: `FUN_006A02A0`

```
Offset  Size  Type    Field
------  ----  ----    -----
0       1     u8      opcode (skipped)
1       4     i32     object_id         (ReadInt32)
```

Server finds the object, serializes it (like opcode 0x02/0x03), and sends the full object state back to the requesting client.

## 0x1F - Enter Set (Change Scene)

**Handler**: `FUN_006A05E0`

```
Offset  Size  Type    Field
------  ----  ----    -----
0       1     u8      opcode (skipped)
1       4     i32     object_id         (ReadInt32)
+0      var   data    set_data          (ReadInt32 + raw buffer via FUN_006d2370)
```

Moves an object into a new "Set" (scene region). If the object doesn't exist locally, sends back opcode 0x1D (not found).

## 0x29 - Explosion / Torpedo Hit

**Sender**: `FUN_00595c60` (iterates explosion list at `this+0x13C`)
**Handler**: `Handler_Explosion_0x29` at `0x006A0080`

```
Offset  Size  Type    Field
------  ----  ----    -----
0       1     u8      opcode = 0x29
1       4     i32/id  object_id         (ReadInt32v - target ship)
5       5     cv4     impact_position   CompressedVector4 (3 dir bytes + CF16 magnitude)
10      2     u16     radius_compressed CompressedFloat16
12      2     u16     damage_compressed CompressedFloat16
Total: 14 bytes
```

Field order verified from sender: radius is written first (from source+0x14), damage second (from source+0x1C). Receiver passes to `ExplosionDamage(pos, radius, damage)` constructor, which stores radius at +0x14, radius^2 at +0x18, and damage at +0x1C. Then calls `ProcessDamage(ship, explosionObj)`.

Both radius and damage are CF16 (lossy). See [cf16-precision-analysis.md](cf16-precision-analysis.md) for precision limits and mod compatibility implications.

## 0x2A - New Player In Game

**Handler**: `FUN_006A1E70`

Signals that a new player has fully joined the game session. Triggers Python InitNetwork handlers and object replication to the new player.
