> [docs](../README.md) / [protocol](README.md) / stateupdate.md

# State Update (0x1C) - The Big One

**Serializer**: `FUN_005b17f0` (called per-ship per-tick on the owning peer)
**Receiver**: `FUN_005b21c0` (processes incoming state updates)

This is the most complex and most frequently sent message. It uses dirty flags to only send fields that changed since the last update. Sent at ~10Hz per ship.

## Wire Format

```
Offset  Size  Type     Field                Description
------  ----  ----     -----                -----------
0       1     u8       opcode = 0x1C
1       4     i32      object_id            Ship's network object ID
5       4     f32      game_time            Current game clock timestamp
9       1     u8       dirty_flags          Bitmask of which fields follow
```

## Dirty Flags Byte

```
Bit 0 (0x01): POSITION_ABSOLUTE   - Full position + optional subsystem hash
Bit 1 (0x02): POSITION_DELTA      - Compressed position delta
Bit 2 (0x04): ORIENTATION_FWD     - Forward vector (CompressedVector3)
Bit 3 (0x08): ORIENTATION_UP      - Up vector (CompressedVector3)
Bit 4 (0x10): SPEED               - Current speed (CompressedFloat16)
Bit 5 (0x20): SUBSYSTEM_STATES    - Subsystem health/status round-robin
Bit 6 (0x40): CLOAK_STATE         - Cloaking device on/off
Bit 7 (0x80): WEAPON_STATES       - Weapon health round-robin (client->server in MP)
```

## Flag 0x01 - Absolute Position

```
+0      4     f32      pos_x              World position X
+4      4     f32      pos_y              World position Y
+8      4     f32      pos_z              World position Z
+12     bit   bool     has_subsystem_hash
[if has_subsystem_hash AND is_multiplayer:]
  +0    2     u16      subsystem_hash     XOR-folded 32-bit hash (see Anti-Cheat)
[else:]
  (nothing additional)
```

**When is this sent?**
- Sent when `uStack_494._3_1_` is non-zero (position delta overflow/wraparound)
- When sent, clears the delta-compression reference point:
  - `saved_pos = current_pos`
  - `delta_dir_bytes = 0,0,0`
  - `delta_magnitude = 0`

The subsystem hash is dead code in multiplayer — see [subsystem-integrity-hash.md](subsystem-integrity-hash.md) for details.

## Flag 0x02 - Position Delta (Compressed)

```
+0      5     cv4      position_delta     CompressedVector4(dx, dy, dz, param4=1)
                                           Uses uint16 magnitude
                                           dx = current_x - saved_x
                                           dy = current_y - saved_y
                                           dz = current_z - saved_z
```

Written via `FUN_006d2f10(stream, dx, dy, dz, 1)`.

Only sent when delta direction bytes have changed from cached values OR the periodic force-update timer fires.

## Flag 0x04 - Forward Orientation

```
+0      3     cv3      forward_vector     CompressedVector3 (3 signed bytes / 127.0, direction only)
```

Written via `FUN_006d2e50(stream, fwd_x, fwd_y, fwd_z)`.

Read from `ship->vtable[0xAC](&output)` = `GetForwardVector`.

## Flag 0x08 - Up Orientation

```
+0      3     cv3      up_vector          CompressedVector3 (3 signed bytes / 127.0, direction only)
```

Written via `FUN_006d2e50(stream, up_x, up_y, up_z)`.

Read from `ship->vtable[0xB0](&output)` = `GetUpVector`.

## Flag 0x10 - Speed

```
+0      2     u16      speed_compressed   CompressedFloat16
```

Speed is computed as:
```c
float* vel = FUN_005a05a0(ship);  // GetVelocity
float speed = sqrt(vel[0]^2 + vel[1]^2 + vel[2]^2);
if (FUN_005ac4f0(ship)) speed = -speed;  // IsReversing
```

Then encoded: `CompressedFloat16(speed)`.

## Flag 0x20 - Subsystem States (Round-Robin)

Server-to-client only. Subsystems are serialized in a round-robin fashion from the ship's top-level subsystem linked list (`ship+0x284`). Each update sends a few subsystems starting from where the previous update left off.

```
+0      1     u8       start_index         Position in subsystem list where this batch begins
+1      var   data     subsystem_data      Per-subsystem WriteState output (variable length)
```

**No count field**: the receiver reads subsystem data until the stream is exhausted (`streamPos >= dataLength`).

### Subsystem List Order

There is no fixed index table. The `start_index` is a position in the ship's serialization linked list at `ship+0x284`, whose contents and order are determined by the hardpoint script's `LoadPropertySet()` call order. Only **top-level system containers** remain in the list after `LinkAllSubsystemsToParents` (`FUN_005b3e20`) removes children. Individual weapons (phaser banks, torpedo tubes) and engines are serialized **recursively** within their parent's WriteState.

### Per-Subsystem WriteState Formats (vtable+0x70)

Each subsystem writes variable-length data via `vtable+0x70` (WriteState). Three implementations exist:

**Format 1: Base ShipSubsystem** (`0x0056d320`) — Hull, ShieldGenerator, individual children:
```
[condition: u8]           // (int)(currentCondition / GetMaxCondition() * 255.0)
                          //   this+0x30 / property+0x20 * 255.0; 0xFF=full, 0x00=destroyed
[child_0 WriteState]      // Recursive: each child writes its own block
[child_1 WriteState]
...
```

**Format 2: PoweredSubsystem** (`0x00562960`) — Sensors, Engines, Weapons, Cloak, Repair, Tractors:
```
[base WriteState]                 // Condition byte + recursive children
if (isOwnShip == 0):             // Remote ship — include power data
    [hasData: bit=1]             // WriteBit(1)
    [powerPctWanted: u8]         // (int)(powerPercentageWanted * 100.0); this+0x90, range 0-100
else:                            // Own ship — owner has local state
    [hasData: bit=0]             // WriteBit(0)
```

**Format 3: PowerSubsystem** (`0x005644b0`) — Reactor/Warp Core only:
```
[base WriteState]                 // Condition byte + recursive children
[mainBatteryPct: u8]             // (int)(mainBatteryPower / mainBatteryLimit * 255.0)
                                 //   this+0xAC / property+0x48; 0xFF=full, 0x00=empty
[backupBatteryPct: u8]           // (int)(backupBatteryPower / backupBatteryLimit * 255.0)
                                 //   this+0xB4 / property+0x4C
```
PowerSubsystem ALWAYS writes both battery bytes regardless of isOwnShip.

### Round-Robin Algorithm

From `Ship_WriteStateUpdate` (`0x005b17f0`), the per-object tracking structure at `iVar7+0x30` (cursor) and `iVar7+0x34` (index) persists across ticks:

```
if cursor == NULL:
    cursor = ship->subsystemListHead   // ship+0x284
    index = 0
initialCursor = cursor
WriteByte(stream, index)               // startIndex

while (streamPos - budgetStart) < 10:  // 10-byte budget including startIndex
    subsystem = cursor->data
    cursor = cursor->next
    subsystem->WriteState(stream, isOwnShip)
    index++
    if cursor == NULL:                 // End of list: wrap
        cursor = ship->subsystemListHead
        index = 0
    if cursor == initialCursor: break  // Full cycle complete
```

### Receiver (Flag 0x20 in `FUN_005b21c0`)

```
startIndex = ReadByte(stream)
node = ship->subsystemListHead
for i in range(startIndex): node = node->next  // Skip to start position
while streamPos < dataLength:
    subsystem = node->data
    node = node->next
    subsystem->ReadState(stream, timestamp)     // vtable+0x74 (inverse of WriteState)
    if node == NULL: node = ship->subsystemListHead  // Wrap
```

For detailed subsystem type tables, linked list structure, and Sovereign-class example, see [stateupdate-subsystem-wire-format.md](stateupdate-subsystem-wire-format.md).

## Flag 0x40 - Cloak State

```
+0      bit   bool     cloak_active       WriteBit/ReadBit: 0 = decloaked, 1 = cloaked
```

Read from `ship[0xB7]+0x9C` (cloaking device subsystem status byte).

Only sent when the value changes from the cached state.

## Flag 0x80 - Weapon States (Round-Robin)

Similar round-robin to subsystems, but iterates the weapon linked list at `ship+0x284`.

```
[repeated while stream_bytes_written < 6:]
  weapon = list_node->data
  if weapon->vtable[0x08](0x801C):  // IsType check
    +0    1     u8       weapon_index
    +0    1     u8       weapon_health_byte   ftol(health * scale_factor)
[end repeat]
```

Each weapon entry is: `[index:u8][health:u8]` = 2 bytes.

Budget: limited to ~6 bytes per update.

## Flag 0x20 vs 0x80 - Direction-Based Split (VERIFIED)

**Packet trace evidence from stock dedicated server** (verified against 30,000+ packets):

| Direction | Flag Used | Flag Never Used | Packet Count |
|-----------|----------|-----------------|--------------|
| **C->S** | 0x80 (WPN) always | 0x20 (SUB) never | 10,459 |
| **S->C** | 0x20 (SUB) always | 0x80 (WPN) never | 19,997 |

Client sends **weapon status** (0x80) to server. Server sends **subsystem health** (0x20) to client.
These flags are **mutually exclusive by direction** in multiplayer.

**Top C->S flag combinations**: 0x9E (DELTA+FWD+UP+SPD+WPN), 0x96, 0x92, 0x9D, 0x8E
**Top S->C flag combinations**: 0x20 (SUB only), 0x3E (DELTA+FWD+UP+SPD+SUB), 0x36, 0x3D, 0x32

## Flag Decision Logic (from FUN_005b17f0 decompiled code)

```c
bVar19 = DAT_0097fa8a == '\0';   // true if NOT multiplayer (SP mode)

if (bVar19) {
    flags |= 0x80;               // SP: always include weapons
    goto write_packet;
}
// MP path:
if (DAT_0097faa2 != 0) {         // friendly fire enabled?
    if (DAT_0097fa88 == 0) {      // is host?
        if (playerCount > 1) goto skip_subsystems;
    } else {                       // is client
        if (playerCount > 2) goto skip_subsystems;
    }
}
flags |= 0x20;                    // MP: include subsystems
```

The decompiled code shows `DAT_0097fa8a == 0` (SP mode) triggers 0x80, and MP mode triggers 0x20.
However, **packet traces show clients send 0x80 in multiplayer**. This suggests the CLIENT-side
value of `DAT_0097fa8a` (IsMultiplayer) differs from the HOST-side value during serialization,
causing the client to follow the SP code path and set 0x80 instead of 0x20.

In multiplayer with friendly fire enabled and enough players, subsystem states (0x20) may be
omitted to save bandwidth.

## Receiver Side (FUN_005b21c0) - Deserialization

The receiver mirrors the serializer:

```
1. ReadByte -> opcode (0x1C)
2. ReadInt32 -> object_id
3. ReadFloat -> game_time
4. ReadByte -> dirty_flags

if (flags & 0x01): // absolute position
    pos_x = ReadFloat, pos_y = ReadFloat, pos_z = ReadFloat
    has_hash = ReadBit
    if (has_hash && isMultiplayer):
        received_hash = ReadShort
        computed_hash = FUN_005b5eb0(this+0x27C)  // compute local hash
        if (received_hash XOR-folded != computed_hash XOR-folded):
            POST ET_BOOT_PLAYER -> kicks the player (anti-cheat!)

if (flags & 0x02): // position delta
    ReadCompressedVector4(stream, &dx, &dy, &dz, param4=1)
    new_pos = saved_pos + delta

if (flags & 0x04): // forward orientation
    ReadCompressedVector3(stream, &fwd_x, &fwd_y, &fwd_z)
    apply to scene node

if (flags & 0x08): // up orientation
    ReadCompressedVector3(stream, &up_x, &up_y, &up_z)
    apply to scene node

if (flags & 0x10): // speed
    raw = ReadShort
    speed = DecompressFloat16(raw)
    apply to physics

if (flags & 0x40): // cloak state
    cloak = ReadBit  // bit-packed boolean
    if cloak: FUN_0055f360(cloak_device)  // activate
    else: FUN_0055f380(cloak_device)      // deactivate

if (flags & 0x20): // subsystem states
    start_idx = ReadByte
    iterate subsystem linked list from start_idx
    while stream_pos < total_length:
        subsystem->vtable[0x74](stream, gameTime)  // subsystem reads its own state

if (flags & 0x80): // weapon states
    while stream_pos < total_length:
        weapon_idx = ReadByte
        health_byte = ReadByte
        navigate to weapon at weapon_idx in linked list
        if weapon->vtable[0x08](0x801C):  // IsWeapon type check
            health = health_byte * SCALE_FACTOR (DAT_008944c4)
            weapon->vtable[0x84](health, gameTime)
```

## Force-Update Timing

The serializer tracks timestamps per-field at `trackerObj+0x04` through `trackerObj+0x2E`. A field is force-sent if:

```c
DAT_00888860 < (gameTime - lastSentTime)  // global threshold
```

When ALL dirty fields are sent simultaneously, the master timestamp at `trackerObj+0x04` is updated.
