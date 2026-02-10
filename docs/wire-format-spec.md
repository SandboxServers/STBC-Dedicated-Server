# Star Trek: Bridge Commander - Multiplayer Wire Format Specification

Produced by systematic decompilation of stbc.exe (base 0x400000, ~5.9MB) using Ghidra.
Validated against stock dedicated server packet traces (30,000+ packets).
See also: [message-trace-vs-packet-trace.md](message-trace-vs-packet-trace.md) for packet trace cross-reference.

## Table of Contents
1. [Transport Layer](#transport-layer)
2. [Stream Primitives](#stream-primitives)
3. [Compressed Data Types](#compressed-data-types)
4. [Checksum/NetFile Opcodes (0x20-0x28)](#checksumnetfile-opcodes-0x20-0x28)
5. [Game Opcodes (0x00-0x0F)](#game-opcodes-0x00-0x0f)
6. [State Update (0x1C) - The Big One](#state-update-0x1c---the-big-one)
7. [Object Replication](#object-replication)
8. [Python Message Dispatch](#python-message-dispatch)
9. [Subsystem Hash (Anti-Cheat)](#subsystem-hash-anti-cheat)

---

## Transport Layer

### Raw UDP Packet
After the AlbyRules! cipher is removed, the decrypted payload has this structure:

```
Offset  Size  Field
------  ----  -----
0       1     direction     (0x01=from server, 0x02=from client, 0xFF=init handshake)
1       1     msg_count     (number of transport messages in this packet)
2+      var   messages      (sequence of transport messages: keepalive, ACK, reliable, etc.)
```

Each transport message within the packet uses self-describing lengths:
- **ACK (0x01)**: fixed 4 bytes: `[0x01][seq:1][0x00][flags:1]`
- **Reliable (0x32)**: `[0x32][totalLen:1][flags:1][seq_hi:1][seq_lo:1][game_opcode][payload]`
  - totalLen includes the 0x32 byte itself
  - flags & 0x80 = has sequence number
- **All other types** (0x00, 0x03-0x06): `[type:1][totalLen:1][data...]` where totalLen includes type byte

The TGNetwork layer wraps messages in a TGMessage object:
- `msg+0x04` = pointer to payload data buffer
- `msg+0x08` = payload data length
- `msg+0x0C` = sender peer ID
- `msg+0x28` = pointer to raw buffer (used by `FUN_006b8530` to get data+len)
- `msg+0x3A` = reliable flag (0x01 = reliable delivery)
- `msg+0x3D` = priority flag

### Message Dispatchers
Two independent dispatchers process incoming messages:

1. **NetFile dispatcher** (`FUN_006a3cd0` at UtopiaModule+0x80): Handles opcodes 0x20-0x27
   - Registered for event type `0x60001` (ET_NETWORK_MESSAGE_EVENT)
   - Sets `DAT_0097fa8b = 1` during processing

2. **MultiplayerGame dispatcher** (registered as `ReceiveMessageHandler`): Handles game opcodes
   - Forwards to per-opcode handlers based on first byte of payload

3. **MultiplayerWindow dispatcher** (`FUN_00504c10`): Client-side UI handler
   - Only processes if `this+0xb0 != 0` (gate flag)
   - Handles opcodes 0x00, 0x01, 0x16

---

## Stream Primitives

All serialization uses a `TGBufferStream` object (`FUN_006cefe0` constructor). The stream has:
- `+0x1C` = buffer pointer
- `+0x20` = buffer capacity
- `+0x24` = current write/read position
- `+0x28` = bit-packing bookmark position
- `+0x2C` = bit-packing state (0 = no active bit group)

### Write Functions (Server -> Wire)

| Function | Type | Size | Description |
|----------|------|------|-------------|
| `FUN_006cf730` | WriteByte | 1 byte | Writes `uint8` at current position |
| `FUN_006cf770` | WriteBit | 0-1 bytes | Packs boolean bits into a shared byte (see Bit Packing) |
| `FUN_006cf7f0` | WriteShort | 2 bytes | Writes `uint16` (little-endian) |
| `FUN_006cf870` | WriteInt32 | 4 bytes | Writes `int32` / `uint32` |
| `FUN_006cf8b0` | WriteFloat | 4 bytes | Writes `float32` (IEEE 754) |
| `FUN_006cf2b0` | WriteBytes | N bytes | Writes raw byte array (memcpy) |
| `FUN_006cf9b0` | GetPosition | - | Returns current stream position (uint32) |

### Read Functions (Wire -> Client)

| Function | Type | Size | Description |
|----------|------|------|-------------|
| `FUN_006cf540` | ReadByte | 1 byte | Reads `uint8` |
| `FUN_006cf580` | ReadBit | 0-1 bytes | Reads packed boolean bit |
| `FUN_006cf600` | ReadShort | 2 bytes | Reads `uint16` (little-endian) |
| `FUN_006cf670` | ReadInt32 | 4 bytes | Reads `int32` / `uint32` |
| `FUN_006cf6b0` | ReadFloat | 4 bytes | Reads `float32` (IEEE 754) |
| `FUN_006cf6a0` | ReadInt32v | 4 bytes | Reads via vtable (variant read) |
| `FUN_006cf230` | ReadBytes | N bytes | Reads raw byte array |

### Bit Packing Format

`WriteBit` / `ReadBit` (`FUN_006cf770` / `FUN_006cf580`) use a compact bit-packing scheme:

A single byte encodes up to 5 boolean values:
```
Byte layout:  [count:3][bits:5]
              MSB          LSB

count (bits 7-5): Number of bits packed (1-5), stored as (count-1)
bits  (bits 4-0): The actual boolean values, one per bit position
```

The packing state machine:
- First `WriteBit` call allocates a new byte at the current position and sets bit 0
- Subsequent calls OR the value into the next bit position
- The count field (upper 3 bits) tracks how many bits are stored
- After 5 bits, the byte is "full" and the next WriteBit starts a new byte
- The `+0x2C` field in the stream tracks whether we're mid-pack (non-zero) or not

On read, `ReadBit` extracts each bit in order, advancing the count. When all packed bits in the current byte have been consumed, the next ReadBit starts reading a fresh byte.

---

## Compressed Data Types

### CompressedFloat16 (Logarithmic Scale Compression)

Used for: speed values, damage amounts, distances.

**Encoding** (`FUN_006d3a90`):
```
Input:  float value
Output: uint16

Format: [sign:1][scale:3][mantissa:12]
        Bit 15=sign, Bits 14-12=scale exponent, Bits 11-0=mantissa

Algorithm:
1. If value < 0: set sign bit, negate
2. Find scale (0-7) such that value < BASE * MULT^scale
   where BASE = DAT_00888b4c, MULT = DAT_0088c548
3. Compute mantissa = ftol(value / (range for this scale) * 4096)
4. If scale overflows (>=8): clamp to scale=7, mantissa=0x1000
5. Result = (sign_flag * 8 + scale) * 0x1000 + mantissa
```

**Decoding** (`FUN_006d3b30`):
```
Input:  uint16 encoded
Output: float

Algorithm:
1. mantissa = encoded & 0xFFF
2. raw_scale = (encoded >> 12)
3. sign = (raw_scale >> 3) & 1
4. scale = raw_scale & 0x7 (if sign set, mask to 3 bits)
5. Compute range boundaries: lo=0, hi=BASE
   For i in 0..scale: lo=hi, hi=hi*MULT
6. result = (hi - lo) * mantissa * (1/4096) + lo
7. If sign: result = -result
```

The constants `DAT_00888b4c` (BASE) and `DAT_0088c548` (MULT) define the logarithmic scale ranges. This gives ~12 bits of precision within each octave, covering a wide dynamic range with only 16 bits.

### CompressedVector3 (Position Delta)

Used for: position offsets, velocity components.

**Write** (`FUN_006d2ad0`):
```
Input:  float dx, dy, dz (delta from last known position)
Output: byte dirX, byte dirY, byte dirZ, uint16 magnitude

Algorithm:
1. magnitude = sqrt(dx*dx + dy*dy + dz*dz)
2. If magnitude <= epsilon: magnitude = 0.0
3. dirX = ftol(dx / magnitude * some_scale)  // normalized direction as byte
4. dirY = ftol(dy / magnitude * some_scale)
5. dirZ = ftol(dz / magnitude * some_scale)
6. magnitude_compressed = CompressedFloat16(magnitude)
```

Wire format: `[dirX:u8][dirY:u8][dirZ:u8][magnitude:u16]` = **5 bytes total**

**Read** (`FUN_006d2eb0` / `ReadCompressedVector3`):
```
1. Read 3 bytes via vtable+0x50 (ReadByte)
2. Call vtable+0xB8 to decompress: (outX, outY, outZ, byte1, byte2, byte3)
```

### CompressedVector4 (Position Delta with Extra Param)

Used for: position + rotation, position + scale.

**Write** (`FUN_006d2f10`):
```
If param4 == 0 (use float for 4th component):
  Compress 3 floats via vtable+0xA0, write 3 bytes via vtable+0x54
  Write float via vtable+0x74
If param4 != 0 (use uint16 for 4th component):
  Compress 3 floats via vtable+0xA4, write 3 bytes via vtable+0x54
  Write uint16 via vtable+0x5C
```

**Read** (`FUN_006d2fd0` / `ReadCompressedVector4`):
```
1. Read 3 bytes via vtable+0x50
2. If param4 != 0: read uint16 via vtable+0x58
   Call vtable+0xB4 to decompress with uint16 magnitude
3. If param4 == 0: read float via vtable+0x70
   Call vtable+0xB0 to decompress with float magnitude
```

Wire format (param4=1): `[dirX:u8][dirY:u8][dirZ:u8][magnitude:u16]` = **5 bytes**
Wire format (param4=0): `[dirX:u8][dirY:u8][dirZ:u8][magnitude:f32]` = **7 bytes**

---

## Checksum/NetFile Opcodes (0x20-0x28)

Dispatcher: `FUN_006a3cd0` (NetFile::ReceiveMessageHandler)

The first byte after TGNetwork headers is checked against 0x32 (magic), then the sub-opcode byte is read.

### 0x20 - Checksum Request (Server -> Client)

Handler: `FUN_006a5df0`

```
Offset  Size  Type    Field
------  ----  ----    -----
0       1     u8      opcode = 0x20
1       1     u8      request_index (0-3)
2       2     u16     directory_name_length
4       var   string  directory_name (e.g. "scripts/")
+0      2     u16     filter_name_length
+2      var   string  filter_name (e.g. "App.pyc")
+0      bit   bool    recursive_flag
```

Client computes file hashes and responds with 0x21.

### 0x21 - Checksum Response (Client -> Server)

Handler: `FUN_006a4260` -> `FUN_006a4560` (verify) or `FUN_006a5570` (mismatch)

Two sub-types based on `byte[1]`:
- If `byte[1] == 0xFF`: new-format response (first-time checksum, handled by main path)
- If `byte[1] != 0xFF`: continuation response (re-request, handled by `FUN_006a4560`)

**First-time format** (byte[1] == 0xFF):
```
Offset  Size  Type    Field
------  ----  ----    -----
0       1     u8      opcode = 0x21
1       1     u8      request_index (0xFF = first response)
2       4     u32     file_hash_crc (from FUN_007202e0 = CRC of filename)
6+      var   data    checksum_data (file hashes)
```

**Continuation format** (byte[1] != 0xFF):
```
Offset  Size  Type    Field
------  ----  ----    -----
0       1     u8      opcode = 0x21
1       1     u8      request_index
2       2     u16     directory_length
4       var   string  directory_name
+0      2     u16     password_length (0 if none)
+2      var   string  password (if length > 0)
+0      bit   bool    recursive_flag
```

### 0x22 / 0x23 - Checksum Fail (Server -> Client)

Handler: `FUN_006a4c10`

0x22 = file/version mismatch ("VersionDifferent"), 0x23 = system checksum fail ("SystemChecksumFail")

```
Offset  Size  Type    Field
------  ----  ----    -----
0       1     u8      sub_opcode (0x22 or 0x23)
1       2     u16     filename_length
3       var   string  failing_filename
```

Client shows error dialog with the failing filename.

### 0x25 - File Transfer Request/Data

Handler: `FUN_006a3ea0` (if `this+0x14 != 0`, i.e., already in transfer mode)

Initial entry (this+0x14 == 0): Sets up receive-file warning dialog.

**Transfer data format**:
```
Offset  Size  Type    Field
------  ----  ----    -----
0       1     u8      opcode = 0x25
1       2     u16     filename_length
3       var   string  filename
+0      var   data    file_data (remainder of packet)
```

After writing the file, client checks if it's a `.pyc` in `Scripts/` and reimports the module.

Client responds with 0x27 (ACK).

### 0x27 - File Transfer ACK

Handler: `FUN_006a4250`

```
Offset  Size  Type    Field
------  ----  ----    -----
0       1     u8      opcode = 0x27
```

Calls `FUN_006a5860` to continue file transfer sequence or signal completion.

---

## Game Opcodes (0x00-0x2A)

These are dispatched by the MultiplayerGame ReceiveMessageHandler (at `0x0069f2a0`). The first payload byte is the opcode, which indexes a 41-entry jump table at `0x0069F534` (opcode minus 2).

**NOTE**: Opcodes 0x07-0x0F are EVENT FORWARD messages (weapon state changes, cloak, warp), NOT Python messages or combat actions. The actual combat opcodes are 0x19 (TorpedoFire) and 0x1A (BeamFire). Python messages use opcode 0x06/0x0D.

### 0x00 - Settings (Server -> Client)

**Sender**: `FUN_006a1b10` (ChecksumCompleteHandler)
**Client handler**: `FUN_00504d30`

Sent after all 4 checksum rounds pass. Carries game settings and player slot assignment.

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

### 0x01 - Game Init Trigger (Server -> Client)

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

### 0x02 / 0x03 - Object Create/Update (Server -> Client)

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

### 0x04 - Boot Player / Kick (Server -> Client)

**Sender**: `FUN_00506170` (BootPlayerHandler, via ET_BOOT_PLAYER event)
**Context**: Used to disconnect/kick a player

```
Offset  Size  Type    Field
------  ----  ----    -----
0       1     u8      sub_cmd = 0x04
1       1     u8      reason            Boot reason code:
                                         2 = server full
                                         3 = game in progress
                                         4 = kicked by host
```

Actually this is wrapped in a `TGBootPlayerMessage` which has additional framing.

### 0x06 / 0x0D - Python Event (Bidirectional)

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

### 0x07-0x0C, 0x0E-0x10, 0x1B - Event Forward Messages

**Handler**: `FUN_0069FDA0` (generic event forwarder) or `FUN_006a17c0` (sender thunk)

These opcodes forward engine-level events (weapon state, cloak, warp) to all connected peers. They all share the same generic format:

```
Offset  Size  Type    Field
------  ----  ----    -----
0       1     u8      opcode
1       4     i32     object_id         (the ship/object generating the event)
5+      var   data    event-specific payload (variable)
```

| Opcode | Event Name | Recv Event Code | Description |
|--------|-----------|-----------------|-------------|
| 0x07 | StartFiring | 0x008000D7 | Weapon subsystem begins firing |
| 0x08 | StopFiring | 0x008000D9 | Weapon subsystem stops firing |
| 0x09 | StopFiringAtTarget | 0x008000DB | Beam/phaser stops tracking target |
| 0x0A | SubsystemStatusChanged | 0x0080006C | Subsystem health/state change |
| 0x0B | EventForward_DF | 0x008000DF | (unknown event forward) |
| 0x0C | EventForward | (from stream) | Generic event forward |
| 0x0E | StartCloaking | 0x008000E3 | Cloaking device activated |
| 0x0F | StopCloaking | 0x008000E5 | Cloaking device deactivated |
| 0x10 | StartWarp | 0x008000ED | Warp drive activated |
| 0x1B | TorpedoTypeChange | 0x008000FD | Torpedo type selection changed |

**Sender/receiver event code pairing**: The sender uses one event code locally, the receiver uses a paired code:
- D8→D7 (StartFiring), DA→D9, DC→DB, DD→6C, E2→E3, E4→E5, EC→ED, FE→FD

### 0x13 - Host Message

**Handler**: `FUN_006A01B0`

Host-specific message dispatch. Used for self-destruct and other host-authority actions.

### 0x14 - Destroy Object

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

### 0x17 - Delete Player UI

**Handler**: `FUN_006A1360`

Removes a player's UI elements from the game display.

### 0x18 - Delete Player Animation

**Handler**: `FUN_006A1420`

Plays the player deletion animation sequence.

### 0x19 - Torpedo/Projectile Fire (Owner -> All)

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

### 0x1A - Beam/Phaser Fire (Owner -> All)

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

### 0x1D - Object Not Found

**Handler**: `FUN_006A0490`

```
Offset  Size  Type    Field
------  ----  ----    -----
0       1     u8      opcode (skipped)
1       4     i32     object_id
```

### 0x1E - Request Object State

**Handler**: `FUN_006A02A0`

```
Offset  Size  Type    Field
------  ----  ----    -----
0       1     u8      opcode (skipped)
1       4     i32     object_id         (ReadInt32)
```

Server finds the object, serializes it (like opcode 0x02/0x03), and sends the full object state back to the requesting client.

### 0x1F - Enter Set (Change Scene)

**Handler**: `FUN_006A05E0`

```
Offset  Size  Type    Field
------  ----  ----    -----
0       1     u8      opcode (skipped)
1       4     i32     object_id         (ReadInt32)
+0      var   data    set_data          (ReadInt32 + raw buffer via FUN_006d2370)
```

Moves an object into a new "Set" (scene region). If the object doesn't exist locally, sends back opcode 0x1D (not found).

### 0x29 - Explosion / Torpedo Hit

**Handler**: `FUN_006A0080`

```
Offset  Size  Type    Field
------  ----  ----    -----
0       1     u8      opcode (skipped)
1       4     i32/id  object_id         (ReadInt32v)
+0      5     cv4     impact_position   CompressedVector4 (with uint16 magnitude)
+0      2     u16     damage_compressed CompressedFloat16
+0      2     u16     radius_compressed CompressedFloat16
```

Creates a shockwave/explosion at the given position with the specified damage and radius.

### 0x2A - New Player In Game

**Handler**: `FUN_006A1E70`

Signals that a new player has fully joined the game session. Triggers Python InitNetwork handlers and object replication to the new player.

### 0x16 - UI Settings Update (Server -> Client)

**Handler**: `FUN_00504c70` (in MultiplayerWindow)

```
Offset  Size  Type    Field
------  ----  ----    -----
0       1     u8      opcode = 0x16
1       bit   bool    collision_damage_flag   Stored to DAT_008e5f59
```

Updates the collision button state in the main menu UI.

---

## State Update (0x1C) - The Big One

**Serializer**: `FUN_005b17f0` (called per-ship per-tick on the owning peer)
**Receiver**: `FUN_005b21c0` (processes incoming state updates)

This is the most complex and most frequently sent message. It uses dirty flags to only send fields that changed since the last update. Sent at ~10Hz per ship.

### Wire Format

```
Offset  Size  Type     Field                Description
------  ----  ----     -----                -----------
0       1     u8       opcode = 0x1C
1       4     i32      object_id            Ship's network object ID
5       4     f32      game_time            Current game clock timestamp
9       1     u8       dirty_flags          Bitmask of which fields follow
```

### Dirty Flags Byte

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

### Flag 0x01 - Absolute Position

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

### Flag 0x02 - Position Delta (Compressed)

```
+0      5     cv4      position_delta     CompressedVector4(dx, dy, dz, param4=1)
                                           Uses uint16 magnitude
                                           dx = current_x - saved_x
                                           dy = current_y - saved_y
                                           dz = current_z - saved_z
```

Written via `FUN_006d2f10(stream, dx, dy, dz, 1)`.

Only sent when delta direction bytes have changed from cached values OR the periodic force-update timer fires.

### Flag 0x04 - Forward Orientation

```
+0      3     cv3      forward_vector     CompressedVector3 (3 signed bytes / 127.0, direction only)
```

Written via `FUN_006d2e50(stream, fwd_x, fwd_y, fwd_z)`.

Read from `ship->vtable[0xAC](&output)` = `GetForwardVector`.

### Flag 0x08 - Up Orientation

```
+0      3     cv3      up_vector          CompressedVector3 (3 signed bytes / 127.0, direction only)
```

Written via `FUN_006d2e50(stream, up_x, up_y, up_z)`.

Read from `ship->vtable[0xB0](&output)` = `GetUpVector`.

### Flag 0x10 - Speed

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

### Flag 0x20 - Subsystem States (Round-Robin)

Subsystems are serialized in a round-robin fashion: each update sends a few subsystems starting from where the previous update left off.

```
+0      1     u8       start_index         Index of first subsystem in this batch
[repeated while stream_bytes_written < 10:]
  +0    1     u8       subsystem_index     Index in the linked list
  +0    var   data     subsystem_data      Written by subsystem->vtable[0x70](stream, flags)
[end repeat]
```

The subsystem linked list is at `ship+0x284` (offset 0xA1 * 4 in the object). When the iterator reaches the end of the list, it wraps around to the beginning.

Each subsystem writes its own state via `vtable[0x70]`. The exact format depends on the subsystem type (hull, shields, sensors, weapons, engines, etc.) but typically includes:
- Current health percentage
- Damage state
- Active/disabled flag
- Type-specific data (shield facing values, weapon charge, etc.)

Budget: The serializer checks `stream_position - start_position < 10` to limit subsystem data to ~10 bytes per update.

### Flag 0x40 - Cloak State

```
+0      1     u8       cloak_active       0 = decloaked, nonzero = cloaked
```

Read from `ship[0xB7]+0x9C` (cloaking device subsystem status byte).

Only sent when the value changes from the cached state.

### Flag 0x80 - Weapon States (Round-Robin)

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

### Flag 0x20 vs 0x80 - Direction-Based Split (VERIFIED)

**Packet trace evidence from stock dedicated server** (verified against 30,000+ packets):

| Direction | Flag Used | Flag Never Used | Packet Count |
|-----------|----------|-----------------|--------------|
| **C->S** | 0x80 (WPN) always | 0x20 (SUB) never | 10,459 |
| **S->C** | 0x20 (SUB) always | 0x80 (WPN) never | 19,997 |

Client sends **weapon status** (0x80) to server. Server sends **subsystem health** (0x20) to client.
These flags are **mutually exclusive by direction** in multiplayer.

**Top C->S flag combinations**: 0x9E (DELTA+FWD+UP+SPD+WPN), 0x96, 0x92, 0x9D, 0x8E
**Top S->C flag combinations**: 0x20 (SUB only), 0x3E (DELTA+FWD+UP+SPD+SUB), 0x36, 0x3D, 0x32

### Flag Decision Logic (from FUN_005b17f0 decompiled code)

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

### Receiver Side (FUN_005b21c0) - Deserialization

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
    cloak = ReadBit
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

### Force-Update Timing

The serializer tracks timestamps per-field at `trackerObj+0x04` through `trackerObj+0x2E`. A field is force-sent if:

```c
DAT_00888860 < (gameTime - lastSentTime)  // global threshold
```

When ALL dirty fields are sent simultaneously, the master timestamp at `trackerObj+0x04` is updated.

---

## Object Replication

### FUN_0069f620 - Object Create/Update Processor

When a new player joins, the server iterates all game objects and sends them. The wire format is:

```
Byte 0: type_tag
  2 = standard object (no team)
  3 = team object (has team byte)

Byte 1: owner_player_slot
  Mapped from object owner to player slot via FUN_006a19a0

[If type_tag == 3:]
  Byte 2: team_id (from playerController[0xB9])

Remaining: object serialization data
  Produced by object->vtable[0x10C](buffer + offset, maxlen - offset)
```

The receiver (`FUN_0069f620`) on the client:
1. Temporarily swaps the local player slot to the sender's slot
2. Calls `FUN_005a1f50` to deserialize and create the game object
3. Restores the original player slot
4. Replicates to all other connected players (if multiplayer host)
5. Creates a "Network" controller for the object via `FUN_0047dab0`

---

## Python Message Dispatch

Python messages (opcodes 0x06, 0x0D) use the engine's event system:

### Message Format (inside the stream)
```
4 bytes: event_code (uint32)
  Common codes:
    MISSION_INIT_MESSAGE  (sent after opcode 0x01)
    SCORE_MESSAGE         (sent per-player after join)
    PLAYER_ACTION         (in-game actions)

Remaining: event-specific payload
  Deserialized by the Python handler registered for that event code
```

### Opcode 0x06 / 0x0D - Python Event

`FUN_0069f880`: Strips opcode byte, creates stream from remaining data, constructs TGEvent via `FUN_006d6200`, posts to event manager. Both opcodes 0x06 and 0x0D route to the same handler.

### Event Forward Messages (0x07-0x0C, 0x0E-0x10, 0x1B)

`FUN_0069fda0`: These are NOT Python messages. They forward engine-level events (weapon fire state, cloak, warp) to all peers in the "Forward" distribution list. The handler creates a TGEvent with a hardcoded event code (different per opcode), then posts it locally and to all other clients.

These are sent by `FUN_006a17c0` which registers handlers for local engine events and serializes them into network messages.

---

## Subsystem Hash (Anti-Cheat)

### Hash Computation - FUN_005b5eb0

The subsystem hash is a 32-bit accumulator built by XOR-folding float values from all ship subsystems. It serves as a tamper-detection mechanism.

**Algorithm** (`FUN_005b6c10`):
```c
void hash_fold(float value, uint32* accumulator) {
    bool negative = (value < 0.0f);
    int32 ival = ftol(value);
    if (negative) ival = -ival;

    // XOR each byte of ival into accumulator
    for (int i = 0; i < 4; i++) {
        ((byte*)accumulator)[i] ^= ((byte*)&ival)[i];
    }

    // Rotate left by 1 bit
    *accumulator = (*accumulator << 1) | (*accumulator >> 31);
}
```

**Components hashed** (from `FUN_005b5eb0`):
1. **Shield system** (`ship+0x27C+0x48`): overall health
2. **Hull system** (`ship+0x27C+0x44`): health + 6 shield facing pairs (min/max for each of 6 facings)
3. **Sensor system** (`ship+0x27C+0x34`): health + several properties
4. **Engine system** (`ship+0x27C+0x4C`): health + one property
5. **Weapon system** (`ship+0x27C+0x50`): health + 4 properties
6. **Cloak system** (`ship+0x27C+0x54`): health only
7. **Repair system** (`ship+0x27C+0x5C`): health + one property
8. **Crew system** (`ship+0x27C+0x60`): health only
9. **Three unknown systems** (`+0x38, +0x3C, +0x40`): via FUN_005b6330
10. **Power system** (`ship+0x27C+0x58`): via FUN_005b6330

### Wire Encoding
The 32-bit hash is XOR-folded to 16 bits before transmission:
```c
uint16 wire_hash = (uint16)(hash32 >> 16) ^ (uint16)(hash32 & 0xFFFF);
```

### Anti-Cheat Trigger
On the receiver side (FUN_005b21c0), if:
1. `has_subsystem_hash` bit is set
2. AND `isMultiplayer` is true
3. AND `received_hash != locally_computed_hash`

Then: posts `ET_BOOT_PLAYER` event (code `0x8000F6`) which triggers `BootPlayerHandler` -> sends kick message -> client disconnects.

**Known issue**: If the server has no ship objects (dedicated server), the local hash is 0, which will always mismatch against a client's valid hash, causing false-positive kicks.

---

## Fragmented Reliable Messages

Large messages that exceed the transport MTU are split into fragments using the reliable
delivery wrapper (type 0x32).

### Fragment Flags (in 0x32 wrapper)
```
Flags byte in the 0x32 transport message:
  bit 7 (0x80) = Reliable delivery
  bit 5 (0x20) = Fragmented message
  bit 0 (0x01) = More fragments follow (0 = last fragment)
```

### Fragment Payload Layout
```
First fragment:
  [fragment_index:u8][total_fragments:u8][inner_opcode:u8][payload...]

Subsequent fragments:
  [fragment_index:u8][continuation_data...]
```

### Example: Checksum Response (3 fragments, 412 bytes total)
```
Packet #32: flags=0xA1 frag_idx=0 total=3 inner=0x21(ChecksumResp)  size=412
Packet #36: flags=0xA1 frag_idx=1 continuation data                  size=412
Packet #37: flags=0xA0 frag_idx=2 LAST fragment                      size=27
```

### Packet Trace Decoder Bug
The packet_trace.log decoder does NOT handle fragmentation. It reads `fragment_index`
as the game opcode, producing garbage entries:
- Fragment 0 (byte=0x00) -> misdecoded as "Settings" with garbage gameTime
- Fragment 1 (byte=0x01) -> misdecoded as "GameInit"
- Fragment 2 (byte=0x02) -> misdecoded as "ObjCreate"

---

## Newly Discovered Opcodes (from stock-dedi packet traces)

These opcodes were identified from stock dedicated server packet captures but are not
yet fully decoded.

| Opcode | Name | Direction | Occurrences | Notes |
|--------|------|-----------|-------------|-------|
| 0x11 | Unknown_11 | Relayed (C->S, S->C) | 2 each | 21 bytes payload, contains object ID patterns |
| 0x12 | Unknown_12 | Relayed (C->S, S->C) | 5 each | 18 bytes payload, contains object ID patterns |
| 0x13 | HostMsg | C->S only | 2 | Not relayed to other clients |
| 0x28 | Unknown_28 | S->C only | 3 | 6 bytes total (1 byte payload), sent before Settings |
| 0x2C | ChatMessage | Relayed | 5 C->S, ~15 S->C | `[0x2C][sender_slot:1][00 00 00][msgLen:2 LE][ASCII text]` |
| 0x35 | GameState | S->C only | 3 | Sent after ObjCreateTeam |
| 0x37 | PlayerRoster | S->C only | 1 | Sent once during join sequence |

---

## Summary: Opcode Table

### Game Opcodes (MultiplayerGame Dispatcher at 0x0069F2A0, jump table at 0x0069F534)

| Opcode | Name | Direction | Handler | Payload Summary |
|--------|------|-----------|---------|-----------------|
| 0x00 | Settings | S->C | FUN_00504d30 | gameTime, settings, playerSlot, mapName, checksumFlag |
| 0x01 | GameInit | S->C | FUN_00504f10 | (empty - just the opcode byte) |
| 0x02 | ObjectCreate | S->C | FUN_0069f620 | type=2, ownerSlot, serializedObject |
| 0x03 | ObjectCreateTeam | S->C | FUN_0069f620 | type=3, ownerSlot, teamId, serializedObject |
| 0x04 | BootPlayer | S->C | (inline) | reason code |
| 0x06 | PythonEvent | any | FUN_0069f880 | eventCode, eventPayload |
| 0x07 | StartFiring | any | FUN_0069fda0 | objectId, event data (→ event 0x008000D7) |
| 0x08 | StopFiring | any | FUN_0069fda0 | objectId, event data (→ event 0x008000D9) |
| 0x09 | StopFiringAtTarget | any | FUN_0069fda0 | objectId, event data (→ event 0x008000DB) |
| 0x0A | SubsysStatus | any | FUN_0069fda0 | objectId, event data (→ event 0x0080006C) |
| 0x0B | EventFwd_DF | any | FUN_0069fda0 | objectId, event data (→ event 0x008000DF) |
| 0x0C | EventFwd | any | FUN_0069fda0 | objectId, event data (from stream) |
| 0x0D | PythonEvent2 | any | FUN_0069f880 | eventCode, eventPayload (same as 0x06) |
| 0x0E | StartCloaking | any | FUN_0069fda0 | objectId, event data (→ event 0x008000E3) |
| 0x0F | StopCloaking | any | FUN_0069fda0 | objectId, event data (→ event 0x008000E5) |
| 0x10 | StartWarp | any | FUN_0069fda0 | objectId, event data (→ event 0x008000ED) |
| 0x13 | HostMsg | C->S | FUN_006a01b0 | host-specific dispatch (self-destruct etc.) |
| 0x14 | DestroyObject | S->C | FUN_006a01e0 | objectId |
| 0x16 | UISettings | S->C | FUN_00504c70 | collisionDamageFlag(bit) |
| 0x17 | DeletePlayerUI | S->C | FUN_006a1360 | player UI cleanup |
| 0x18 | DeletePlayerAnim | S->C | FUN_006a1420 | player deletion animation |
| 0x19 | TorpedoFire | owner->all | FUN_0069f930 | objId, flags, velocity(cv3), [targetId, impact(cv4)] |
| 0x1A | BeamFire | owner->all | FUN_0069fbb0 | objId, flags, targetDir(cv3), moreFlags, [targetId] |
| 0x1B | TorpTypeChange | any | FUN_0069fda0 | objectId, event data (→ event 0x008000FD) |
| 0x1C | StateUpdate | owner->all | FUN_005b21c0 | objectId, gameTime, dirtyFlags, [fields...] |
| 0x1D | ObjNotFound | S->C | FUN_006a0490 | objectId (0x3FFFFFFF queries are normal) |
| 0x1E | RequestObject | C->S | FUN_006a02a0 | objectId (server responds with 0x02/0x03) |
| 0x1F | EnterSet | S->C | FUN_006a05e0 | objectId, setData |
| 0x28 | Unknown_28 | S->C | (unknown) | 1 byte payload, sent before Settings |
| 0x29 | Explosion | any | FUN_006a0080 | objectId, impact(cv4), damage(cf16), radius(cf16) |
| 0x2A | NewPlayerInGame | C->S | FUN_006a1e70 | (triggers InitNetwork + object replication) |
| 0x2C | ChatMessage | relayed | (unknown) | senderSlot, padding, msgLen, ASCII text |
| 0x35 | GameState | S->C | (unknown) | Sent after ObjCreateTeam during join |
| 0x37 | PlayerRoster | S->C | (unknown) | Sent once during join sequence |

### Checksum/NetFile Opcodes

| Opcode | Name | Direction | Handler | Payload Summary |
|--------|------|-----------|---------|-----------------|
| 0x20 | ChecksumRequest | S->C | FUN_006a5df0 | index, directory, filter, recursive |
| 0x21 | ChecksumResponse | C->S | FUN_006a4260 | index, hashes |
| 0x22 | VersionMismatch | S->C | FUN_006a4c10 | filename |
| 0x23 | SystemChecksumFail | S->C | FUN_006a4c10 | filename |
| 0x25 | FileTransfer | S->C | FUN_006a3ea0 | filename, filedata |
| 0x27 | FileTransferACK | C->S | FUN_006a4250 | (empty) |

### Event Handler Registration (from FUN_0069efe0)

| Address | Name |
|---------|------|
| 0x0069f2a0 | ReceiveMessageHandler (main dispatch) |
| 0x006a0a20 | DisconnectHandler |
| 0x006a0a30 | NewPlayerHandler |
| 0x006a0c60 | SystemChecksumPassHandler |
| 0x006a0c90 | SystemChecksumFailHandler |
| 0x006a0ca0 | DeletePlayerHandler |
| 0x006a0f90 | ObjectCreatedHandler |
| 0x006a1150 | HostEventHandler |
| 0x006a1590 | NewPlayerInGameHandler |
| 0x006a1790 | StartFiringHandler |
| 0x006a17a0 | StartWarpHandler |
| 0x006a17b0 | TorpedoTypeChangeHandler |
| 0x006a18d0 | StopFiringHandler |
| 0x006a18e0 | StopFiringAtTargetHandler |
| 0x006a18f0 | StartCloakingHandler |
| 0x006a1900 | StopCloakingHandler |
| 0x006a1910 | SubsystemStatusHandler |
| 0x006a1920 | AddToRepairListHandler |
| 0x006a1930 | ClientEventHandler |
| 0x006a1940 | RepairListPriorityHandler |
| 0x006a1970 | SetPhaserLevelHandler |
| 0x006a1a60 | DeleteObjectHandler |
| 0x006a1a70 | ChangedTargetHandler |
| 0x006a1b10 | ChecksumCompleteHandler |
| 0x006a2640 | KillGameHandler |
| 0x006a2a40 | RetryConnectHandler |
| 0x006a1240 | ObjectExplodingHandler |
| 0x006a07d0 | EnterSetHandler |
| 0x006a0a10 | ExitedWarpHandler |

---

## Appendix A: TGBufferStream Layout

```
Offset  Size  Type        Field
------  ----  ----        -----
0x00    4     vtable*     vtable pointer (PTR_LAB_00895c58 for derived reader)
0x04    4     int**       error_code_ptr
0x08    4     ...         (base class fields)
0x0C    4     int         field_0C
0x10-   ...   ...         (more base class)
0x1C    4     void*       buffer_ptr
0x20    4     int         buffer_capacity
0x24    4     int         current_position
0x28    4     int         bit_pack_bookmark
0x2C    1     byte        bit_pack_state (0=not packing, >0=current bit mask)
```

## Appendix B: Network Object Tracker Layout

Each ship has a per-peer tracking structure (at offset computed by hash table lookup):

```
Offset  Size  Type    Field
------  ----  ----    -----
0x00    4     ptr     next (linked list)
0x04    4     f32     last_force_update_time
0x08    4     f32     reserved
0x0C    4     f32     last_speed_value
0x10    4     f32     saved_pos_x (for delta compression)
0x14    4     f32     saved_pos_y
0x18    4     f32     saved_pos_z
0x1C    4     f32     saved_delta_magnitude
0x20    1     u8      saved_delta_dirX
0x21    1     u8      saved_delta_dirY
0x22    1     u8      saved_delta_dirZ
0x24    4     f32     last_orientation_update_time
0x28    1     u8      saved_fwd_dirX
0x29    1     u8      saved_fwd_dirY
0x2A    1     u8      saved_fwd_dirZ
0x2B    1     u8      saved_up_dirX
0x2C    1     u8      saved_up_dirY
0x2D    1     u8      saved_up_dirZ
0x2E    1     u8      saved_cloak_state
0x30    4     ptr     subsystem_list_iterator (for round-robin)
0x34    4     int     subsystem_round_robin_index
0x38    4     ptr     weapon_list_iterator (for round-robin)
0x3C    4     int     weapon_round_robin_index
0x40    4     ptr     weapon_hash_table_vtable (for weapon tracking)
0x44    4     int     weapon_hash_count
0x48    ...   ...     (weapon hash table data)
0x4C    4     ptr     weapon_hash_buckets
```
