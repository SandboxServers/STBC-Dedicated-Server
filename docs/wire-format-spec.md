# Star Trek: Bridge Commander - Multiplayer Wire Format Specification

Produced by systematic decompilation of stbc.exe (base 0x400000, ~5.9MB) using Ghidra.
Validated against stock dedicated server packet traces (30,000+ packets).
See also: [message-trace-vs-packet-trace.md](message-trace-vs-packet-trace.md) for packet trace cross-reference.

## Table of Contents
1. [Transport Layer](#transport-layer)
2. [Stream Primitives](#stream-primitives)
3. [Compressed Data Types](#compressed-data-types)
4. [Checksum/NetFile Opcodes (0x20-0x28)](#checksumnetfile-opcodes-0x20-0x28)
5. [Game Opcodes (0x02-0x2A)](#game-opcodes-0x02-0x2a)
6. [State Update (0x1C) - The Big One](#state-update-0x1c---the-big-one)
7. [Object Replication](#object-replication)
8. [Python Message Dispatch](#python-message-dispatch)
9. [Ship Subsystem Type Catalog](#ship-subsystem-type-catalog)
10. [Subsystem Hash (Anti-Cheat)](#subsystem-hash-anti-cheat)

---

## Transport Layer

### Encryption
All UDP game packets are encrypted with the AlbyRules! stream cipher (key at 0x0095abb4).
**Byte 0 is NOT encrypted** -- both `SendPacket` (0x006b9870) and `ReceivePacket` (0x006b95f0)
call the cipher on `buffer+1` with `length-1`. The first PRNG XOR byte happens to be 0x00,
so byte 0 would survive unchanged anyway, but the engine explicitly skips it.

GameSpy packets (first byte = `\` / 0x5C) are never encrypted.

### Raw UDP Packet
After the AlbyRules! cipher is removed, the decrypted payload has this structure:

```
Offset  Size  Field
------  ----  -----
0       1     peer_id       (0x01=server, 0x02=first client, 0xFF=unassigned/init)
1       1     msg_count     (number of transport messages in this packet, 0x00-0xFF)
2+      var   messages      (sequence of transport messages, each self-describing)
```

The receive processor (`FUN_006b5c90`) reads peer_id from byte 0, msg_count from byte 1,
then loops msg_count times, reading a type byte from each message and dispatching through
the factory table at `DAT_009962d4` (indexed by type * 4).

### Transport Message Types

The factory table at `DAT_009962d4` supports up to 256 type slots. Seven are populated:

| Type | Class | Factory | Constructor | Vtable | Registration |
|------|-------|---------|-------------|--------|-------------|
| 0x00 | TGDataMessage | FUN_006bc6a0 | FUN_006bc5b0 | 0x0089598c | FUN_006bc5a0 |
| 0x01 | TGHeaderMessage (ACK) | FUN_006bd1f0 | FUN_006bd120 | 0x008959ac | FUN_006bd110 |
| 0x02 | TGConnectMessage | FUN_006bdd10 | FUN_006bdc40 | 0x008959cc | FUN_006bdc30 |
| 0x03 | TGConnectAckMessage | FUN_006be860 | FUN_006be730 | 0x008959ec | FUN_006be720 |
| 0x04 | TGBootMessage | FUN_006badb0 | FUN_006bac70 | 0x0089596c | FUN_006bac60 |
| 0x05 | TGDisconnectMessage | FUN_006bf410 | FUN_006bf2e0 | 0x00895a0c | FUN_006bf2d0 |
| 0x32 | TGMessage (base) | FUN_006b83f0 | FUN_006b82a0 | 0x008958d0 | FUN_006b8290 |

**Type 0x32 is the general-purpose data message** used for ALL game-layer payloads.
Types 0x00-0x05 are connection management. The separation matters because type 0x32
has fragment support and uses 13-bit length, while type 0x00 has no fragment support
and uses 14-bit length. There are also separate reliable sequence counters for
types < 0x32 vs types >= 0x32 (see `FUN_006b5080`).

### Wire Formats

#### Type 0x32 - Data Message (game payloads)

```
Offset  Size  Field
------  ----  -----
0       1     type          Always 0x32
1       2     flags_len     LE uint16 (see below)
[if reliable:]
3       2     seq_num       LE uint16 reliable sequence number
[if fragmented:]
+0      1     frag_idx      Fragment index (0-based)
[if frag_idx == 0:]
+1      1     total_frags   Total number of fragments
[end if]
+N      var   payload       Game opcode + data

flags_len bit layout (LE uint16):
  bits 12-0 (0x1FFF): total message size (includes the 0x32 type byte)
  bit 13    (0x2000): is_fragment -- fragment metadata follows seq_num
  bit 14    (0x4000): ordered (priority delivery)
  bit 15    (0x8000): reliable (ACK required, has seq_num)
```

**Serializer**: FUN_006b8340 (TGMessage::WriteToBuffer)
**Deserializer**: FUN_006b83f0 (type 0x32 factory)

When viewed as two separate bytes (as the packet decoder reads them):
- `flags_len_lo` = low byte: bits 7-0 of the 13-bit length
- `flags_len_hi` = high byte: bits 12-8 of length (low 5 bits) + flags (high 3 bits)

Common `flags_len_hi` values observed in traces:
- `0x80` = reliable, no fragment, length bits 12-8 = 0
- `0x81` = reliable, no fragment, length bit 8 set
- `0xA0` = reliable + fragment, length bits 12-8 = 0
- `0xA1` = reliable + fragment, length bit 8 set
- `0x00` = unreliable, no fragment

#### Type 0x00 - Control Data Message (small, no fragment support)

```
Offset  Size  Field
------  ----  -----
0       1     type          Always 0x00
1       2     flags_len     LE uint16 (see below)
[if reliable:]
3       2     seq_num       LE uint16 reliable sequence number
+N      var   payload       Data

flags_len bit layout (LE uint16):
  bits 13-0 (0x3FFF): total message size (14-bit, max 16383)
  bit 14    (0x4000): ordered
  bit 15    (0x8000): reliable
  (NO fragment bit -- type 0x00 does not support fragmentation)
```

**Serializer**: FUN_006bc610 (TGDataMessage::WriteToBuffer)
**Deserializer**: FUN_006bc6a0 (type 0x00 factory)

#### Type 0x01 - ACK / Header Message

```
Offset  Size  Field
------  ----  -----
0       1     type          Always 0x01
1       2     seq_num       LE uint16 sequence number being ACKed
3       1     flags         bit 0: is_fragment, bit 1: has_total_frags
[if is_fragment:]
4       1     frag_idx      Fragment index of the message being ACKed
```

**Serializer**: FUN_006bd190 (TGHeaderMessage::WriteToBuffer)
**Deserializer**: FUN_006bd1f0 (type 0x01 factory)
Total size: 4 bytes (non-fragment ACK) or 5 bytes (fragment ACK)

#### Types 0x02-0x05 - Connection Management

These use derived classes with their own serialization. Wire format is:
`[type:1][type-specific data...]`
See individual factory functions for details (not yet fully analyzed).

### Fragment Reassembly

When a message is too large for a single UDP packet, `FragmentMessage` (vtable[7],
FUN_006b8720) splits it into multiple type 0x32 messages:

1. If message fits in `max_size`, returns a 1-element array (no fragmentation)
2. If too large, forces `reliable = 1` on the message
3. Creates clones via vtable[6] (Clone), each with:
   - `+0x3C = 1` (is_fragment)
   - `+0x39 = fragment_index` (0, 1, 2, ...)
4. Fragment 0 gets `+0x38 = total_fragment_count` (set AFTER the loop completes)
5. Each fragment carries a slice of the original payload

On the receive side, `FUN_006b6ad0` checks `msg+0x3C` (is_fragment). If set,
calls `FUN_006b6cc0` for reassembly:

1. Allocates a 256-element array indexed by fragment_index
2. Scans the pending message queue for fragments with matching seq_num
3. Places each fragment into the array by its `+0x39` index
4. Checks if fragment 0 exists (it carries total_frags at `+0x38`)
5. If ALL fragments collected: allocates combined buffer, copies each fragment's data in order
6. Replaces the message buffer with the reassembled data via FUN_006b89a0
7. Clears is_fragment flag (`+0x3C = 0`)
8. Removes consumed fragments from the queue

### Reliable Delivery

When `FUN_006b5c90` processes a received message with `reliable = 1` (+0x3A),
it calls `FUN_006b61e0` which creates a TGHeaderMessage (type 0x01) ACK.
The ACK carries the sequence number and, if the message was a fragment,
the fragment index.

Two separate sequence counters exist per peer:
- `peer + 0x98` (LE u16): for types < 0x32 (connection management)
- `peer + 0xA8` (LE u16): for types >= 0x32 (game data)

### TGMessage Object Layout

```
Offset  Size  Type     Field
------  ----  ----     -----
+0x00   4     ptr      vtable
+0x04   4     ptr      buffer_ptr (payload data)
+0x08   4     int      buffer_size (payload length)
+0x0C   4     int      field_0C (peer-related)
+0x10   4     int      field_10
+0x14   2     uint16   sequence_number
+0x18   4     int      retry_state
+0x1C   4     float    retry_delay
+0x20   4     float    timestamp1
+0x24   4     float    timestamp2
+0x28   4     int      field_28
+0x2C   4     int      retry_strategy (0/1/2)
+0x30   4     float    base_delay
+0x34   4     float    delay_factor
+0x38   1     byte     total_fragments (set on fragment 0 ONLY)
+0x39   1     byte     fragment_index
+0x3A   1     byte     reliable (0=unreliable, 1=reliable)
+0x3B   1     byte     ordered (priority)
+0x3C   1     byte     is_fragment
+0x3D   1     byte     field_3D (initialized to 1)
```

Constructor: FUN_006b82a0 (base), sets vtable to 0x008958d0.
Copy constructor: FUN_006b8550, copies all fields including fragment metadata.

### TGMessage Base Vtable (0x008958d0)

| Slot | Offset | Function | Name |
|------|--------|----------|------|
| 0 | +0x00 | 0x006b9430 | GetType (returns 0x32) |
| 1 | +0x04 | 0x006b82f0 | Destructor |
| 2 | +0x08 | 0x006b8340 | WriteToBuffer (serializer) |
| 3 | +0x0C | 0x006b9440 | Unknown (returns 0) |
| 4 | +0x10 | 0x006b9450 | Unknown |
| 5 | +0x14 | 0x006b8640 | GetSize |
| 6 | +0x18 | 0x006b8610 | Clone |
| 7 | +0x1C | 0x006b8720 | FragmentMessage |

### TGDataMessage Vtable (0x0089598c, overrides base)

| Slot | Offset | Function | Name |
|------|--------|----------|------|
| 0 | +0x00 | 0x006bd100 | GetType (returns 0x00) |
| 1 | +0x04 | 0x006bc5d0 | Destructor |
| 2 | +0x08 | 0x006bc610 | WriteToBuffer (14-bit length, no fragments) |
| 5 | +0x14 | 0x006bc770 | GetSize |
| 6 | +0x18 | 0x006bc740 | Clone |

### Message Dispatchers
Three C++ dispatchers plus a Python-level message path:

1. **NetFile dispatcher** (`FUN_006a3cd0` at UtopiaModule+0x80): Handles opcodes 0x20-0x27
   - Registered for event type `0x60001` (ET_NETWORK_MESSAGE_EVENT)
   - Sets `DAT_0097fa8b = 1` during processing

2. **MultiplayerGame dispatcher** (`0x0069f2a0`, registered as `ReceiveMessageHandler`): Game opcodes 0x00-0x2A
   - Jump table at `0x0069F534` (41 entries)
   - Forwards to per-opcode handlers based on first byte of payload

3. **MultiplayerWindow dispatcher** (`FUN_00504c10`): Client-side UI handler
   - Only processes if `this+0xb0 != 0` (gate flag)
   - Handles opcodes 0x00, 0x01, 0x16

4. **Python SendTGMessage**: Opcodes 0x2C-0x39 (chat, scoring, game flow)
   - Bypass all C++ dispatchers entirely
   - Handled by Python-level ReceiveMessage in multiplayer scripts

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

Used for: speed values, damage amounts, distances. Full analysis in [cf16-precision-analysis.md](cf16-precision-analysis.md).

**Constants** (extracted from .rdata):
- `DAT_00888b4c` (BASE) = 0.001 (float32, hex `3A83126F`)
- `DAT_0088c548` (MULT) = 10.0 (float32, hex `41200000`)
- `DAT_00895f50` (ENC_SCALE) = 4095.0 (encoder mantissa multiplier)
- `DAT_00895f54` (DEC_SCALE) = float32(1/4095) = 0.000244200258... (decoder inverse)

**Encoding** (`FUN_006d3a90`):
```
Input:  float value
Output: uint16

Format: [sign:1][scale:3][mantissa:12]
        Bit 15=sign, Bits 14-12=scale exponent (0-7), Bits 11-0=mantissa (0-4095)

Algorithm:
1. If value < 0: set sign bit, negate
2. Find scale (0-7) such that value < BASE * MULT^scale
   Scale 0=[0, 0.001), Scale 1=[0.001, 0.01), ..., Scale 7=[1000, 10000)
3. frac = (value - range_lo) / (range_hi - range_lo)
4. mantissa = ftol(frac * 4095.0)  // truncate toward zero
5. If scale overflows (>=8): clamp to scale=7, mantissa=0xFFF
6. Result = ((sign << 3) | scale) << 12 | mantissa
```

**Decoding** (`FUN_006d3b30`):
```
Input:  uint16 encoded
Output: float

Algorithm:
1. mantissa = encoded & 0xFFF
2. sign = (encoded >> 15) & 1
3. scale = (encoded >> 12) & 0x7
4. Compute range: lo=0, hi=BASE; for i in 0..scale: lo=hi, hi=lo*MULT
5. result = (hi - lo) * mantissa * float32(1/4095) + lo
6. If sign: result = -result
```

8 logarithmic decades from 0 to 10000, each with 4096 discrete levels (~0.022% relative precision per level). The decoder uses `1/4095` (not `1/4096`), making mantissa 4095 decode to exactly the top of the range. Encoding is LOSSY -- values always round down due to truncation. See [cf16-precision-analysis.md](cf16-precision-analysis.md) for full precision tables and [cf16-explosion-encoding.md](cf16-explosion-encoding.md) for explosion opcode analysis and mod weapon-type ID compatibility.

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

After the type 0x32 transport framing is stripped, the game-layer payload starts with the opcode byte (0x20-0x28 for checksum/NetFile operations).

### 0x20 - Checksum Request (Server -> Client)

Handler: `FUN_006a5df0`

```
Offset  Size  Type    Field
------  ----  ----    -----
0       1     u8      opcode = 0x20
1       1     u8      request_index (0x00-0x03, or 0xFF for final round)
2       2     u16     directory_name_length
4       var   string  directory_name (e.g. "scripts/")
+0      2     u16     filter_name_length
+2      var   string  filter_name (e.g. "App.pyc")
+0      bit   bool    recursive_flag
```

There are **5 checksum rounds** sent sequentially (server waits for each response before sending the next):

| Round | Index | Directory | Filter | Recursive | Purpose |
|-------|-------|-----------|--------|-----------|---------|
| 1 | `0x00` | `scripts/` | `App.pyc` | No | Core application module |
| 2 | `0x01` | `scripts/` | `Autoexec.pyc` | No | Startup script |
| 3 | `0x02` | `scripts/ships` | `*.pyc` | **Yes** | All ship definition modules |
| 4 | `0x03` | `scripts/mainmenu` | `*.pyc` | No | Menu system modules |
| 5 | `0xFF` | `Scripts/Multiplayer` | `*.pyc` | **Yes** | Multiplayer mission scripts |

Client computes file hashes and responds with 0x21.

### 0x21 - Checksum Response (Client -> Server)

Handler: `FUN_006a4260` -> `FUN_006a4560` (verify) or `FUN_006a5570` (mismatch)

The response echoes the round index from the request:

```
Offset  Size  Type    Field
------  ----  ----    -----
0       1     u8      opcode = 0x21
1       1     u8      request_index (echoes the request's round index)
2+      var   data    hash_data (variable length, opaque)
```

The server handler uses `byte[1]` to route processing:
- `byte[1] == 0xFF`: final round response (Scripts/Multiplayer), handled by main path
- `byte[1] != 0xFF`: standard round response, handled by `FUN_006a4560`

Round 2 responses are significantly larger (~400 bytes, fragmented) due to the number of ship `.pyc` files.

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

### 0x28 - Checksum Complete (Server -> Client)

No dedicated handler — signals that all checksum rounds have passed. Observed in stock dedi traces immediately before Settings (0x00) and GameInit (0x01).

```
Offset  Size  Type    Field
------  ----  ----    -----
0       1     u8      opcode = 0x28
```

Single byte, no additional payload.

### 0x24, 0x26 - Unknown/Unused

These opcode slots exist in the NetFile dispatcher range but no handler or packet trace evidence has been found for either.

---

## Game Opcodes (0x02-0x2A)

These are dispatched by the MultiplayerGame ReceiveMessageHandler (at `0x0069f2a0`). The first payload byte is the opcode, which indexes a 41-entry jump table at `0x0069F534` (opcode minus 2, covering opcodes 0x02-0x2A).

**NOTE**: Opcodes 0x00 and 0x01 are NOT in this jump table. They are handled by the MultiplayerWindow dispatcher (`FUN_00504c10`) which processes them on the client side.

**NOTE**: Opcodes 0x07-0x0F are EVENT FORWARD messages (weapon state changes, cloak, warp), NOT Python messages or combat actions. The actual combat opcodes are 0x19 (TorpedoFire) and 0x1A (BeamFire). Python messages use opcode 0x06/0x0D.

### 0x00 - Settings (Server -> Client, MultiplayerWindow dispatcher)

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

### 0x04 / 0x05 - Dead Opcodes (jump table default)

These opcode slots in the game jump table point to the DEFAULT handler (clears processing flag and returns). They are NOT used for game messages.

**Boot/kick is handled at the transport layer** via `TGBootPlayerMessage` (sent by `FUN_00506170`, the BootPlayerHandler registered for `ET_BOOT_PLAYER`), not as a game opcode.

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

### 0x07-0x0C, 0x0E-0x12, 0x1B - Event Forward Messages

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
| 0x11 | RepairListPriority | 0x008000E1 | Repair priority ordering | occasional |
| 0x12 | SetPhaserLevel | 0x008000E0 | Phaser power/intensity setting | 33 |
| 0x1B | TorpedoTypeChange | 0x008000FD | Torpedo type selection changed | occasional |

**Sender/receiver event code pairing**: The sender uses one event code locally, the receiver uses a paired code:
- D8→D7 (StartFiring), DA→D9, DC→DB, DD→6C, E0→E1, E2→E3, E4→E5, EC→ED, FE→FD

### 0x13 - Host Message

**Handler**: `FUN_006A01B0`

Host-specific message dispatch. Used for self-destruct and other host-authority actions. Processes damage via `obj+0x2C4` subsystem.

### 0x15 - CollisionEffect (Client -> Server)

**Sender**: Collision detection system via `FUN_006a17c0` (event forwarder, event code `0x00800050`)
**Handler**: `FUN_006a2470` (Handler_CollisionEffect_0x15)
**Write method**: `0x005871a0` (CollisionEvent::Write, vtable+0x34)
**Read method**: `0x00587300` (CollisionEvent::Read, vtable+0x38)

Collision damage relay. Client detects a collision locally and sends this to the host for authoritative damage processing. The host validates proximity (bounding sphere check), then re-posts the event as `0x008000fc` (HostCollisionEffect) for damage application. 84 times in a 15-minute 3-player stock session (4th most common combat opcode).

**Serialization chain**: The collision event class (factory ID `0x00008124`, vtable `0x0089395c`) inherits from TGEvent. The Write method calls the base TGEvent Write first, then appends collision-specific data.

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

**Contact point compression** (CompressedVec4_Byte format, `stream->vtable+0x98`):

The Write method at `0x005871a0` transforms each contact point to ship-relative coordinates before compression:

1. **Ship-relative transform**: If the target object exists, contact position is transformed:
   - Subtract ship NiNode position (NiNode+0x88/0x8C/0x90)
   - Apply inverse rotation via matrix multiply (`FUN_00813aa0` with NiNode+0x64 rotation matrix)
   - Scale by `DAT_00888860 / NiNode+0x94` (bounding sphere normalization)

2. **Compression** (`vtable+0xA0` at `0x006d29a0`):
   - Compute magnitude = sqrt(x^2 + y^2 + z^2)
   - If magnitude > threshold: normalize each component by (SCALE / magnitude)
   - Convert normalized components to signed bytes via ftol
   - Output: 3 signed direction bytes

3. **Magnitude byte** (`vtable+0xAC` at `0x006d2d10`):
   - Divides magnitude by a reference value (bounding radius)
   - Multiplies by scale constant at `DAT_0088b9ac`
   - Converts to unsigned byte via ftol

**Decompression** (Read at `0x00587300`, uses `stream->vtable+0x9C` at `FUN_006d30e0`):
1. Reads 4 bytes (ReadByte x4)
2. Gets bounding sphere radius from target object (via `vtable+0xE4` GetBoundingBox, radius at bbox+0x0C)
3. If target not found: uses 1.0 as default radius; if radius is 0: uses 0.01
4. Calls `vtable+0xBC` to decompress 4 bytes back to Vec3 using radius as scale
5. Allocates Vec3 (12 bytes) and stores in contact point array at event+0x2C

**Handler validation** (`Handler_CollisionEffect_0x15` at `0x006a2470`):
1. Reconstructs the TGEvent from the stream via `FUN_006d6200`
2. Verifies sender's ship matches one of the collision objects (anti-spoof)
3. If sender is the source object AND target is also player-controlled: drops the event (deduplication -- the target player will report their own collision)
4. Validates physical proximity: computes distance between the two objects, subtracts both bounding radii, checks against threshold `DAT_008955c8`
5. Changes event code from `0x00800050` to `0x008000fc` (HostCollisionEffect)
6. Posts the modified event to the event manager for host-side damage processing

**Host damage processing** (`FUN_005afad0` = ShipClass::HostCollisionEffectHandler):
- Iterates contact points, transforms each relative to the ship's NiNode
- Calls `FUN_005afd70` (damage application) per contact point with the collision force
- Also posts `0x00800053` event for collision sound/visual effects

**Example decode** (P1, 26 bytes):
```
15                    opcode = 0x15 (CollisionEffect)
24 81 00 00           type_class_id = 0x00008124
50 00 80 00           event_code = 0x00800050 (ET_COLLISION_EFFECT)
00 00 00 00           source_obj_id = 0x00000000 (environment collision)
FF FF FF 3F           target_obj_id = 0x3FFFFFFF (Player 0 ship)
01                    contact_count = 1
0D 7E 00 D9           contact[0]: dir=(+13, +126, +0) mag=217
BB 20 A0 44           force = 1281.02 (float 0x44A020BB)
```

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

Server-to-client only. Subsystems are serialized in a round-robin fashion from the ship's top-level subsystem linked list (`ship+0x284`). Each update sends a few subsystems starting from where the previous update left off.

```
+0      1     u8       start_index         Position in subsystem list where this batch begins
+1      var   data     subsystem_data      Per-subsystem WriteState output (variable length)
```

**No count field**: the receiver reads subsystem data until the stream is exhausted (`streamPos >= dataLength`).

#### Subsystem List Order

There is no fixed index table. The `start_index` is a position in the ship's serialization linked list at `ship+0x284`, whose contents and order are determined by the hardpoint script's `LoadPropertySet()` call order. Only **top-level system containers** remain in the list after `LinkAllSubsystemsToParents` (`FUN_005b3e20`) removes children. Individual weapons (phaser banks, torpedo tubes) and engines are serialized **recursively** within their parent's WriteState.

#### Per-Subsystem WriteState Formats (vtable+0x70)

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

#### Round-Robin Algorithm

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

#### Receiver (Flag 0x20 in `FUN_005b21c0`)

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

### Flag 0x40 - Cloak State

```
+0      bit   bool     cloak_active       WriteBit/ReadBit: 0 = decloaked, 1 = cloaked
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

Two entirely separate mechanisms exist for sending Python-originated data over the network:

### Mechanism 1: Engine Event Forwarding (opcodes 0x06, 0x0D, 0x07-0x12, 0x1B)

These are C++-level messages that forward engine events. The payload is a serialized TGEvent.

**Opcode 0x06 / 0x0D - Python Event**: `FUN_0069f880` strips the opcode byte, creates a stream
from remaining data, constructs TGEvent via `FUN_006d6200`, posts to the event manager. Both
opcodes route to the same handler.

**Opcodes 0x07-0x0C, 0x0E-0x10, 0x1B - Event Forwarding**: `FUN_0069fda0` forwards engine-level
events (weapon fire state, cloak, warp, subsystem toggle) to all peers. Each opcode maps to a
hardcoded event code. These are NOT user-level Python messages.

### Mechanism 2: TGMessage Script Messages (opcodes 0x2C+)

These are the user-level "script messages" that Python mods create via `TGMessage_Create()` and
send via `SendTGMessage()` or `SendTGMessageToGroup()`. They travel as **standard type 0x32
TGMessage** transport messages on the wire, with the script-defined payload as the message data.

**There is no special C++ dispatcher for these.** They bypass the C++ jump table entirely because
the MultiplayerGame switch only handles opcodes 0x02-0x2A. Instead, ALL type 0x32 TGMessages
arriving from the network are posted as `ET_NETWORK_MESSAGE_EVENT` (event type `0x60001`) to the
engine's event manager. Python handlers registered on this event read the first payload byte
themselves to determine the message type.

### MAX_MESSAGE_TYPES Constant

`MAX_MESSAGE_TYPES = 43` (0x2B), stored as a SWIG constant in the Appc module (registered at
`0x00654f31` in the SWIG init function, value stored at `0x0090b490`).

This constant defines the boundary between C++ game opcodes and Python script message types.
Python scripts define their message types as `MAX_MESSAGE_TYPES + N`:

| Constant | Value | Hex | Module |
|----------|-------|-----|--------|
| MAX_MESSAGE_TYPES | 43 | 0x2B | Appc (SWIG) |
| CHAT_MESSAGE | 44 | 0x2C | MultiplayerMenus |
| TEAM_CHAT_MESSAGE | 45 | 0x2D | MultiplayerMenus |
| MISSION_INIT_MESSAGE | 53 | 0x35 | MissionShared |
| SCORE_CHANGE_MESSAGE | 54 | 0x36 | MissionShared |
| SCORE_MESSAGE | 55 | 0x37 | MissionShared |
| END_GAME_MESSAGE | 56 | 0x38 | MissionShared |
| RESTART_GAME_MESSAGE | 57 | 0x39 | MissionShared |
| SCORE_INIT_MESSAGE | 63 | 0x3F | Mission5 |
| TEAM_SCORE_MESSAGE | 64 | 0x40 | Mission5 |
| TEAM_MESSAGE | 65 | 0x41 | Mission5 |

Mods can use any value >= 43 as their message type byte. Since the byte is written via
`WriteChar(chr(N))`, custom types up to 255 are valid.

### How Python Scripts Create and Send Messages

The canonical pattern (from `MissionShared.py`):

```python
pMessage = App.TGMessage_Create()       # Allocates TGMessage (0x40 bytes)
pMessage.SetGuaranteed(1)               # Sets +0x3A = 1 (reliable delivery)

kStream = App.TGBufferStream()          # Allocates TGBufferStream (0x30 bytes)
kStream.OpenBuffer(256)                 # Allocates 256-byte write buffer

kStream.WriteChar(chr(END_GAME_MESSAGE))  # Writes 0x38 as first byte
kStream.WriteInt(iReason)                 # Writes 4-byte LE int

pMessage.SetDataFromStream(kStream)     # Copies stream bytes into TGMessage

pNetwork.SendTGMessage(0, pMessage)     # Broadcasts to all peers
kStream.CloseBuffer()                   # Frees stream buffer
```

**SetDataFromStream** (`0x006b8a00`): Calls `stream.GetBuffer()` (vtable+0xF4, returns `+0x1C`)
and `stream.GetPos()` (vtable+0xD8, returns `+0x24`), then calls BufferCopy (`FUN_006b84d0`) to
copy exactly the written bytes into the TGMessage's data buffer (`+0x04` ptr, `+0x08` length).
No header or framing is added -- the stream content IS the TGMessage payload.

### TGBufferStream Write Primitives

All writes are **little-endian** (native x86 store instructions).

| Python Method | C++ vtable slot | Size | Format |
|---------------|----------------|------|--------|
| `WriteChar(chr(N))` | +0x54 (`0x006cf730`) | 1 byte | `uint8` |
| `WriteShort(N)` | +0x5C (`0x006cf7f0`) | 2 bytes | `uint16 LE` |
| `WriteInt(N)` | +0x64 (`0x006cf830`) | 4 bytes | `int32 LE` |
| `WriteLong(N)` | +0x6C (`0x006cf870`) | 4 bytes | `int32 LE` (same as WriteInt on Win32) |
| `WriteFloat(N)` | +0x70 (`0x006cf8b0`) | 4 bytes | `float32 LE` (IEEE 754) |
| `WriteBool(N)` | +0x58 (`0x006cf7a0`) | 1 byte | `uint8` (0 or 1) |
| `Write(buf, len)` | +0x14 (`0x006cf2b0`) | N bytes | raw memcpy |
| `WriteCString(s)` | +0x24 (`0x006cf460`) | 2+N bytes | `[uint16 LE strlen] [raw chars, NO null]` |

### SendTGMessage vs SendTGMessageToGroup

**`pNetwork.SendTGMessage(targetID, pMessage)`** (`FUN_006b4c10`, `__thiscall`):
- SWIG format: `"OiO|i"` (self, targetID:int, message:TGMessage*, optional:int)
- `targetID == 0`: **Broadcast** -- iterates all connected peers, copies message for each, sends to all
- `targetID > 0`: **Unicast** -- binary searches peer array by ID, sends to that specific peer
- `targetID == -1`: Special mode using the optional 4th param to locate peer
- Returns 0 on success, error code otherwise

**`pNetwork.SendTGMessageToGroup(groupName, pMessage)`** (`FUN_006b4de0`, `__thiscall`):
- SWIG format: `"OOO"` (self, groupName:string, message:TGMessage*)
- Binary searches the group table (`+0xF4`, sorted by name) for the group string
- Found: calls `FUN_006b4ec0` which iterates group members, sends to each valid peer
- Not found: returns error 0x10

**Built-in Groups** (created by MultiplayerGame constructor, `FUN_0069e590`):
- **"NoMe"** (`0x008e5528`): All connected peers EXCEPT the local player
- **"Forward"** (`0x008d94a0`): Same membership; used for engine event forwarding

### Byte-By-Byte Wire Example: CHAT_MESSAGE

Given this Python code:
```python
pMessage = App.TGMessage_Create()
pMessage.SetGuaranteed(1)
kStream = App.TGBufferStream()
kStream.OpenBuffer(256)
kStream.WriteChar(chr(CHAT_MESSAGE))  # 0x2C
kStream.WriteLong(pNetwork.GetLocalID())  # e.g., 0x00000002
kStream.WriteShort(5)  # string length
kStream.Write("hello", 5)  # raw bytes
pMessage.SetDataFromStream(kStream)
pNetwork.SendTGMessage(pNetwork.GetHostID(), pMessage)
```

The TGMessage payload (at `+0x04`, length `+0x08 = 12`) is:
```
2C 02 00 00 00 05 00 68 65 6C 6C 6F
^^                                      message type (CHAT_MESSAGE = 44)
   ^^ ^^ ^^ ^^                         sender ID (uint32 LE = 2)
               ^^ ^^                    string length (uint16 LE = 5)
                     ^^ ^^ ^^ ^^ ^^    "hello" (raw bytes, no null terminator)
```

This payload is serialized by `TGMessage::WriteToBuffer` (`FUN_006b8340`) into a type 0x32
transport message:
```
32 0F 80 01 00 2C 02 00 00 00 05 00 68 65 6C 6C 6F
^^                                                     transport type (0x32)
   ^^ ^^                                               flags_len (0x800F)
                                                         bits 0-12: 0x0F = 15 (total msg size)
                                                         bit 15: 1 = reliable
         ^^ ^^                                          seq_num (0x0001, reliable sequence #)
               ^^ ^^ ^^ ^^ ^^ ^^ ^^ ^^ ^^ ^^ ^^ ^^  payload (12 bytes)
```

Then in the UDP packet (after AlbyRules! encryption on bytes 1+):
```
01 01 32 0F 80 01 00 2C 02 00 00 00 05 00 68 65 6C 6C 6F
^^                                                           peer_id (0x01 = server)
   ^^                                                        msg_count (1 message)
      ^^ ... (encrypted, but shown decrypted here)           the type 0x32 message
```

### Byte-By-Byte Wire Example: Custom Mod Message (type 205)

Given this mod Python code:
```python
MY_MESSAGE = App.MAX_MESSAGE_TYPES + 162  # = 43 + 162 = 205 = 0xCD
pMessage = App.TGMessage_Create()
pMessage.SetGuaranteed(1)
kStream = App.TGBufferStream()
kStream.OpenBuffer(256)
kStream.WriteChar(chr(MY_MESSAGE))  # 0xCD
kStream.WriteInt(42)
pMessage.SetDataFromStream(kStream)
pNetwork.SendTGMessageToGroup("NoMe", pMessage)
```

TGMessage payload (5 bytes):
```
CD 2A 00 00 00
^^              custom message type (205)
   ^^ ^^ ^^ ^^ int value 42 (uint32 LE)
```

Type 0x32 transport message (10 bytes):
```
32 0A 80 01 00 CD 2A 00 00 00
^^                              transport type
   ^^ ^^                        flags_len: 0x800A (reliable, size=10)
         ^^ ^^                  seq_num: 0x0001
               ^^ ^^ ^^ ^^ ^^  payload (5 bytes)
```

### Receive Side Dispatch

1. `WSN::ReceivePacket` (`FUN_006b95f0`): recvfrom, decrypt bytes 1+ with AlbyRules!
2. `ProcessIncomingMessages` (`FUN_006b5c90`): reads peer_id, msg_count; for each message, reads
   type byte, dispatches through factory table. Type 0x32 calls `FUN_006b83f0` (TGMessage factory)
   which deserializes the flags/length/seq/payload into a TGMessage object.
3. `FUN_006b52b0`: Dequeues completed messages (handles reliable ordering, fragment reassembly)
4. `TGWinsockNetwork::Update` (`FUN_006b4560`): For each dequeued message, creates a
   `TGMessageEvent` (`FUN_006bfe80`, size 0x2C), sets event type to `ET_NETWORK_MESSAGE_EVENT`
   (0x60001), attaches the TGMessage via `FUN_006bff30`, posts to event manager.
5. **C++ handlers** (`MultiplayerGame_ReceiveMessage` at `0x0069f2a0`): Checks `GetType() == 0x32`,
   reads first payload byte, dispatches via switch for opcodes 0x02-0x2A. Opcodes outside this
   range (including all Python script messages 0x2C+) fall through the switch and are ignored.
6. **Python handlers**: Registered via `AddBroadcastPythonFuncHandler(ET_NETWORK_MESSAGE_EVENT, ...)`.
   The handler calls `pEvent.GetMessage().GetBufferStream()` to get a read view, reads the first
   byte as message type, then dispatches based on value.

Multiple handlers can be registered for `ET_NETWORK_MESSAGE_EVENT`. In stock BC:
- `MultiplayerGame::ReceiveMessageHandler` (C++, handles 0x02-0x2A)
- `MultiplayerWindow::ReceiveMessageHandler` (C++, handles 0x00, 0x01, 0x16)
- `NetFile::ReceiveMessageHandler` (C++, handles 0x20-0x27)
- `MissionShared.ProcessMessageHandler` (Python, handles 0x35-0x39)
- `MultiplayerMenus.ProcessMessageHandler` (Python, handles 0x2C-0x2D)
- Mission-specific handlers (Python, handle mission-specific types)

All handlers receive the same event. Each reads the first byte and acts on types it recognizes,
ignoring types meant for other handlers.

### Guaranteed vs Unreliable

`SetGuaranteed(1)` sets `TGMessage+0x3A = 1`, which causes:
- The `reliable` flag (bit 15) to be set in the wire format's `flags_len` field
- A 2-byte sequence number to be included after `flags_len`
- The transport layer to send ACKs (type 0x01) and retransmit on timeout
- The reliable sequence counter (`peer+0xA8` for type 0x32) to be incremented

`SetGuaranteed(0)` (default after `TGMessage_Create`): Message is sent once with no ACK or
retransmit. The `flags_len` has bit 15 = 0 and no sequence number field.

Stock BC scripts **always** call `SetGuaranteed(1)` for script messages. In theory, unreliable
script messages are supported but never used in practice.

### TGMessage Object Layout (Complete)

```
Offset  Size  Type     Field                   Set By
------  ----  ----     -----                   ------
+0x00   4     ptr      vtable                  ctor (= 0x008958d0)
+0x04   4     ptr      data_ptr                SetData / SetDataFromStream / BufferCopy
+0x08   4     int      data_length             SetData / SetDataFromStream / BufferCopy
+0x0C   4     int      from_id                 Set by send path (peer ID of sender)
+0x10   4     int      field_10                (connection context)
+0x14   2     uint16   sequence_number         Set by send helper (FUN_006b5080)
+0x18   4     int      field_18                (from address)
+0x1C   4     float    first_resend_time       Retry timing
+0x20   4     float    first_send_time         Retry timing
+0x24   4     float    timestamp               Retry timing
+0x28   4     int      field_28                (to_id on wire)
+0x2C   4     int      num_retries             Retry counter (init 0)
+0x30   4     float    backoff_time            Retry timing (init 1.0)
+0x34   4     float    backoff_factor          Retry multiplier (init 1.0)
+0x38   1     byte     total_fragments         Fragment 0 only: total fragment count
+0x39   1     byte     fragment_index          Which fragment this is (0-based)
+0x3A   1     byte     is_guaranteed           0=unreliable, 1=reliable (SetGuaranteed)
+0x3B   1     byte     is_high_priority        0=normal, 1=priority (SetHighPriority)
+0x3C   1     byte     is_fragment             0=complete, 1=fragment piece
+0x3D   1     byte     field_3D                (init 1, override_old_packets flag)
+0x3E   1     byte     field_3E                (is_multipart flag)
+0x3F   1     byte     field_3F                (is_aggregate flag)
```

Constructor: `FUN_006b82a0` (allocates 0x40 bytes from pool `FUN_00717b70`).
SWIG type: `"_TGMessage_p"` (registered at `puRam00991290`).

---

## Ship Subsystem Type Catalog

**Validated by JMP detour trace** (2026-02-10, stock dedicated server, 223K lines).
See [subsystem-trace-analysis.md](subsystem-trace-analysis.md) for full trace data.

### Vtable-to-Type Map

| vtable | Type | Named Slot | Offset | Instances (Sovereign) |
|--------|------|-----------|--------|----------------------|
| 0x0088A1F0 | PoweredSubsystem | Powered | +2B0 | 1 |
| 0x00892C98 | PowerReactor | Power | +2C4 | 1 (+1 secondary in list) |
| 0x00892D10 | LifeSupport | Unk_C | +2CC | 1 |
| 0x00892E24 | WarpDrive | Unk_E | +2D8 | 1 |
| 0x00892EAC | CloakingDevice | Cloak | +2C8 | 1 |
| 0x00892F34 | RepairSubsystem | Repair | +2C0 | 1 |
| 0x00892FC4 | ImpulseEngine | -- | -- | 4 |
| 0x00893040 | SensorArray | Unk_B | +2D0 | 1 |
| 0x00893194 | PhaserEmitter | -- | -- | 8 |
| 0x00893240 | PhaserController | Phaser | +2B8 | 1 |
| 0x00893598 | ShieldGenerator | Shield | +2B4 | 1 |
| 0x00893630 | TorpedoTube | -- | -- | 6 (4 fwd, 2 aft) |
| 0x008936F0 | TractorBeam | -- | -- | 4 |
| 0x00893794 | PulseWeapon | Pulse | +2D4 | 1 |
| 0x00895340 | ShipRefNiNode | ShipRef | +2E0 | 1 (set separately) |

### Named Slot Layout (ship+0x2B0 to ship+0x2E4)

```
+2B0  Powered      0x0088A1F0   Master powered subsystem
+2B4  Shield       0x00893598   Shield generator
+2B8  Phaser       0x00893240   Phaser controller
+2BC  (unused)     NULL         Always NULL
+2C0  Repair       0x00892F34   Auto-repair
+2C4  Power        0x00892C98   Power reactor
+2C8  Cloak        0x00892EAC   Cloaking device (present on all ships)
+2CC  LifeSupport  0x00892D10   Structural/life support
+2D0  SensorArray  0x00893040   Sensors
+2D4  Pulse        0x00893794   Pulse weapons (present on all ships)
+2D8  WarpDrive    0x00892E24   Warp drive
+2DC  (unused)     NULL         Always NULL
+2E0  ShipRef      0x00895340   NiNode scene graph backpointer
```

### Anti-Cheat Hash Field Offsets (from ship+0x27C)

These offsets are used by FUN_005b5eb0 to locate subsystem pointers for hash computation:

| Offset from +0x27C | Subsystem | Hashed Fields |
|---------------------|-----------|---------------|
| +0x34 | Sensors | health + properties |
| +0x38 | Unknown1 | via FUN_005b6330 |
| +0x3C | Unknown2 | via FUN_005b6330 |
| +0x40 | Unknown3 | via FUN_005b6330 |
| +0x44 | Hull | health + 6 shield facings |
| +0x48 | Shield | overall health |
| +0x4C | Engine | health + property |
| +0x50 | Weapons | health + 4 properties |
| +0x54 | Cloak | health only |
| +0x58 | Power | via FUN_005b6330 |
| +0x5C | Repair | health + property |
| +0x60 | Crew | health only |

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

Large messages that exceed the transport MTU are split into multiple type 0x32 messages
by `FragmentMessage` (FUN_006b8720). Fragment metadata is encoded in the flags_len field
and as prefix bytes in the payload. See "Transport Layer > Fragment Reassembly" above
for the complete mechanism.

### flags_len High Byte (commonly called "flags" in traces)

The high byte of the LE uint16 flags_len field encodes:
```
bit 7 (0x80) = Reliable delivery (has sequence number)
bit 6 (0x40) = Ordered (priority delivery)
bit 5 (0x20) = Fragmented (fragment metadata follows sequence number)
bits 4-0     = High 5 bits of the 13-bit total message length
```

Note: There is NO "more fragments" bit. The receiver detects the last fragment
by checking if all fragment indices from 0 to total_frags-1 have been received.
Fragment 0 always carries the total_frags count.

### Fragment Wire Layout
```
All fragments: [0x32][flags_len:2][seq:2][frag_idx:1][payload...]
Fragment 0:    [0x32][flags_len:2][seq:2][0x00][total_frags:1][game_opcode:1][payload...]
```

When frag_idx is 0, the factory reads one additional byte (total_frags) before the payload.
This is what makes fragment 0 the "header" fragment.

### Example: Checksum Response (3 fragments)
```
Fragment 0: flags_hi=0xA1 -> reliable(0x80) + fragment(0x20) + len_bit8(0x01)
            seq=N, frag_idx=0, total_frags=3, inner_opcode=0x21(ChecksumResp)

Fragment 1: flags_hi=0xA1 -> reliable(0x80) + fragment(0x20) + len_bit8(0x01)
            seq=N, frag_idx=1, continuation payload data

Fragment 2: flags_hi=0xA0 -> reliable(0x80) + fragment(0x20) + len_bit8(0x00)
            seq=N, frag_idx=2, continuation payload data (last fragment)
```

The receiver (FUN_006b6cc0) collects all fragments matching `seq=N` into a 256-entry
array indexed by frag_idx. Once fragment 0 (with total_frags) and all subsequent
fragments are present, it concatenates them in order and delivers the reassembled message.

### Historical Note on flag 0x01
Previous documentation incorrectly identified `flags_hi & 0x01` as a "more fragments"
flag. In reality, this is bit 8 of the 13-bit total length field. The difference between
`0xA1` and `0xA0` is simply whether the message length has bit 8 set (i.e., total
length >= 256 vs < 256). Fragment detection uses the fragment flag (bit 5 / 0x20) only.

---

## Formerly Unknown Opcodes (now identified)

Opcodes originally discovered from stock-dedi packet captures, now fully identified via Ghidra analysis:

| Opcode | Name | Handler | Direction | Stock 15-min count | Notes |
|--------|------|---------|-----------|--------------------|-------|
| 0x11 | RepairListPriority | FUN_0069fda0 | Relayed | occasional | Crew repair priority ordering (event 0x008000E1) |
| 0x12 | SetPhaserLevel | FUN_0069fda0 | Relayed | 33 | Phaser power/intensity setting (event 0x008000E0) |
| 0x15 | CollisionEffect | FUN_006a2470 | C->S | 84 | Collision damage relay — client detects, host processes |
| 0x28 | ChecksumComplete | (NetFile dispatcher) | S->C | 3 | Signals all checksum rounds passed; sent before Settings |

Python-level messages (bypass C++ dispatcher entirely via SendTGMessage):

| Byte | Name | Direction | Notes |
|------|------|-----------|-------|
| 0x2C | CHAT_MESSAGE | Relayed | `[0x2C][sender_slot:1][00 00 00][msgLen:2 LE][ASCII text]` |
| 0x2D | TEAM_CHAT_MESSAGE | Relayed | Same format as 0x2C |
| 0x35 | MISSION_INIT_MESSAGE | S->C | Game config, sent after ObjCreateTeam |
| 0x36 | SCORE_CHANGE_MESSAGE | S->C | Score deltas |
| 0x37 | SCORE_MESSAGE | S->C | Full score sync, sent once during join |
| 0x38 | END_GAME_MESSAGE | S->C | Game over signal |
| 0x39 | RESTART_GAME_MESSAGE | S->C | Game restart signal |

---

## Summary: Opcode Table

### MultiplayerWindow Dispatcher (FUN_00504c10, handles 0x00/0x01/0x16)

| Opcode | Name | Direction | Handler | Payload Summary |
|--------|------|-----------|---------|-----------------|
| 0x00 | Settings | S->C | FUN_00504d30 | gameTime, settings, playerSlot, mapName, checksumFlag |
| 0x01 | GameInit | S->C | FUN_00504f10 | (empty - just the opcode byte) |
| 0x16 | UICollisionSetting | S->C | FUN_00504c70 | collisionDamageFlag(bit) |

### Game Opcodes (MultiplayerGame Dispatcher at 0x0069F2A0, jump table at 0x0069F534, opcodes 0x02-0x2A)

| Opcode | Name | Direction | Handler | Payload Summary |
|--------|------|-----------|---------|-----------------|
| 0x02 | ObjectCreate | S->C | FUN_0069f620 | type=2, ownerSlot, serializedObject |
| 0x03 | ObjectCreateTeam | S->C | FUN_0069f620 | type=3, ownerSlot, teamId, serializedObject |
| 0x04 | (dead) | -- | DEFAULT | Jump table default; boot handled at transport layer |
| 0x05 | (dead) | -- | DEFAULT | Jump table default |
| 0x06 | PythonEvent | any | FUN_0069f880 | eventCode, eventPayload |
| 0x07 | StartFiring | any | FUN_0069fda0 | objectId, event data (→ event 0x008000D7) |
| 0x08 | StopFiring | any | FUN_0069fda0 | objectId, event data (→ event 0x008000D9) |
| 0x09 | StopFiringAtTarget | any | FUN_0069fda0 | objectId, event data (→ event 0x008000DB) |
| 0x0A | SubsysStatus | any | FUN_0069fda0 | objectId, event data (→ event 0x0080006C) |
| 0x0B | AddToRepairList | any | FUN_0069fda0 | objectId, event data (→ event 0x008000DF) |
| 0x0C | ClientEvent | any | FUN_0069fda0 | objectId, event data (from stream, preserve=0) |
| 0x0D | PythonEvent2 | any | FUN_0069f880 | eventCode, eventPayload (same as 0x06) |
| 0x0E | StartCloaking | any | FUN_0069fda0 | objectId, event data (→ event 0x008000E3) |
| 0x0F | StopCloaking | any | FUN_0069fda0 | objectId, event data (→ event 0x008000E5) |
| 0x10 | StartWarp | any | FUN_0069fda0 | objectId, event data (→ event 0x008000ED) |
| 0x11 | RepairListPriority | any | FUN_0069fda0 | objectId, event data (→ event 0x008000E1) |
| 0x12 | SetPhaserLevel | any | FUN_0069fda0 | objectId, event data (→ event 0x008000E0) |
| 0x13 | HostMsg | C->S | FUN_006A01B0 | host-specific dispatch (self-destruct etc.) |
| 0x14 | DestroyObject | S->C | FUN_006a01e0 | objectId |
| 0x15 | CollisionEffect | C->S | FUN_006a2470 | typeClassId(0x8124), eventCode(0x800050), srcObjId, tgtObjId, count, count*cv4_byte(dir+mag), force(f32) |
| 0x16 | (default) | -- | DEFAULT | Handled by MultiplayerWindow dispatcher, not game jump table |
| 0x17 | DeletePlayerUI | S->C | FUN_006a1360 | player UI cleanup |
| 0x18 | DeletePlayerAnim | S->C | FUN_006a1420 | player deletion animation |
| 0x19 | TorpedoFire | owner->all | FUN_0069f930 | objId, flags, velocity(cv3), [targetId, impact(cv4)] |
| 0x1A | BeamFire | owner->all | FUN_0069fbb0 | objId, flags, targetDir(cv3), moreFlags, [targetId] |
| 0x1B | TorpTypeChange | any | FUN_0069fda0 | objectId, event data (→ event 0x008000FD) |
| 0x1C | StateUpdate | owner->all | FUN_0069FF50 | objectId, gameTime, dirtyFlags, [fields...] |
| 0x1D | ObjNotFound | S->C | FUN_006a0490 | objectId (0x3FFFFFFF queries are normal) |
| 0x1E | RequestObject | C->S | FUN_006a02a0 | objectId (server responds with 0x02/0x03) |
| 0x1F | EnterSet | S->C | FUN_006a05e0 | objectId, setData |
| 0x20-0x28 | (default) | -- | DEFAULT | Handled by NetFile dispatcher, not game jump table |
| 0x29 | Explosion | S->C | FUN_006a0080 | objectId, impact(cv4), damage(cf16), radius(cf16) |
| 0x2A | NewPlayerInGame | S->C | FUN_006a1e70 | (triggers InitNetwork + object replication) |

### Python-Level Messages (via SendTGMessage, bypass C++ dispatcher)

| Byte | Name | Direction | Handler | Payload Summary |
|------|------|-----------|---------|-----------------|
| 0x2C | CHAT_MESSAGE | relayed | Python ReceiveMessage | senderSlot, padding, msgLen, ASCII text |
| 0x2D | TEAM_CHAT_MESSAGE | relayed | Python ReceiveMessage | same format as 0x2C |
| 0x35 | MISSION_INIT_MESSAGE | S->C | Python ReceiveMessage | game config, sent after ObjCreateTeam |
| 0x36 | SCORE_CHANGE_MESSAGE | S->C | Python ReceiveMessage | score deltas |
| 0x37 | SCORE_MESSAGE | S->C | Python ReceiveMessage | full score sync, sent once during join |
| 0x38 | END_GAME_MESSAGE | S->C | Python ReceiveMessage | game over signal |
| 0x39 | RESTART_GAME_MESSAGE | S->C | Python ReceiveMessage | game restart signal |

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
