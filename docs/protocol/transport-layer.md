> [docs](../README.md) / [protocol](README.md) / transport-layer.md

# Transport Layer

Produced by systematic decompilation of stbc.exe (base 0x400000, ~5.9MB) using Ghidra.
Validated against stock dedicated server packet traces (30,000+ packets).

## Encryption

All UDP game packets are encrypted with the AlbyRules! stream cipher (key at 0x0095abb4).
**Byte 0 is NOT encrypted** -- both `SendPacket` (0x006b9870) and `ReceivePacket` (0x006b95f0)
call the cipher on `buffer+1` with `length-1`. The first PRNG XOR byte happens to be 0x00,
so byte 0 would survive unchanged anyway, but the engine explicitly skips it.

GameSpy packets (first byte = `\` / 0x5C) are never encrypted.

## Raw UDP Packet

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

## Transport Message Types

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

## Wire Formats

### Type 0x32 - Data Message (game payloads)

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

### Type 0x00 - Control Data Message (small, no fragment support)

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

### Type 0x01 - ACK / Header Message

```
Offset  Size  Field
------  ----  -----
0       1     type          Always 0x01
1       2     seq_num       LE uint16 sequence number being ACKed
3       1     flags         bit 0: is_fragment, bit 1: is_below_0x32 (msg type category)
[if is_fragment:]
4       1     frag_idx      Fragment index of the message being ACKed
```

**Serializer**: FUN_006bd190 (TGHeaderMessage::WriteToBuffer)
**Deserializer**: FUN_006bd1f0 (type 0x01 factory)
Total size: 4 bytes (non-fragment ACK) or 5 bytes (fragment ACK)

### Types 0x02-0x05 - Connection Management

These use derived classes with their own serialization. Wire format is:
`[type:1][type-specific data...]`
See individual factory functions for details (not yet fully analyzed).

## Fragment Reassembly

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

## Reliable Delivery

When `FUN_006b5c90` processes a received message with `reliable = 1` (+0x3A),
it calls `FUN_006b61e0` which creates a TGHeaderMessage (type 0x01) ACK.
The ACK carries the sequence number and, if the message was a fragment,
the fragment index.

Two separate sequence counters exist per peer:
- `peer + 0x98` (LE u16): for types < 0x32 (connection management)
- `peer + 0xA8` (LE u16): for types >= 0x32 (game data)

## TGMessage Object Layout

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

## TGMessage Base Vtable (0x008958d0)

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

## TGDataMessage Vtable (0x0089598c, overrides base)

| Slot | Offset | Function | Name |
|------|--------|----------|------|
| 0 | +0x00 | 0x006bd100 | GetType (returns 0x00) |
| 1 | +0x04 | 0x006bc5d0 | Destructor |
| 2 | +0x08 | 0x006bc610 | WriteToBuffer (14-bit length, no fragments) |
| 5 | +0x14 | 0x006bc770 | GetSize |
| 6 | +0x18 | 0x006bc740 | Clone |

## Message Dispatchers

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

## Fragmented Reliable Messages

Large messages that exceed the transport MTU are split into multiple type 0x32 messages
by `FragmentMessage` (FUN_006b8720). Fragment metadata is encoded in the flags_len field
and as prefix bytes in the payload. See "Fragment Reassembly" above
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

## TGMessage Object Layout (Complete)

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
