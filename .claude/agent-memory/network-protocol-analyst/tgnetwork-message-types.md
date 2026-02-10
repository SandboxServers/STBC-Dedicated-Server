# TGNetwork Message Type Table

## Framing Structure

```
UDP Payload (after decryption):
[dir:1] [msg_count:1] [msg1...] [msg2...] ... [msgN...]

direction: 0x01=server->client, 0x02=client->server, 0xFF=initial_contact
msg_count: number of concatenated messages (1-14 observed)
```

## Message Types (first byte of each message)

### Fixed-Size Messages
| Type | Size | Name | Description |
|------|------|------|-------------|
| 0x00 | 3B   | Keepalive/Settings | [00][byte1][flags] |
| 0x01 | 4B   | ACK/Status | [01][seq][00][flags] - flags: 0x00=plain, 0x02=with_data |

### Variable-Size Messages
| Type | Name | Format |
|------|------|--------|
| 0x32 | Reliable | [32][msg_len][flags][seq_hi][seq_lo][payload...] |

### Reliable Inner Opcodes (inside 0x32 wrapper)
When flags & 0x80, the message requires acknowledgment.

### Unreliable Game Data (0x00 type, 0x1C sub-opcode)
```
[0x00] [0x1C] [f32:object_id] [f32:game_time] [bitmask_byte] [data...]
```
This is the format for ALL high-frequency gameplay packets. The outer byte[3]
value (which appears in the analysis as the "message type") is actually the
first byte of an unreliable message that starts with type=0x00, then 0x1C.

Actually: After re-examining, the structure is:
- For single-message unreliable packets: [dir][01][32][len][00][1C][f32][f32][mask][data]
  - The 0x32 IS the message type (reliable wrapper) with length=len
  - flags=0x00 means unreliable (no ack needed)
  - The 0x1C at byte[5] is the INNER game opcode

## Inner Game Opcodes (byte after flags+seq in reliable, or at offset 5 in unreliable)

### 0x1C = State Update (most common inner opcode)
Format: `[1C] [f32:object_id] [f32:game_time] [bitmask] [data...]`

The "message types" at byte[3] are actually the LENGTH byte of 0x32 reliable messages:
- 0x0D = 13 bytes reliable msg (minimal state update, just bitmask 0x80)
- 0x0F = 15 bytes (state update with 3 extra bytes)
- 0x10 = 16 bytes
- 0x11 = 17 bytes
- 0x12 = 18 bytes (most common C->S, 694 packets)
- 0x13 = 19 bytes
- 0x14 = 20 bytes
- 0x17 = 23 bytes (most common S->C, 868 packets)
- 0x18 = 24 bytes
- 0x19 = 25 bytes
- 0x1A = 26 bytes
- 0x1B = 27 bytes
- 0x1D = 29 bytes
- 0x24 = 36 bytes (position update with 3D coords)

### Bitmask Values (byte after game_time float)
| Mask  | Meaning | Context |
|-------|---------|---------|
| 0x80  | Minimal heartbeat | Most 0x0D packets (C->S) |
| 0x20  | Server state block | Various S->C sizes |
| 0x82  | Client orientation? | Type 0x12 (C->S, 694 pkts) |
| 0x90  | Cloak state? | Type 0x0F during 18:13:45-18:14:25 (281 pkts) |
| 0x92  | Client angular vel? | Type 0x14 (C->S, 405 pkts) |
| 0x96  | Client extended | Type 0x17 (C->S variant) |
| 0x9D  | Full position | Type 0x24 with 3 position floats |
| 0x9E  | Position + orient | Type 0x1A (C->S variant) |
| 0x84  | Sub-system state | Type 0x10 (18 pkts during combat) |
| 0xC0  | Weapon/damage? | Type 0x0E (rare, 4 C->S during combat) |

### Reliable Game Events (type 0x32, flags=0x80)

#### Type 0x16 inner opcode (Reliable State/Score)
C->S format: `[08] [01 01 00 00] [DA 00] [80 00 00 00 00 00] [f32:value1] [00 00 00 00] [00 00 00 00]`
S->C format: `[06] [01 01 00 00] [DF 00] [80 00] [f32:value1] [f32:value2] [f32:value3]`

#### Type 0x1E inner opcode (Major Game Events)
C->S: inner=[07][28 81 00 00][D8 00][80 00 00 00 00 00][f32:game_time][00 00 00 00][00 00 00 00]
S->C: inner=[06][29 81 00 00][4E 00][80 00 00 00 00 00][f32:value1][00 00 00 00][f32:value2]
  - Contains score data: kills, deaths, round info
  - value1 and value2 are game-time-related

#### Type 0x0A inner opcode (Mission Init)
Contains mission setup data: `[35 08 09 FF FF] [32 17...] [reliable sub-messages]`

### Checksum Opcodes (inside reliable messages)
| Inner | Name | Content |
|-------|------|---------|
| 0x20  | Checksum Request | [dir_path_len][dir_path][filter_len][filter] |
| 0x21  | Checksum Response | [index][hash_data...] |
| 0x28  | Ship Selection | "Systems.Poseidon.Poseidon1" with spawn coordinates |

### Object Network IDs
Encoded as IEEE 754 floats near 2.0:
- Primary ship: 0x3FFFFFFF (mantissa=0x7FFFFF, essentially 2.0)
- New objects get IDs 0x4000002D, 0x40000051, 0x4000006C
- The mantissa low bits encode a sequential counter
