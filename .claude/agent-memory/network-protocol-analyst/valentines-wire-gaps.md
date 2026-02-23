# Valentine's Day Wire Format Cross-Reference (2026-02-23)

Cross-reference of Valentine's Day battle trace against existing OpenBC protocol docs.
Source: `logs/battle-of-valentines-day/packet_trace.log` (138,695 packets, 33.5 min, 3 players)

## 1. TorpedoFire (0x19) — Arc Data Gap

Existing doc at `docs/protocol/game-opcodes.md` lines 232-258 covers basic structure but
the arc trajectory data is undocumented.

### Observed Wire Format
```
19 [objId:i32v] [flags1:u8] [flags2:u8] [velocity:cv3]
  if has_target (flags2 bit 1): [targetId:i32v] [impact:???]
  if has_arc (flags2 bit 0) and NOT has_target: [8 bytes trailing arc data]
```

### Examples
No target, with arc (flags2=0x01): 18 bytes payload
```
19 0D 00 00 40 02 01 DF 87 11 FF FF 03 40 00 88 D8 5C
   ^obj=0x4000000D ^fl ^fl ^cv3       ^trailing 8 bytes
```
Trailing: FF FF 03 40 = ReadInt32v 0x4003FFFF (server ship?), 00 88 D8 5C = unknown 4B

With target + arc (flags2=0x03): 18 bytes payload
```
19 9C 00 04 40 03 03 CF D2 6B 70 00 00 40 70 C7 FA 49
   ^obj=0x4004009C ^fl ^fl ^cv3  ^target=0x40000070 ^4B
```
Impact only 4 bytes (70 C7 FA 49), not 5 as doc says for cv4.

### flags1 Values
- 0x02 = most torpedoes (no target lock)
- 0x03 = targeted torpedoes

### flags2 Values
- 0x01 = has_arc only (photon torpedoes fired forward)
- 0x03 = has_arc + has_target (locked torpedoes)
- 0x05 = noted in doc for photon torpedoes (needs verification)

### TO DO
- RE FUN_0057CB10 (TorpedoSystem::SendFireMessage) to decode the trailing bytes
- Determine if the 4-byte "impact" is a different encoding than cv4

## 2. BeamFire (0x1A) — Fully Documented

Wire format at `docs/protocol/game-opcodes.md` lines 260-282 is complete and verified.
Example with target (14 bytes payload, msg len=19):
```
1A 77 00 00 40 02 75 0E D2 03 68 00 08 40
   ^obj=0x40000077 ^f ^cv3     ^mf ^target=0x40080068
```

## 3. ObjCreate (0x02) Non-Team — Mission Objects

3 instances at lines 46633/46645/46657, all S->C to Peer#2 during third player join.
- owner=0 (server-owned), str1="Multi1" (set name)
- Object IDs: 0x22, 0x24, 0x25 (low range = server-created objects)
- Sent immediately before Explosion (0x29) messages
- Likely: mission environment objects replicated to joining player
- First object has str0="XK" (entity identifier?)

## 4. PythonEvent2 (0x0D) — NOT Relayed

DEFINITIVE: 75 instances, ALL C->S, ZERO S->C.
- message-trace-vs-packet-trace.md line 102: "12 factory, 12 C->S, 0 S->C"
- Valentine's trace: 75 total (3 players x ~25 each)
- All carry eventCode=0x0000010C (TGObjPtrEvent, power reactor state)
- Jump table index 11 (0x0D-2) -> FUN_0069f880 directly (no relay wrapper)
- Jump table index 4 (0x06-2) -> relay-then-FUN_0069f880

## 5. Disconnect (type 0x05) — Verified

```
05 0A [8 bytes data: C0 02 00 02 0A 00 32 03]
```
- byte1 always 0x0A
- 8-byte payload consistent across all traces
- Server ACKs seq=2, retransmits 7x at ~0.67s
- TGBootMessage (type 0x04) never seen on wire

## 6. Keepalive (type 0x00) — Two Variants

Full (handshake): `00 [flags_len:2 LE=0xC016] [seq:2 LE] [slot:1] [IP:4] [name:UTF-16LE+null]`
Short (steady-state): `00` (1 byte, type only)

## 7. Post-Checksum Bundle

Always: [ACK] [0x28 no-payload] [0x00 Settings] [0x01 GameInit] in ONE datagram.
0x28 = "checksums complete" signal. Verified 3/3 joins.
