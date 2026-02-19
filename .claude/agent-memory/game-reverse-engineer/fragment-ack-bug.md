# Fragment ACK Bug Analysis (2026-02-18)

## Summary
Client-side bug in BC 1.1: fragmented reliable messages retransmit endlessly despite server ACKs.
Full static analysis performed. Per-fragment ACK logic appears correct but bug manifests consistently.

## Key Functions

| Address | Name | Role |
|---------|------|------|
| 0x006b5080 | SendHelper | Fragments message, queues each fragment with shared seq, increments counter once |
| 0x006b8720 | FragmentMessage | Splits large TGMessage into N fragments (vtable[7]) |
| 0x006b55b0 | SendOutgoingPackets | 3 queue passes: ACK-send(+0x9C), retransmit(+0x80), first-send(+0x64) |
| 0x006b61e0 | HandleReliableReceived | Creates per-fragment ACK entries in peer+0x9C; 4-field dedup |
| 0x006bd190 | TGHeaderMessage::WriteToBuffer | Serializes ACK: type+seq+flags+[frag_idx] |
| 0x006bd1f0 | TGHeaderMessage::ReadFromBuffer | Factory: parses ACK, sets +0x14(seq), +0x3C(frag), +0x39(idx), +0x40(below32) |
| 0x006b5c90 | ProcessIncomingMessages | Receive loop; calls 006b61e0 THEN 006b6ad0 for each msg |
| 0x006b6ad0 | QueueForDispatch | Queues msgs; calls ReassembleFragment for reliable+fragmented |
| 0x006b5f70 | DispatchReceivedMessages | Processes dispatch queues; type switch to handlers |
| 0x006b64d0 | HandleACK | Searches peer+0x80 retransmit queue for matching entry, removes ONE |
| 0x006b6cc0 | ReassembleFragment | Collects fragments by seq+frag_idx, reassembles when complete |

## Peer Queue Layout (per-peer structure offsets)

| Offset | Type | Field |
|--------|------|-------|
| +0x18 | u32 | peer player ID |
| +0x24 | u16 | expected reliable seq for types < 0x32 |
| +0x26 | u16 | send reliable seq counter for types < 0x32 |
| +0x28 | u16 | expected reliable seq for types >= 0x32 |
| +0x2A | u16 | send reliable seq counter for types >= 0x32 |
| +0x30 | float | last activity timestamp |
| +0x64 | node* | first-send queue HEAD |
| +0x68 | node* | first-send queue TAIL |
| +0x7C | u32 | first-send queue COUNT |
| +0x80 | node* | retransmit queue HEAD (awaiting ACK) |
| +0x84 | node* | retransmit queue TAIL |
| +0x8C | node* | retransmit cursor |
| +0x90 | u32 | retransmit cursor index |
| +0x98 | u32 | retransmit queue COUNT |
| +0x9C | node* | ACK-outbox HEAD |
| +0xA0 | node* | ACK-outbox TAIL |
| +0xA8 | node* | ACK-outbox cursor |
| +0xAC | u32 | ACK-outbox cursor index |
| +0xB4 | u32 | ACK-outbox COUNT |

Queue nodes: 8 bytes `[msg_ptr:4][next_ptr:4]`

## TGMessage Object Layout (0x40 bytes)

| Offset | Size | Field |
|--------|------|-------|
| +0x00 | 4 | vtable |
| +0x04 | 4 | data_ptr |
| +0x08 | 4 | data_len |
| +0x0C | 4 | ??? |
| +0x14 | 2 | reliable seq number |
| +0x18 | 4 | retransmit_count |
| +0x1C | 4 | retransmit_interval (float) |
| +0x20 | 4 | last_send_time (float) |
| +0x24 | 4 | first_send_time (float) |
| +0x28 | 4 | target player ID |
| +0x2C | 4 | backoff_mode |
| +0x30 | 4 | initial_interval (float) |
| +0x34 | 4 | max_interval (float) |
| +0x38 | 1 | total_fragments (only on frag 0) |
| +0x39 | 1 | fragment_index |
| +0x3A | 1 | is_reliable |
| +0x3B | 1 | is_ordered |
| +0x3C | 1 | is_fragmented |
| +0x3D | 1 | flag (init=1 for msg, 0 for header) |

## ACK Wire Format (TGHeaderMessage, type 0x01)

```
[0x01]              type byte
[seq_lo] [seq_hi]   u16 LE - seq of message being ACKed
[flags]             bit 0: is_fragmented, bit 1: is_below_0x32
[if fragmented:]
  [frag_idx]        fragment index being ACKed
```

## ACK Handler Matching (FUN_006b64d0)

Walks peer+0x80 retransmit queue. For each entry:
1. `ACK.is_below_0x32` must equal `(msg.GetType() < 0x32)`
2. `ACK.seq (+0x14)` must equal `msg.seq (+0x14)` (u16)
3. Fragment matching:
   - Both fragmented + same frag_idx -> MATCH (remove at 0x6b656a via FUN_006b78d0)
   - Both non-fragmented -> MATCH (remove at 0x6b6594 inline)
   - Mixed -> no match
4. Returns after removing ONE entry

## Verified Correct Paths
- Fragment creation: all N fragments get same seq, frag_idx 0..N-1, is_fragmented=1
- Seq counter: incremented by 1 ONCE (not per fragment)
- ACK creation (server): per-fragment, copies seq+is_fragmented+frag_idx from incoming
- ACK dedup: 4-field match prevents merging different frag_idx ACKs
- ACK serialization: includes frag_idx when is_fragmented=1
- ACK parsing (client): correctly reads is_fragmented + frag_idx from wire
- ACK dispatch: goes to unreliable queue, NOT through reassembly
- ACK handler: 4-field match correctly identifies per-fragment entries
- Retransmit queue: all reliable msgs go to peer+0x80 regardless of type

## Remaining Hypotheses (need runtime verification)

1. **ACK delivery failure**: All 3 ACKs may be created but only some arrive (packet loss, batching)
2. **Queue corruption**: Node manipulation in concurrent access could corrupt linked list
3. **Retransmit re-entry**: Fragment being retransmitted gets re-queued to +0x80 before ACK arrives
4. **FUN_006b8670 backoff**: Retransmit timer reset logic may prevent ACK processing window
5. **Memory reuse**: Pool allocator reuses freed message memory, corrupting field values
