# Fragmented Reliable Message ACK Bug — Reverse Engineering Analysis

## Observable Behavior

From wire traces of BC 1.1 clients connecting to both the stock dedicated server and our reimplementation:

1. Client sends a fragmented reliable message (3 fragments, all sharing seq=0x0200, flags 0xA1/0xA1/0xA0)
2. Server responds with ACK (seq=0x0200)
3. Client **ignores** the ACK and retransmits all 3 fragments every ~2 seconds
4. Retransmission continues for the entire session duration (10+ retransmits observed, no backoff limit)
5. Non-fragmented reliable messages (seq=0x0000, 0x0100, 0x0300, 0x0400) are ACKed correctly and stop retransmitting immediately

Both the stock dedicated server and our reimplementation produce identical ACK bytes and identical endless retransmit behavior. This confirms a **client-side bug**.

---

## Transport Layer Architecture

### Three Per-Peer Send Queues

Each peer object maintains three linked-list queues for outgoing messages:

| Queue | Head | Tail | Count | Cursor | Index | Purpose |
|-------|------|------|-------|--------|-------|---------|
| First-send | +0x64 | +0x68 | +0x7C | — | — | New messages awaiting first transmission |
| Retransmit | +0x80 | +0x84 | +0x98 | +0x8C | +0x90 | Reliable messages awaiting ACK |
| ACK-outbox | +0x9C | +0xA0 | +0xB4 | +0xA8 | +0xAC | ACK messages to send back |

Queue nodes: 8 bytes each — `[msg_ptr:4][next_ptr:4]`

### Peer Object Key Fields

| Offset | Type | Field |
|--------|------|-------|
| +0x18 | u32 | peer player ID |
| +0x24 | u16 | expected reliable seq (types < 0x32) |
| +0x26 | u16 | send reliable seq counter (types < 0x32) |
| +0x28 | u16 | expected reliable seq (types >= 0x32) |
| +0x2A | u16 | send reliable seq counter (types >= 0x32) |
| +0x30 | float | last activity timestamp |
| +0xBC | u8 | is_disconnecting flag |

### Sequence Counter Management

Two separate per-peer counters partition reliable delivery by message category:
- `peer+0x26` / `peer+0x2A`: **send** counters (incremented when queuing outgoing reliable messages)
- `peer+0x24` / `peer+0x28`: **expected** counters (incremented when dispatching received reliable messages)

The boundary is type 0x32: types 0x00-0x31 use the first pair, types 0x32+ use the second.

---

## TGMessage Object Layout (0x40 bytes)

Base vtable: `0x008958d0`. Constructor: `FUN_006b82a0`.

| Offset | Size | Type | Field |
|--------|------|------|-------|
| +0x00 | 4 | ptr | vtable |
| +0x04 | 4 | ptr | data_ptr (payload buffer) |
| +0x08 | 4 | u32 | data_len (payload length) |
| +0x0C | 4 | u32 | sender_player_id (set by receive path, not serialized) |
| +0x10 | 4 | u32 | receive_metadata |
| +0x14 | 2 | u16 | reliable sequence number |
| +0x18 | 4 | u32 | retransmit_count |
| +0x1C | 4 | float | retransmit_interval |
| +0x20 | 4 | float | last_send_time |
| +0x24 | 4 | float | first_send_time |
| +0x28 | 4 | u32 | target_player_id |
| +0x2C | 4 | u32 | backoff_mode (0/1/2) |
| +0x30 | 4 | float | initial_interval |
| +0x34 | 4 | float | max_interval |
| +0x38 | 1 | u8 | total_fragments (only valid on fragment index 0) |
| +0x39 | 1 | u8 | fragment_index |
| +0x3A | 1 | u8 | is_reliable |
| +0x3B | 1 | u8 | is_ordered |
| +0x3C | 1 | u8 | is_fragmented |
| +0x3D | 1 | u8 | field_3D (initialized to 1 for TGMessage, 0 for TGHeaderMessage) |

### TGHeaderMessage Extension (0x44 bytes)

Vtable: `0x008959ac`. Constructor: `FUN_006bd120`.

Inherits all TGMessage fields. Additional:

| Offset | Size | Type | Field |
|--------|------|------|-------|
| +0x40 | 1 | u8 | is_below_0x32 (1 if original message type < 0x32) |

---

## ACK Wire Format (Type 0x01)

Serializer: `FUN_006bd190` (TGHeaderMessage::WriteToBuffer)
Deserializer: `FUN_006bd1f0` (TGHeaderMessage factory)

```
Offset  Size  Field
------  ----  -----
0       1     type            Always 0x01
1       2     seq_num         LE uint16 - sequence number being ACKed
3       1     flags           bit 0: is_fragmented, bit 1: is_below_0x32
[if is_fragmented:]
4       1     frag_idx        Fragment index being ACKed
```

Total size: 4 bytes (non-fragment ACK) or 5 bytes (fragment ACK).

**Note**: The `flags` byte bit 1 carries `is_below_0x32` (whether the original message type was < 0x32), NOT `has_total_frags` as previously documented in wire-format-spec.md.

---

## Complete Message Flow

### Send Path — FUN_006b5080 (SendHelper)

1. Reads seq counter from peer: `peer+0x2A` for types >= 0x32, `peer+0x26` for types < 0x32
2. Calls `msg->vtable[7]` (FragmentMessage, `FUN_006b8720`) which returns an array of N message pointers
3. **All N fragments receive the SAME seq number** (read once from the peer counter)
4. Each fragment is assigned: `*(u16*)(fragment+0x14) = seq`, `*(u32*)(fragment+0x28) = peer+0x18`
5. Each fragment is appended to the first-send queue (`peer+0x64`)
6. The seq counter is incremented **once** (not per fragment)

### Fragment Creation — FUN_006b8720 (FragmentMessage)

1. If message fits in `max_size`: returns 1-element array (no fragmentation)
2. If too large: forces `is_reliable = 1` on the original message
3. Creates N clones via vtable[6] (Clone, `FUN_006b8610`)
4. Each clone gets: `+0x3C = 1` (is_fragmented), `+0x39 = fragment_index` (0, 1, 2, ...)
5. Fragment 0 gets `+0x38 = total_fragment_count` (set AFTER loop completion)
6. Each fragment carries a slice of the original payload

### First Send — FUN_006b55b0 (SendOutgoingPackets)

Processes three queues per peer in this order:
1. **ACK-outbox** (`peer+0x9C`): Serialize and send pending ACKs
2. **Retransmit** (`peer+0x80`): Retransmit expired reliable messages
3. **First-send** (`peer+0x64`): Send new messages for the first time

For each first-send message:
- Call `vtable[2]` (WriteToBuffer) to serialize into the packet
- Remove from first-send queue
- If reliable: move to retransmit queue (`peer+0x80`), record send timestamp
- If not reliable: destroy the message

After first send, **all 3 fragment messages are separate entries in the retransmit queue** (`peer+0x80`), each with the same seq but different `fragment_index`.

### Retransmit Timer — FUN_006b8700 / FUN_006b8670

Each message in the retransmit queue has:
- `+0x1C`: current retransmit interval (float, seconds)
- `+0x20`: last send time
- `+0x18`: retransmit count

`FUN_006b8700` checks if `current_time - last_send_time > retransmit_interval`. If expired, returns true (message should be retransmitted).

`FUN_006b8670` updates the retransmit count and interval. The backoff strategy depends on `+0x2C`:
- Mode 0: fixed interval
- Mode 1: linear backoff
- Mode 2: exponential backoff (clamped to `+0x34` max)

**No maximum retransmit count observed** — messages retransmit indefinitely until ACKed or the connection drops.

If the time since first send (`+0x24`) exceeds the peer's timeout (`peer+0xB8` area), the message is dropped (removed from queue and destroyed via `FUN_006b78d0`).

### Receive Path — FUN_006b5c90 (ProcessIncomingMessages)

For each transport message in a received UDP packet:
1. Read type byte, dispatch to factory table (`DAT_009962d4`) to create message object
2. Set `msg+0x0C` = sender player ID (from packet byte 0)
3. Look up or create peer object
4. **If reliable** (`msg+0x3A != 0`): call `FUN_006b61e0` (create ACK to send back)
5. Call `FUN_006b6ad0` (queue for dispatch)

### ACK Creation (Server Side) — FUN_006b61e0 (HandleReliableReceived)

Called once per received reliable message (including individual fragments):

1. Extract from incoming message: `seq (+0x14)`, `is_fragmented (+0x3C)`, `fragment_index (+0x39)`
2. Compute `is_below_0x32 = (GetType() < 0x32)`
3. **Dedup search**: Walk the peer's ACK-outbox (`peer+0x9C`) looking for existing entry with ALL FOUR fields matching:
   - `existing.seq == incoming.seq`
   - `existing.is_below_0x32 == incoming.(type < 0x32)`
   - `existing.is_fragmented == incoming.is_fragmented`
   - `existing.fragment_index == incoming.fragment_index`
4. If match found: refresh timer only (already scheduled)
5. If no match: allocate new `TGHeaderMessage` (0x44 bytes), set all 4 fields, append to ACK-outbox

**For a 3-fragment message, this creates THREE separate ACK entries** with different `fragment_index` values (0, 1, 2). The dedup correctly distinguishes them because `frag_idx` differs.

### Dispatch — FUN_006b5f70 (DispatchReceivedMessages)

Processes two queues:
1. Unreliable queue (`this+0x70` for types < 0x32, `this+0x38` for types >= 0x32)
2. Reliable queue (`this+0x8C` for types < 0x32, `this+0x54` for types >= 0x32)

For each message, looks up peer via `msg+0x0C` (sender ID), then dispatches by GetType():
- Type 0: `FUN_006b63a0` (TGDataMessage handler)
- **Type 1**: `FUN_006b64d0` (**HandleACK** — searches retransmit queue)
- Type 3: `FUN_006b6640` (TGConnectAckMessage handler)
- Type 4: `FUN_006b6a70` (TGBootMessage handler)
- Type 5: `FUN_006b6a20` (TGDisconnectMessage handler)

ACK messages (type 0x01) are unreliable, so they go through the unreliable dispatch queue. They are NOT fed through fragment reassembly (reassembly only applies to reliable messages in `FUN_006b6ad0`).

### ACK Handler (Client Side) — FUN_006b64d0 (HandleACK)

Called with `(ACK_message, peer_ptr)`. Searches the peer's retransmit queue (`peer+0x80`):

```
For each entry in retransmit queue:
  1. Check is_below_0x32:  ACK.is_below_0x32 == (msg.GetType() < 0x32)?
  2. Check seq:            ACK.seq == msg.seq?  (u16 comparison)
  3. Check fragment status:
     - Both fragmented:      ACK.frag_idx == msg.frag_idx?  → MATCH
     - Both non-fragmented:  → MATCH
     - Mixed (one frag, one not):  → no match
  4. On MATCH: remove entry from queue, destroy message, RETURN
```

**Critical**: The function returns after removing **ONE** matching entry. For per-fragment ACKs, each ACK call removes the corresponding fragment entry.

### Fragment Reassembly (Receive Side) — FUN_006b6cc0

Called from `FUN_006b6ad0` when a reliable fragmented message is received:

1. Allocates 256-element array indexed by `fragment_index`
2. Scans the reliable dispatch queue for fragments with matching `seq`
3. Places each fragment into the array by its `+0x39` index
4. Checks if fragment 0 exists (it carries `total_frags` at `+0x38`)
5. If ALL fragments collected: allocates combined buffer, copies payload in order
6. Clears `is_fragmented` flag (`+0x3C = 0`) on the reassembled message
7. Removes consumed fragments from the queue
8. Returns the reassembled message

---

## Analysis: Why the Bug Occurs

### What Static Analysis Shows

Every individual path has been verified correct:

- **Fragment creation**: N fragments, same seq, different frag_idx, is_fragmented=1
- **Seq counter**: incremented once (not per fragment) — correct
- **ACK creation (server)**: per-fragment, copies seq + is_fragmented + frag_idx
- **ACK dedup**: 4-field match prevents merging different frag_idx ACKs
- **ACK serialization**: includes frag_idx when is_fragmented=1
- **ACK parsing (client)**: correctly reads is_fragmented + frag_idx from wire
- **ACK dispatch**: goes to unreliable queue, NOT through reassembly
- **ACK handler**: 4-field match correctly identifies per-fragment entries

The per-fragment ACK logic appears logically sound when traced through the decompiled code. Yet the bug manifests consistently.

### Remaining Hypotheses (Runtime-Level)

The following scenarios cannot be ruled out through static analysis alone and require runtime verification:

1. **ACK batching/loss**: The server creates 3 ACK entries, but they may be coalesced or only partially sent in the next outgoing packet. If only 1 of 3 ACKs reaches the client, only 1 fragment entry is cleared. The remaining 2 trigger retransmission of all 3 (since the retransmit loop sends ALL entries in the retransmit queue, not just expired ones).

2. **Retransmit re-queuing**: When a fragment is retransmitted from `peer+0x80`, it may be re-serialized and re-added to the queue (creating duplicates). If the ACK clears one entry but duplicates exist, retransmission continues.

3. **ACK wire format mismatch**: If the server sends a **non-fragmented** ACK (flags byte bit 0 = 0) despite the original message being fragmented, the ACK handler's mixed-status check would reject the match. The client's retransmit queue entries have `is_fragmented=1`, and a non-fragmented ACK would fail at step 3 of the matching logic.

4. **Queue iterator corruption**: The retransmit loop in `SendOutgoingPackets` uses a cursor (`peer+0x8C`/`+0x90`) while iterating. If the ACK handler modifies the queue concurrently (e.g., from a different execution context), the cursor could become invalid.

5. **`+0x3D` field gating**: The `field_3D` byte (initialized to 1 for TGMessage, 0 for TGHeaderMessage) may gate some behavior not captured in the static analysis.

### Most Likely Root Cause

Hypothesis **#3** (ACK wire format mismatch) is the most likely candidate. If the server's outgoing ACK packet has `flags=0x00` (non-fragmented) instead of `flags=0x01` (fragmented), the client sees a non-fragmented ACK for a fragmented retransmit entry and rejects the match. This would explain:

- Why non-fragmented messages are ACKed correctly (both sides agree on non-fragmented status)
- Why the bug affects BOTH stock dedi and our reimplementation (same ACK generation code)
- Why the user observes "ACK counter=2" as a single ACK (possibly the non-fragmented 4-byte format)

To verify, capture the raw ACK packet bytes and check the flags byte at offset 3. If it's `0x00` instead of `0x01`, the bug is in ACK serialization or in how the `is_fragmented` field is populated on the ACK message object.

---

## Function Reference

| Address | Name | Role |
|---------|------|------|
| 0x006b5080 | SendHelper | Fragments, assigns seq, queues to first-send |
| 0x006b55b0 | SendOutgoingPackets | 3-queue send loop (ACK, retransmit, first-send) |
| 0x006b5c90 | ProcessIncomingMessages | Receive loop, ACK creation, dispatch queueing |
| 0x006b5f70 | DispatchReceivedMessages | Type switch: 0→data, 1→ACK, 3→connack, 4→boot, 5→disconnect |
| 0x006b61e0 | HandleReliableReceived | Creates per-fragment ACK entries in peer+0x9C |
| 0x006b64d0 | HandleACK | Searches peer+0x80, removes one matching entry |
| 0x006b6ad0 | QueueForDispatch | Routes to dispatch queues, calls reassembly for fragments |
| 0x006b6cc0 | ReassembleFragment | Collects fragments by seq, reassembles when complete |
| 0x006b78d0 | RemoveFromQueue | Removes node at index from linked list |
| 0x006b8340 | TGMessage::WriteToBuffer | Type 0x32 serializer (13-bit length, fragment support) |
| 0x006b83f0 | TGMessage::ReadFromBuffer | Type 0x32 factory/deserializer |
| 0x006b8550 | TGMessage::CopyConstructor | Copies all fields including fragment metadata |
| 0x006b8610 | TGMessage::Clone | Allocates new TGMessage via copy constructor |
| 0x006b8670 | SetRetransmitCount | Updates retransmit count and interval |
| 0x006b8700 | CheckRetransmitTimer | Returns true if retransmit interval expired |
| 0x006b8720 | FragmentMessage | Splits large message into N fragments |
| 0x006bd120 | TGHeaderMessage::Constructor | Sets vtable to 0x008959ac |
| 0x006bd190 | TGHeaderMessage::WriteToBuffer | ACK serializer (type + seq + flags + [frag_idx]) |
| 0x006bd1f0 | TGHeaderMessage::ReadFromBuffer | ACK factory/deserializer |
