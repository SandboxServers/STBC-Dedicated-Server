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

## Ghidra-Verified Analysis (2026-02-19)

All five priority functions have been decompiled and verified via Ghidra MCP and raw objdump disassembly. The previous analysis (without Ghidra) was largely correct but incomplete. This section supersedes the earlier hypotheses.

### ACK Factory / Deserializer — 0x006bd1f0 (VERIFIED)

This function was NOT in Ghidra's function database (undefined code between 0x006bd1e9 and 0x006bd250). Raw disassembly via objdump reveals a clean factory function:

```asm
; Allocate TGHeaderMessage (0x44 bytes)
push   0x0
push   0x8d858c
push   0x44
mov    ecx, 0x99c478
call   NiAlloc              ; 0x717b70
mov    ecx, eax
call   PlacementNew         ; 0x718010
test   eax, eax
je     null_path
mov    ecx, eax
call   TGHeaderMessage_ctor ; 0x6bd120
jmp    proceed
null_path:
xor    eax, eax
proceed:
push   esi
mov    esi, [esp+0x8]       ; esi = wire buffer ptr
inc    esi                   ; skip byte[0] (type byte, already consumed)
mov    cx, [esi]             ; cx = byte[1..2] = seq (LE u16)
add    esi, 0x2              ; esi -> byte[3] (flags)
mov    [eax+0x14], cx        ; msg.seq = wire seq                    CORRECT
mov    cl, [esi]             ; cl = byte[3] = flags
mov    dl, cl                ; dl = flags
shr    cl, 1                 ; cl = (flags >> 1) & 1 = bit 1
and    dl, 0x1               ; dl = flags & 1 = bit 0
and    cl, 0x1
test   dl, dl
mov    [eax+0x3c], dl        ; msg.is_fragmented = bit 0             CORRECT
mov    [eax+0x40], cl        ; msg.is_below_0x32 = bit 1             CORRECT
je     done                  ; if NOT fragmented, skip frag_idx
mov    dl, [esi+0x1]         ; dl = byte[4] = frag_idx
mov    [eax+0x39], dl        ; msg.frag_idx = wire frag_idx          CORRECT
done:
pop    esi
ret
```

**Verdict**: The ACK factory correctly deserializes ALL fields from wire data. `seq`, `is_fragmented`, `is_below_0x32`, and `frag_idx` are all populated correctly. The factory is **perfectly symmetric** with WriteToBuffer at 0x006bd190. **Hypothesis #3 (ACK wire format mismatch) is ELIMINATED** as a code-level bug — the serialization and deserialization are provably correct.

### ACK Serializer — 0x006bd190 (VERIFIED)

TGHeaderMessage::WriteToBuffer, confirmed via both Ghidra decompile and raw disassembly:

```
Wire layout:
  byte[0] = GetType()         = 0x01 (from vtable call at 0x006bdc20)
  byte[1..2] = msg+0x14       = seq (LE u16)
  byte[3] = flags:
      bit 0 = (msg+0x3C != 0) = is_fragmented
      bit 1 = (msg+0x40 != 0) = is_below_0x32
  [if is_fragmented]:
  byte[4] = msg+0x39          = frag_idx
Returns: 4 (non-fragmented) or 5 (fragmented) bytes written
```

Perfectly symmetric with the factory. No issues.

### ACK Creator — 0x006b61e0 (VERIFIED)

HandleReliableReceived. Called from ProcessIncomingMessages at 0x006b5f30 when `msg+0x3A` (is_reliable) is non-zero. Confirmed via raw disassembly:

```asm
; Extract fields from incoming message (ESI)
mov    cl, [esi+0x3c]        ; cl = incoming.is_fragmented
cmp    eax, 0x32             ; compare GetType() result
setl   dl                    ; dl = (type < 0x32) = is_below_0x32
mov    bl, [esi+0x39]        ; bl = incoming.frag_idx
mov    bp, [esi+0x14]        ; bp = incoming.seq

; ... dedup search on peer+0x9C ACK outbox (4-field match) ...

; If no existing ACK matches, create new TGHeaderMessage:
call   TGHeaderMessage_ctor  ; 0x6bd120
mov    [edi+0x14], bp        ; ACK.seq = incoming.seq
mov    [edi+0x40], dl        ; ACK.is_below_0x32 = (type < 0x32)
mov    [edi+0x3c], al        ; ACK.is_fragmented = incoming.is_fragmented
mov    [edi+0x39], bl        ; ACK.frag_idx = incoming.frag_idx
```

**Verdict**: ACK creation correctly copies all 4 matching fields from the incoming message. For a 3-fragment message, 3 separate ACK entries are created with distinct `frag_idx` values (0, 1, 2). The dedup search correctly distinguishes them.

### HandleACK — 0x006b64d0 (VERIFIED)

Called from DispatchReceivedMessages (type 1 dispatch). Signature: `__stdcall(ack_msg, peer)`. Searches `peer+0x80` retransmit queue:

```c
// Initialize: piVar4 = &peer+0x80 (queue head), index = 0
// Get first node, extract message pointer (puVar8)

for each entry puVar8 in retransmit queue:
    // CHECK 1: is_below_0x32
    cVar1 = *(char*)(ack_msg + 0x40);            // ACK.is_below_0x32
    iVar3 = (**(code**)*puVar8)();                // retransmit_entry.GetType()
    if ((bool)cVar1 != (iVar3 < 0x32))           // compare
        goto next;                                 // MISMATCH -> skip

    // CHECK 2: sequence number
    if (*(short*)(puVar8 + 0x14) != *(short*)(ack_msg + 0x14))
        goto next;                                 // MISMATCH -> skip

    // CHECK 3: fragment status
    if (retransmit_entry.is_fragmented) {          // puVar8+0x3C != 0
        if (!ack.is_fragmented) {                  // ack_msg+0x3C == 0
            goto next;                             // mixed status -> skip
        }
        if (retransmit_entry.frag_idx == ack.frag_idx) {  // +0x39 match
            // FRAGMENTED MATCH: remove from queue, destroy, RETURN
            RemoveFromQueue(&peer+0x80, current_index);
            destroy(removed_entry);
            return;
        }
        goto next;                                 // different frag_idx -> skip
    }
    // Entry is NOT fragmented
    if (ack.is_fragmented)
        goto next;                                 // mixed status -> skip
    // NON-FRAGMENTED MATCH: remove from queue, destroy, RETURN
    ...
```

**Verdict**: The matching logic is correct for all 4 cases (both-frag-match, both-nonfrag-match, mixed-status-reject, frag-idx-mismatch). Returns after removing ONE entry.

**Key detail verified**: CHECK 1 compares ACK's `+0x40` (is_below_0x32 byte) against `GetType() < 0x32` evaluated on the retransmit entry. Since both game messages (TGMessage, GetType()=0x32) and their ACKs have `is_below_0x32 = 0`, this check passes. Since ACK messages themselves (TGHeaderMessage, GetType()=0x01) are never in the retransmit queue, there is no type confusion.

### ProcessIncomingMessages — 0x006b5c90 (VERIFIED)

The receive loop. For each transport message in a UDP packet:

```
1. Read type byte from wire
2. Look up factory in table at DAT_009962d4 (256-entry, indexed by type byte)
3. Call factory to create message object
4. Set msg+0x0C = sender player ID, msg+0x10 = metadata, msg+0x28 = own player ID
5. Advance wire pointer by vtable[5] (GetHeaderSize) bytes
6. Look up or create peer object
7. If msg+0x3A (is_reliable) != 0:
       call HandleReliableReceived (0x006b61e0) -> creates ACK
8. Call QueueForDispatch (0x006b6ad0)
```

**For ACK messages (type 0x01)**: Factory at DAT_009962d8 = 0x006bd1f0. Constructor sets `msg+0x3A = 0` (unreliable). Therefore step 7 is SKIPPED (no ACK-of-ACK). The ACK goes directly to QueueForDispatch. **Correct behavior.**

### QueueForDispatch — 0x006b6ad0 (VERIFIED)

Routes messages to dispatch queues based on type and reliability:

```c
if (msg+0x3A == 0) {  // unreliable
    type = msg->GetType();
    if (type < 0x32)
        queue = this+0x70;     // unreliable queue for types < 0x32
    else
        queue = this+0x38;     // unreliable queue for types >= 0x32
} else {               // reliable
    type = msg->GetType();
    if (type < 0x32) {
        queue = this+0x8C;     // reliable queue, seq check against peer+0x24
    } else {
        queue = this+0x54;     // reliable queue, seq check against peer+0x28
    }
    // Sequence number windowing check (drops old/future messages)
    // Fragment reassembly call if msg+0x3C != 0
}
```

**For ACK messages**: Type 0x01 < 0x32, unreliable -> queue = `this+0x70`. No sequence check. No fragment reassembly. **Correct routing.**

### DispatchReceivedMessages — 0x006b5f70 (VERIFIED)

Processes unreliable queue first, then reliable queue:

**Unreliable queue (this+0x70):**
```
1. Dequeue message
2. Look up peer by msg+0x0C (sender ID) via binary search (FUN_00401830)
3. If peer not found: REMOVE message from queue, DESTROY it, continue
4. Jump to common dispatch at LAB_006b60b6
```

**Common dispatch (LAB_006b60b6):**
```
5. If msg is reliable: increment peer's expected seq counter
6. GetType() -> switch dispatch:
     case 0: HandleDataMessage (0x006b63a0)
     case 1: HandleACK (0x006b64d0)  <-- ACKs go here
     case 3: HandleConnectAck
     case 4: HandleBoot
     case 5: HandleDisconnect
7. After dispatch: remove message from queue, loop
```

**Critical path verified**: ACK (type 1) goes through unreliable dispatch, peer is found by binary search, then dispatched to HandleACK with correct (ack_msg, peer) parameters.

**One potential issue found in reliable queue section** (NOT affecting ACKs): At 0x006b60ab, if a reliable message has `msg+0x3C` (is_fragmented) set AND its seq matches the expected seq, the function RETURNS without dispatching. This is the fragment-hold-back mechanism -- fragmented reliable messages are held until reassembly completes. This does NOT affect ACKs since they go through the unreliable path.

### GetType() Return Values (VERIFIED)

```
TGMessage::GetType()       at 0x006b9430:  mov eax, 0x32; ret  (= 50 decimal)
TGHeaderMessage::GetType() at 0x006bdc20:  mov eax, 0x01; ret  (= 1 = ACK type)
```

### Complete Static Verification Summary

Every code path has been verified correct:

| Component | Function | Address | Status |
|-----------|----------|---------|--------|
| ACK creation (server) | HandleReliableReceived | 0x006b61e0 | CORRECT: copies all 4 fields |
| ACK serialization | TGHeaderMessage::WriteToBuffer | 0x006bd190 | CORRECT: symmetric encoding |
| ACK deserialization | TGHeaderMessage::ReadFromBuffer | 0x006bd1f0 | CORRECT: symmetric decoding |
| ACK routing | QueueForDispatch | 0x006b6ad0 | CORRECT: unreliable, no seq check |
| ACK dispatch | DispatchReceivedMessages | 0x006b5f70 | CORRECT: type 1 -> HandleACK |
| ACK matching | HandleACK | 0x006b64d0 | CORRECT: 4-field match logic |
| Peer lookup | FUN_00401830 | 0x00401830 | CORRECT: binary search by player ID |
| Fragment creation | FragmentMessage | 0x006b8720 | CORRECT: same seq, different frag_idx |
| Fragment retransmit | SendOutgoingPackets | 0x006b55b0 | CORRECT: preserves fragment fields |

**ALL static code paths are verified correct. The logic should work.**

---

## Root Cause Analysis

### Eliminated Hypotheses

The following hypotheses from the previous analysis are now eliminated by Ghidra verification:

- **~~Hypothesis #3 (ACK wire format mismatch)~~**: WriteToBuffer and ReadFromBuffer are provably symmetric. The flags byte correctly encodes/decodes is_fragmented and is_below_0x32. ACK creation correctly copies is_fragmented from the incoming message. **ELIMINATED.**

- **~~Hypothesis #4 (Queue iterator corruption)~~**: The game is single-threaded. HandleACK and SendOutgoingPackets cannot execute concurrently. **ELIMINATED.**

- **~~Hypothesis #5 (+0x3D field gating)~~**: The `+0x3D` field is never read by HandleACK, QueueForDispatch, or DispatchReceivedMessages. It only affects `+0x3D` checks in SendOutgoingPackets' first-send loop (controls whether a message can be serialized before the first in the queue). **ELIMINATED.**

### Surviving Hypotheses (Require Runtime Verification)

**Hypothesis #1 (ACK delivery failure)**: The ACK-outbox queue (`peer+0x9C`) is processed with a **retransmit count limit of 3** and a timer check (FUN_006b8700). A freshly-created ACK has retransmit count 0 and last_send_time = creation_time. If the timer interval is too long, the ACK might not be sent in the same tick as it's created. If it IS sent but the UDP packet is lost, the ACK retransmits up to 3 times. However, this cannot explain persistent failure -- the server creates NEW ACKs for each retransmitted fragment set, so even if old ACKs expire, new ones should succeed.

**Hypothesis #2 (Retransmit re-queuing)**: When a reliable message is retransmitted from `peer+0x80`, the code at 0x006b57e7 calls WriteToBuffer to serialize it, then at 0x006b5930+ moves it BACK to the retransmit queue (`peer+0x80`) with updated timestamps. It does NOT create duplicates -- it reuses the same message object. **ELIMINATED as "duplicate entries" but CONFIRMED as "stays in queue".**

**NEW Hypothesis #6 (Packet-level multiplexing)**: The SendOutgoingPackets function serializes messages from ALL THREE queues into a SINGLE outgoing buffer per peer. The buffer starts at `puVar8 + 2` (2 bytes reserved for [sender_id, message_count]). Messages are written sequentially. The maximum is 255 messages per packet. If the ACK-outbox has ACKs AND the retransmit queue has fragments due for retransmission, they are ALL serialized into the SAME packet. The server sends ONE UDP packet containing both the ACKs AND the re-requested fragments. The client processes this packet in ProcessIncomingMessages, which iterates all transport messages in sequence. When it encounters the ACKs, they go to the unreliable dispatch queue. When it encounters the re-requested data messages, they go through HandleReliableReceived (creating yet more ACKs). But dispatch happens LATER (in DispatchReceivedMessages), not inline. So ACKs are processed correctly -- they're queued and dispatched after all messages in the packet are parsed.

**However**, there is a subtle ordering issue: DispatchReceivedMessages processes the unreliable queue FIRST (ACKs), THEN the reliable queue (data messages). An ACK received in the same packet as a retransmitted fragment would be processed first, clearing one entry from the retransmit queue. But the data message would then be processed and create a NEW ACK. This should be fine -- it doesn't re-add anything to the retransmit queue.

**NEW Hypothesis #7 (THE MOST LIKELY ROOT CAUSE -- is_below_0x32 MISMATCH)**:

When the CLIENT creates the original outgoing fragmented message (via SendHelper at 0x006b5080), SendHelper calls `FragmentMessage` (vtable[7]) which creates fragment clones via the COPY CONSTRUCTOR. The fragments are TGMessage objects (vtable 0x008958d0, GetType() = 0x32). They go into the retransmit queue with `is_fragmented=1`.

When the SERVER receives these fragments, ProcessIncomingMessages calls the TGMessage FACTORY at 0x006b83f0 (registered for type 0x32 in the factory table). This factory creates a NEW TGMessage object. The factory correctly reads `is_fragmented`, `frag_idx`, and `is_reliable` from the wire. Then HandleReliableReceived (0x006b61e0) creates an ACK with:

```
ACK.is_below_0x32 = (incoming.GetType() < 0x32) = (0x32 < 0x32) = FALSE = 0
```

On the CLIENT side, HandleACK checks:

```
ACK.is_below_0x32 (0) == (retransmit_entry.GetType() < 0x32)
```

The retransmit entries are TGMessage objects, so `GetType() = 0x32`, and `0x32 < 0x32 = FALSE = 0`. The comparison is `0 == 0 = TRUE`. **This matches.**

So Hypothesis #7 is actually fine for TGMessage. But what if the FRAGMENTED message is NOT a TGMessage? What if it's a SUBCLASS with a different GetType()? Let me check: are there any subclasses of TGMessage that override GetType() with a value >= 0x32 and could produce fragmented messages?

**The answer is: TGMessage IS the only type that gets fragmented.** FragmentMessage (0x006b8720) creates clones of type TGMessage. The clone vtable[6] creates copies via the TGMessage copy constructor. So fragments are always TGMessage objects with GetType() = 0x32.

**Revised: Hypothesis #7 is also ELIMINATED.**

### FINAL Assessment: Two Distinct Bugs

After exhaustive static analysis with Ghidra MCP access AND runtime instrumentation (2026-02-19):

1. **Every function in the ACK creation, serialization, deserialization, routing, and matching pipeline is provably correct** at the code level.
2. **The fragment fields (is_fragmented, frag_idx, seq, is_below_0x32) are correctly preserved through the entire lifecycle.**
3. **The matching logic in HandleACK correctly handles all 4 fragment/non-fragment combinations.**

However, runtime instrumentation reveals **two distinct bugs**:

**Bug 1: Fragment ACK matching failure** (original bug). Fragment ACKs arrive at the client but the retransmit queue is already empty (`retxQ=0`), so HandleACK has nothing to match against. The fragments were already cleared by an earlier mechanism (possibly the whole-message ACK or fragment reassembly path), but the server's per-fragment ACKs arrive after that and find nothing to remove. The client's retransmit queue is clean, but the server doesn't know that, so each retransmitted fragment batch triggers new ACK creation.

**Bug 2: ACK-outbox never drains** (newly discovered). ACK entries in the ACK-outbox (`peer+0x9C`) are NEVER removed after being sent. They accumulate indefinitely, growing from 2 entries (pre-connect) to 10-13 entries (post-checksum) to 38+ entries (mid-game). Every outbound packet carries the full set of stale ACKs as overhead. See "Runtime Evidence" section below for details.

---

## Runtime Evidence: ACK-Outbox Accumulation (2026-02-19)

### Instrumentation Setup

Runtime hooks deployed via OBSERVE_ONLY proxy build (zero patches, passive logging only):

- **HandleACK hook** at 0x006B64D0: Logs every ACK dispatch call with the ACK fields and the full retransmit queue state
- **ACK-DIAG**: Periodic dump of per-peer `retxQ` and `ackOutQ` counts with per-entry detail

Both hooks installed on **both** the stock dedicated server and the stock client simultaneously. All behavior described below is 100% stock game code.

### Server-Side Observations (stock-dedi)

**Pre-connect phase** (server↔self, peerID=1):
```
[11:37:29.975] peer=1 retxQ=0 ackOutQ=2
  ack[0] seq=0x0000 frag=0 below32=1 retx=1
  ack[1] seq=0x0000 frag=0 below32=0 retx=1
```
Two ACK entries created for the server's own connection management. retxQ=0 — both original messages already cleared.

**Client connects** (peerID=2 appears at 11:37:53):
```
[11:37:53.596] peer=2 retxQ=1 ackOutQ=4
  retx[0] seq=0x0002 frag=0 rel=1 retx=0 intv=1.00
  ack[0] seq=0x0000 below32=1 retx=1
  ack[1] seq=0x0001 below32=1 retx=1
  ack[2] seq=0x0000 below32=0 retx=1
  ack[3] seq=0x0001 below32=0 retx=1
```
4 ACK entries for the 2 connect/ack exchanges (each generates a below32=1 and below32=0 ACK).

**After checksum + settings exchange** (11:37:56):
```
[11:37:56.315] peer=2 retxQ=0 ackOutQ=10
  ack[0] seq=0x0000 frag=0 below32=1 retx=4      ← stale (from connect)
  ack[1] seq=0x0001 frag=0 below32=1 retx=4      ← stale (from connect)
  ack[2] seq=0x0000 frag=0 below32=0 retx=4      ← stale
  ack[3] seq=0x0001 frag=0 below32=0 retx=4      ← stale
  ack[4] seq=0x0002 frag=1 idx=0 below32=0 retx=3  ← fragment ACK (never cleared)
  ack[5] seq=0x0002 frag=1 idx=1 below32=0 retx=3  ← fragment ACK
  ack[6] seq=0x0002 frag=1 idx=2 below32=0 retx=3  ← fragment ACK
  ack[7] seq=0x0003 frag=0 below32=0 retx=3      ← stale
  ack[8] seq=0x0004 frag=0 below32=0 retx=3      ← stale
  ack[9] seq=0x0005 frag=0 below32=0 retx=2      ← stale
```
**retxQ=0** — every original reliable message has been successfully acknowledged. But **ackOutQ=10** — all 10 ACK entries are still in the outbox, being retransmitted in every outbound packet. The 3 fragment ACKs (ack[4-6]) for seq=0x0002 are visible — these are the per-fragment ACKs for the client's 3-fragment settings message.

**5 seconds later** (11:37:59):
```
[11:37:59.035] peer=2 retxQ=0 ackOutQ=11
  ack[0] seq=0x0000 below32=1 retx=8     ← retx count doubled
  ...
  ack[4] seq=0x0002 frag=1 idx=0 retx=7  ← fragment ACKs still there
  ack[5] seq=0x0002 frag=1 idx=1 retx=7
  ack[6] seq=0x0002 frag=1 idx=2 retx=7
  ...
```
retx counts have grown from 3-4 to 7-8. One new entry added (seq=0x0006). **None of the previous 10 entries were removed.**

### Client-Side Observations (matching behavior)

```
[11:37:55.503] peer=1 retxQ=0 ackOutQ=12
  ack[0] seq=0x0000 below32=1 retx=3
  ack[1] seq=0x0000 below32=0 retx=3
  ...
  ack[9] seq=0x0007 below32=0 retx=2
  ... 2 more entries

[11:37:58.165] peer=1 retxQ=0 ackOutQ=13
  ack[0] seq=0x0000 below32=1 retx=7    ← same entries, higher retx
  ...
  ... 3 more entries
```

Client shows identical behavior: retxQ=0 (all messages acknowledged), but ackOutQ=12→13 with retx counts climbing from 3 to 7+. The ACK entries are never removed.

### HandleACK Dispatch Pattern

The most revealing evidence: after the initial handshake, HandleACK is called with **retxQ=0** for almost every invocation:

```
[11:37:54.974] HandleACK: ack seq=0x0000 below32=1 | retxQ=0
[11:37:54.974] HandleACK: ack seq=0x0000 below32=0 | retxQ=0
[11:37:54.974] HandleACK: ack seq=0x0001 below32=1 | retxQ=0
[11:37:54.974] HandleACK: ack seq=0x0001 below32=0 | retxQ=0
[11:37:54.974] HandleACK: ack seq=0x0002 below32=0 | retxQ=0
[11:37:54.974] HandleACK: ack seq=0x0003 below32=0 | retxQ=0
[11:37:54.974] HandleACK: ack seq=0x0004 below32=0 | retxQ=0
```

These are **stale ACKs from the remote peer's ackOutQ** being endlessly retransmitted. The local retxQ is already empty (original messages cleared), so HandleACK walks an empty queue and returns without doing anything. But the remote side never stops sending them because the ACK entries are never removed from its outbox.

### Root Cause: Missing Cleanup in SendOutgoingPackets

The `SendOutgoingPackets` function (0x006b55b0) processes the ACK-outbox queue and serializes each ACK into the outgoing packet. After serialization, it increments the retransmit count and updates the timestamp — **but it never checks whether the ACK has been successfully delivered or whether the retransmit count exceeds a limit**.

The dedup logic in `HandleReliableReceived` (0x006b61e0) only prevents creating a *new* ACK entry when a duplicate reliable message arrives — it "refreshes" the existing entry's timer. But once an ACK entry is in the outbox, **there is no code path that removes it**.

The result:
- ACK entries accumulate for the entire session duration
- Each outbound packet carries ALL accumulated ACKs (4-5 bytes each)
- By mid-game: 38+ stale ACK entries = ~190 bytes of overhead per packet
- retx counts grow indefinitely (observed up to retx=8 within 6 seconds of connect)

### Relationship to the Fragment ACK Bug

The "errant checksum packets flowing after checksum completes" that prompted this investigation are actually **stale ACKs for checksum-phase reliable messages**. They are not checksum data packets — they are ACK messages that were created during the checksum exchange and never cleaned up.

The fragment ACK bug (fragments retransmitting despite correct ACKs) and the ackOutQ accumulation bug are **two separate issues**:

1. **Fragment retransmission**: The client's retxQ entries for fragments are cleared correctly (retxQ=0), but something in the timing means the server's per-fragment ACKs arrive "late" — after the client already cleared the entries. The ACKs hit an empty retxQ and become no-ops.

2. **ACK-outbox leak**: ACK entries in the outbox are NEVER removed, regardless of whether they're fragment ACKs or non-fragment ACKs. Every ACK ever created stays in the outbox forever, growing the per-packet overhead monotonically.

### Valentine's Day Battle Trace (2026-02-14)

A 34-minute, 3-player active combat session (136 MB / 2.6M lines) was analyzed for fragment ACK evidence. **Zero fragmented ACK entries were found in client packets** across the entire trace. All observed ACK messages were non-fragmented (4-byte ACKs, flags byte with bit 0 = 0).

This provides additional evidence that the fragment ACK bug (Bug 1) and the ACK-outbox accumulation bug (Bug 2) are **distinct issues**. The fragment retransmission pattern observed in the 91-second Feb 19 trace (where fragmented reliable messages retransmit endlessly) is either session-phase dependent (only occurs during the initial checksum/settings exchange) or was not triggered during the Valentine's Day combat session. In either case, the ACK-outbox accumulation observed in the Valentine's Day trace is entirely from non-fragmented ACK entries.

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
