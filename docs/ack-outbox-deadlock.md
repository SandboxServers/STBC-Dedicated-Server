# ACK-Outbox Deadlock — Long-Session Degradation Root Cause

Reverse-engineered from stbc.exe via Ghidra decompilation and runtime instrumentation (OBSERVE_ONLY proxy build, 2026-02-19).

**Related docs**:
- [fragmented-ack-bug.md](fragmented-ack-bug.md) — ACK-outbox accumulation evidence, fragment ACK matching failure
- [disconnect-flow.md](disconnect-flow.md) — Disconnect packet carries stale ACKs

## Summary

The ACK-outbox (`peer+0x9C`) has a cleanup mechanism that removes entries after 9 retransmissions — but a logic deadlock prevents the cleanup pass from executing during normal gameplay. Entries with retransmit count 3-8 become permanently stuck: never sent again, never cleaned up, never freed. This causes progressive memory leaks, game data starvation, and O(N) dedup search degradation that compounds over long sessions.

---

## 1. Packet Buffer Allocation

**Function**: FUN_006b55b0 (SendOutgoingPackets)

The outgoing packet buffer is **heap-allocated** at the top of each call:

```c
buffer = NiAlloc(this[0x2B]);  // this = TGNetwork
```

Buffer size comes from `TGNetwork+0xAC`:
- Base class constructor (FUN_006b3a00) sets `this[0x2B] = 0x400` (1024 bytes)
- **TGWinsockNetwork constructor (FUN_006b9bf0) overrides to `this[0x2B] = 0x200` (512 bytes)**

**Actual buffer size: 512 bytes.** First 2 bytes reserved for header (`[peer_id][msg_count]`), leaving **510 usable bytes** for transport messages.

---

## 2. Two-Pass ACK Processing

SendOutgoingPackets processes the ACK-outbox in **two separate passes** per peer, with different retransmit count filters.

### Pass 1: Fresh ACKs (retx < 3)

```
Location: 0x006b5690 - 0x006b5740

for each entry in peer+0x9C (ACK-outbox):
    if CheckRetransmitTimer(entry) AND entry.retx_count < 3:
        bytes = entry.WriteToBuffer(write_ptr, remaining)
        if bytes == 0: break          // buffer full
        entry.last_send_time = now
        msg_count++
        entry.retx_count++
        write_ptr += bytes
        remaining -= bytes
        if msg_count >= 255: break    // u8 cap
```

Key details:
- **Filter**: `entry+0x18 < 3` (retx count at TGMessage offset +0x18)
- **No removal**: entries stay in the queue after serialization
- **Cursor-based iteration** via `peer+0xA8` / `peer+0xAC` (not destructive dequeue)
- Entries with retx >= 3 are **silently skipped**

### Retransmit Queue + First-Send Queue (between passes)

After Pass 1, the retransmit queue (`peer+0x80`) and first-send queue (`peer+0x64`) are processed normally. Both have the same `msg_count >= 255` and buffer-remaining guards.

### Pass 2: Stale ACKs (retx >= 3) — With Cleanup

```
Location: 0x006b5a50 - 0x006b5b90

GATE: (msg_count > 0) OR (peer+0xBC != 0)    // ← THE DEADLOCK

if gate passes:
    for each entry in peer+0x9C (ACK-outbox):
        if CheckRetransmitTimer(entry) AND entry.retx_count >= 3:
            bytes = entry.WriteToBuffer(write_ptr, remaining)
            if bytes == 0: break
            entry.last_send_time = now
            msg_count++
            entry.retx_count++

            if entry.retx_count > 8:              // retx >= 9
                RemoveFromQueue(&peer+0x9C, idx)   // FUN_006b78d0
                removed.Destroy(1)                 // free TGHeaderMessage

            write_ptr += bytes
            remaining -= bytes
            if msg_count >= 255: break
```

Key details:
- **Gate condition**: `msg_count > 0 || peer.is_disconnecting` — Pass 2 only runs if Pass 1 or the retransmit/first-send queues wrote at least one message, OR the peer is disconnecting
- **Filter**: `entry+0x18 >= 3` (opposite of Pass 1)
- **Cleanup at retx >= 9**: entry removed from queue and freed via `FUN_006b78d0` (RemoveFromQueue) + destructor

---

## 3. The Deadlock

The two passes create a deadlock condition for entries in the retx 3-8 range:

```
State: All ACK-outbox entries have retx >= 3
       No new reliable messages to send (retransmit queue empty, first-send empty)

Pass 1: Iterates ackOutQ → skips all entries (retx >= 3 filter)
         → msg_count stays 0

Retransmit queue: Empty → msg_count stays 0
First-send queue: Empty → msg_count stays 0

Pass 2 gate: msg_count == 0 AND peer.is_disconnecting == 0
           → gate FAILS → Pass 2 DOES NOT EXECUTE

Result: Entries with retx 3-8 are stuck forever:
        - Pass 1 won't touch them (retx too high)
        - Pass 2 won't run (msg_count gate fails)
        - No other code path removes them
```

The only exits from deadlock:
1. **New game traffic** generates a retransmit or first-send message → msg_count > 0 → Pass 2 gate opens → stuck entries get incremented toward retx 9 → eventually cleaned up
2. **Peer disconnects** → `peer+0xBC = 1` → Pass 2 gate opens via disconnecting flag
3. **Never** — in a lull between active exchanges, entries remain stuck indefinitely

In practice, active gameplay generates enough traffic that msg_count > 0 most ticks, so entries eventually reach retx 9 and get cleaned. But during quiet periods (lobby, post-combat lulls), the deadlock kicks in and entries accumulate.

---

## 4. Buffer Overflow Analysis

**Result: No buffer overflow vulnerability.**

| Protection | Mechanism |
|-----------|-----------|
| Write bounds | WriteToBuffer checks `remaining < required_size`, returns 0 if insufficient |
| Loop termination | All 4 loops break on WriteToBuffer returning 0 |
| msg_count cap | All 4 loops break at `msg_count >= 255` (`0xFE < iStack_28`) |
| msg_count write | `buffer[1] = (char)msg_count` — but never exceeds 255 due to caps |

Maximum ACK entries before buffer exhaustion:
- Non-fragmented ACKs (4 bytes): 510 / 4 = **127 entries**
- Fragmented ACKs (5 bytes): 510 / 5 = **102 entries**
- The 255 msg_count cap would require 1020+ bytes — buffer fills first

The engine safely stops serializing when the buffer is full. No overflow is possible.

---

## 5. Three Degradation Effects

### 5.1 Memory Leak

Each stuck ACK entry consumes:
- 0x44 bytes (68 bytes) — TGHeaderMessage object (vtable 0x008959ac)
- 8 bytes — queue node (`[msg_ptr:4][next_ptr:4]`)
- **Total: 76 bytes per entry**

Growth rate depends on session activity:
- Each incoming reliable message creates an ACK entry (if not deduped)
- Dedup only matches if an entry with the SAME {seq, is_fragmented, frag_idx, is_below_0x32} exists
- New sequence numbers always create new entries

Estimated accumulation:
- Checksum phase: ~10 entries
- Per minute of active gameplay: ~20-50 entries (depends on PythonEvent/weapon/collision traffic)
- 1-hour session: ~1,200-3,000 stuck entries → **91-228 KB leaked**
- 4-hour session: ~5,000-12,000 entries → **370 KB - 1 MB leaked**

Not catastrophic for modern systems, but BC's 32-bit address space and 2002-era memory assumptions make this non-trivial.

### 5.2 Game Data Starvation

While entries have retx < 3 (first 3 sends), they consume buffer space:
- 38 stale ACKs × 4 bytes = **152 bytes** of the 510-byte budget
- Leaves only **358 bytes** for actual game data (StateUpdates, weapon fire, collisions)
- In burst scenarios (ship explodes, many subsystems damaged), critical game messages may be deferred to the next tick

This is transient — after 3 sends the entries stop consuming buffer space (Pass 1 skips them). But new entries are constantly being created, so some buffer waste is continuous.

### 5.3 Dedup Search Degradation (Most Dangerous)

**Function**: FUN_006b61e0 (HandleReliableReceived)

Called for EVERY incoming reliable message. Walks the ENTIRE ACK-outbox linearly to check for duplicates:

```c
// At 0x006b6240
node = peer+0x9C.head;
while (node != NULL) {
    existing = node->value;
    if (existing.seq == incoming.seq
        && existing.is_below_0x32 == (incoming.type < 0x32)
        && existing.is_fragmented == incoming.is_fragmented
        && existing.frag_idx == incoming.frag_idx) {
        // Match found — refresh timer, don't create new entry
        break;
    }
    node = node->next;
}
```

This is **O(N)** where N = total ACK-outbox entries (including stuck ones). As N grows:

| Session Duration | Est. Entries | Dedup Cost per Reliable Msg |
|------------------|--------------|-----------------------------|
| 2 minutes | ~13 | ~13 comparisons (negligible) |
| 30 minutes | ~600 | ~600 comparisons |
| 2 hours | ~2,400 | ~2,400 comparisons |
| 4 hours | ~6,000 | ~6,000 comparisons |

At 60 reliable messages/second (typical combat): **2,400 entries × 60 msgs/sec = 144,000 4-field comparisons per second**. Each comparison involves 4 memory reads + 4 conditional branches. On 2002-era CPUs (~1 GHz), this becomes non-trivial.

The dedup scan runs inside `ProcessIncomingMessages` which runs inside the network tick. If the network tick takes too long, the game loop falls behind, packets queue up, peers appear to time out, and the session degrades or crashes.

---

## 6. Key Functions

| Address | Name | Role |
|---------|------|------|
| 0x006b55b0 | SendOutgoingPackets | 2-pass ACK + retransmit + first-send serialization |
| 0x006b61e0 | HandleReliableReceived | ACK creation + O(N) dedup scan |
| 0x006b64d0 | HandleACK | Searches retransmit queue, removes matching entry |
| 0x006b78d0 | RemoveFromQueue | Removes node at index from linked list |
| 0x006b8700 | CheckRetransmitTimer | Returns true if retransmit interval expired |
| 0x006b8670 | SetRetransmitCount | Updates retx count and interval |
| 0x006b9bf0 | TGWinsockNetwork::ctor | Sets buffer size to 0x200 (512 bytes) |
| 0x006bd120 | TGHeaderMessage::ctor | ACK message constructor (0x44 bytes) |
| 0x006bd190 | TGHeaderMessage::WriteToBuffer | ACK serializer with remaining-space check |

## 7. Key Offsets

| Offset | Object | Field |
|--------|--------|-------|
| peer+0x9C | head | ACK-outbox linked list head |
| peer+0xA0 | tail | ACK-outbox linked list tail |
| peer+0xA8 | cursor | Iteration cursor (node pointer) |
| peer+0xAC | index | Iteration cursor (index counter) |
| peer+0xB4 | count | ACK-outbox entry count |
| peer+0xBC | u8 | is_disconnecting flag |
| msg+0x18 | u32 | retransmit_count |
| msg+0x1C | float | retransmit_interval |
| msg+0x20 | float | last_send_time |
| TGNetwork+0xAC | u32 | Max packet buffer size (0x200 for WSN) |
