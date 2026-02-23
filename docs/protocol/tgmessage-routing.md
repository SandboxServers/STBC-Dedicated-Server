> [docs](../README.md) / [protocol](README.md) / tgmessage-routing.md

# TGMessage Routing in Stock Dedicated Server

Reverse engineering analysis of how TGMessages are routed, filtered, and dispatched in
Bridge Commander (stbc.exe). Answers the four key questions about custom message type
compatibility for mods like Kobayashi Maru and BC Remastered.

See also: [tgmessage-routing-cleanroom.md](../networking/tgmessage-routing-cleanroom.md) for a clean-room
behavioral specification (no addresses or decompiled code).

---

## Executive Summary

| Question | Answer |
|----------|--------|
| Does the server whitelist message types? | **No — relay-all.** |
| Does the server examine the type byte on relay? | **No — payload is opaque.** |
| Is there a maximum message type value? | **No — byte range (0-255) is the only limit.** |
| Can clients send directly to other clients? | **No — star topology, all through host.** |

Custom mod message types (Kobayashi Maru 205/211-214, BC Remastered 53-57, team modes 63-65)
work because the transport layer is opaque and the C++ dispatcher silently ignores unknown
opcodes, allowing Python event handlers to process them.

---

## Two Independent Type Systems

A common source of confusion: there are **two separate type bytes** in the message stack.

### Transport Type (outer layer)
- First byte of each sub-message within a UDP packet
- Indexes into a 256-entry factory table at `DAT_009962d4`
- Only 7 of 256 slots populated (types 0x00-0x05 and 0x32)
- Determines how to deserialize the wire bytes into a TGMessage object

### Game Opcode (inner layer)
- First byte of the TGMessage **payload** (inside a type-0x00 or type-0x32 transport message)
- Dispatched by three C++ handlers and by Python event handlers
- This is the byte that `MAX_MESSAGE_TYPES` and mod custom types refer to

All game messages — stock and modded — use the existing transport types (0x00 or 0x32).
No mod registers custom transport types.

---

## Transport Layer

### Factory Table (0x009962d4)

Initialized once by the TGWinsockNetwork constructor at `0x006b3a00`:

| Type | Factory | Class | Purpose |
|------|---------|-------|---------|
| 0x00 | FUN_006bc6a0 | TGDataMessage | Game message carrier (14-bit length, no fragments) |
| 0x01 | FUN_006bd1f0 | TGHeaderMessage | ACK / reliable transport |
| 0x02 | FUN_006bdd10 | TGConnectMessage | Connection request |
| 0x03 | FUN_006be860 | TGConnectAckMessage | Connection acknowledgement |
| 0x04 | FUN_006badb0 | TGBootMessage | Boot / disconnect |
| 0x05 | FUN_006bf410 | TGDisconnectMessage | Graceful disconnect |
| 0x32 | FUN_006b83f0 | TGMessage | General-purpose (13-bit length, fragment support) |

Types 6-49 and 51-255 are NULL. When `FUN_006b5c90` (receive processor) encounters a
NULL factory entry, it silently returns — no crash, no error log.

### Factory Registration

The SWIG wrapper `TGNetwork_RegisterMessageType` at `0x005e4860` writes:
```c
factory_table[(type_byte & 0xFF) * 4] = factory_vtable_ptr;
```
The `& 0xFF` mask is the only "bounds check" — a natural byte wrap, not a validation.
Stock Python scripts **never** call this function. All mod messages use the existing
type-0x00/0x32 transport with custom game opcodes in the payload.

---

## Packet Receive Path

### Wire → Factory → Queue

`FUN_006b5c90` (called from `TGNetwork::Update` at `0x006b4560`):

```
1. Read raw UDP payload (after AlbyRules decryption)
2. byte[0] = sender_peer_id
3. byte[1] = sub_message_count
4. For each sub-message:
   a. Read transport_type = first byte
   b. factory = factory_table[transport_type * 4]
   c. If NULL → return (drop entire remaining packet)
   d. msg = factory(wire_data)         ← deserialize
   e. msg->from_id = sender_peer_id
   f. If msg->is_reliable → ACK tracking (FUN_006b61e0)
   g. FUN_006b6ad0 → queue for dispatch
```

**Key finding**: The receive path never examines the game opcode inside the payload.
It only checks the transport type (for factory lookup) and reliable flag (for ACK handling).

### Type-0x00 Factory (FUN_006bc6a0) — Opaque Copy

```c
TGMessage* factory(byte* data) {
    msg = alloc(0x40);                          // TGMessage object
    uint16_t header = *(uint16_t*)(data + 1);   // flags + length
    uint16_t payload_len = (header & 0x3FFF) - 3;
    // ... extract reliable flag, sequence number ...
    BufferCopy(msg, payload_data, payload_len);  // OPAQUE COPY
    return msg;
}
```

The payload bytes (including the game opcode as byte[0]) are copied verbatim.
The factory does not read, validate, or filter the game opcode.

---

## Host Relay Path — Opaque Forwarding

### Question 1: Whitelist or relay-all? → **Relay-all**

When the host receives a type-0x00 message from a client, `FUN_006b63a0` checks:
```c
if (this->is_host_mode) {          // this+0x10E
    BroadcastToOthers(this, msg);  // FUN_006b51e0
}
```

This is **unconditional**. There is no content inspection, no type filtering, no whitelist.

### FUN_006b51e0 — BroadcastToOthers

```c
int BroadcastToOthers(this, TGMessage* msg) {
    for each peer in peer_array:
        if (peer->net_id != this->local_id && !peer->is_disconnecting):
            clone = msg->Clone()
            QueueForSend(this, clone, peer)
    return result;
}
```

Every message from any client is cloned and sent to all other clients. No payload inspection.

### Question 2: Does the server examine the type byte? → **No**

The type byte lives inside the TGMessage payload. The relay path (`FUN_006b63a0` →
`FUN_006b51e0` → `FUN_006b5080`) never calls `GetData()` on the message. It clones
and queues the entire message as an opaque blob.

---

## SendTGMessage and "NoMe" Group

### FUN_006b4c10 — SendTGMessage

```c
int SendTGMessage(this, int target_id, TGMessage* msg, int flags) {
    if (target_id == 0) {
        // BROADCAST: send to all peers
        for each peer in peer_array:
            if (!peer->is_disconnecting):
                clone = msg->Clone()
                QueueForSend(this, clone, peer)
    } else {
        // UNICAST: binary search peer_array for target_id
        peer = FindPeer(target_id)
        QueueForSend(this, msg, peer)
    }
}
```

No payload inspection. Routing decision is based solely on `target_id`.

### FUN_006b4de0 — SendTGMessageToGroup

```c
int SendTGMessageToGroup(this, char* group_name, TGMessage* msg) {
    group = FindGroupByName(group_name);  // strcmp binary search at this+0xF4
    if (!group) { release(msg); return 0x10; }  // ERR_GROUP_NOT_FOUND
    return SendToGroupMembers(this, group, msg);  // FUN_006b4ec0
}
```

### FUN_006b4ec0 — SendToGroupMembers

Iterates group member list, clones message for each member, queues for send.
**No payload inspection** — purely a routing mechanism.

### "NoMe" Group

"NoMe" = all connected peers EXCEPT the local player (host). Created by multiplayer
Python code. Used by `ProcessMessageHandler` to forward chat and other messages:

```python
# From MultiplayerMenus.py line 2276-2279:
if (App.g_kUtopiaModule.IsHost()):
    pNewMessage = pMessage.Copy()
    pNetwork.SendTGMessageToGroup("NoMe", pNewMessage)
```

The group mechanism is **routing only** — it selects recipients, it does not filter content.

---

## Game Dispatch Path — C++ Dispatchers

### MultiplayerGame Dispatcher (0x0069f2a0)

```c
void MultiplayerGame_ReceiveMessage(this, event) {
    TGMessage* msg = event->message;
    if (msg->GetType() != 0x32) return;    // must be game message transport type

    byte* data = TGMessage_GetData(msg);   // FUN_006b8530: returns msg+4
    byte opcode = *data;

    switch (opcode) {
        case 0x02: Handler_ObjCreate(this, msg, 0); break;
        case 0x03: Handler_ObjCreate(this, msg, 1); break;
        case 0x06: case 0x0D: Handler_PythonEvent(msg); break;
        case 0x07: Handler_EventForward(msg, 0x8000D7); break;
        // ... cases 0x08 through 0x1F, 0x29, 0x2A ...
        case 0x2A: Handler_NewPlayerInGame(this, msg); break;
        // *** NO DEFAULT CASE ***
    }
    DAT_0097fa8b = 0;  // clear "processing" flag
}
```

For opcodes outside the switch (0x2C, 0x35, 0xCD, etc.):
- No case matches
- Execution falls through to `DAT_0097fa8b = 0; return;`
- **Silently ignored by C++**

### MultiplayerWindow Dispatcher (FUN_00504c10)

Handles only opcodes 0x00 (Settings), 0x01 (GameInit), 0x16 (UICollision).
All others silently ignored.

### NetFile Dispatcher (FUN_006a3cd0)

Handles only opcodes 0x20-0x27 (checksum/file transfer).
All others silently ignored.

### Question 3: Maximum message type? → **No explicit limit**

- The C++ switch has no default case and no bounds check
- Unknown opcodes simply fall through silently
- The game opcode is a single byte (0x00-0xFF), so 256 values maximum by byte width
- Within that range, any value not handled by C++ is available for Python

---

## Python Message Dispatch

### Stock Message Type Allocation

`MAX_MESSAGE_TYPES` is a SWIG constant (`Appc.MAX_MESSAGE_TYPES = 0x2B = 43`).
Stock Python defines types relative to this:

| Constant | Value | Decimal | Source |
|----------|-------|---------|--------|
| `MAX_MESSAGE_TYPES + 1` | 0x2C | 44 | CHAT_MESSAGE (MultiplayerMenus.py) |
| `MAX_MESSAGE_TYPES + 2` | 0x2D | 45 | TEAM_CHAT_MESSAGE |
| `MAX_MESSAGE_TYPES + 10` | 0x35 | 53 | MISSION_INIT_MESSAGE (MissionShared.py) |
| `MAX_MESSAGE_TYPES + 11` | 0x36 | 54 | SCORE_CHANGE_MESSAGE |
| `MAX_MESSAGE_TYPES + 12` | 0x37 | 55 | SCORE_MESSAGE |
| `MAX_MESSAGE_TYPES + 13` | 0x38 | 56 | END_GAME_MESSAGE |
| `MAX_MESSAGE_TYPES + 14` | 0x39 | 57 | RESTART_GAME_MESSAGE |
| `MAX_MESSAGE_TYPES + 20` | 0x3F | 63 | SCORE_INIT_MESSAGE (Mission2/3/5) |
| `MAX_MESSAGE_TYPES + 21` | 0x40 | 64 | TEAM_SCORE_MESSAGE (Mission2/3/5) |
| `MAX_MESSAGE_TYPES + 22` | 0x41 | 65 | TEAM_MESSAGE (Mission2/3/5) |

Stock uses types 44-45 and 53-65. The gap (46-52) and range 66-255 are available for mods.

### Python Receive Path

```python
# Mission1.py line 220:
def ProcessMessageHandler(self, pEvent):
    pMessage = pEvent.GetMessage()
    kStream = pMessage.GetBufferStream()
    cType = ord(kStream.ReadChar())     # read game opcode from payload

    if cType == MissionShared.MISSION_INIT_MESSAGE:   # 0x35
        ...
    elif cType == MissionShared.SCORE_CHANGE_MESSAGE:  # 0x36
        ...
    elif cType == MissionShared.SCORE_MESSAGE:         # 0x37
        ...
    elif cType == MissionShared.RESTART_GAME_MESSAGE:  # 0x39
        ...
```

Python handlers are registered on `ET_NETWORK_MESSAGE_EVENT` and fire for ALL incoming
TGMessages. They read the first byte, compare against known constants, and ignore unknowns.
No bounds check, no rejection of unrecognized types.

### Chat Relay (Python-level, host-side)

```python
# MultiplayerMenus.py line 2273:
if (cType == CHAT_MESSAGE):         # 0x2C
    if (App.g_kUtopiaModule.IsHost()):
        pNewMessage = pMessage.Copy()
        pNetwork.SendTGMessageToGroup("NoMe", pNewMessage)
    # then display locally...

elif (cType == TEAM_CHAT_MESSAGE):  # 0x2D
    if (App.g_kUtopiaModule.IsHost()):
        # team routing: determine sender's team, forward only to teammates
        for each player:
            if player in same team:
                pNetwork.SendTGMessage(player.GetNetID(), pMessage.Copy())
```

Chat relay happens in **Python**, not C++. The host Python handler reads the type byte,
decides to forward, and calls SendTGMessage/SendTGMessageToGroup. This is in addition
to the C++ relay in `FUN_006b63a0`.

---

## Question 4: Client-to-Client Routing → **Star Topology**

```
Client A  ←→  HOST  ←→  Client B
                ↑
Client C  ←————┘
```

### Evidence

1. **Client peer array**: Clients have exactly ONE peer entry — the host. When a client
   calls `SendTGMessage(0, msg)` (broadcast), it goes ONLY to the host.

2. **Host peer array**: Host has entries for ALL connected clients. When host calls
   `SendTGMessage(0, msg)` (broadcast), it goes to all clients.

3. **No peer-to-peer connections**: `FUN_006b6640` (HandleConnectRequest) only runs on
   the host. Clients never accept incoming connections from other clients.

4. **Two relay mechanisms**:
   - C++ automatic relay: `FUN_006b63a0` → `BroadcastToOthers` (unconditional)
   - Python explicit relay: `ProcessMessageHandler` → `SendTGMessageToGroup("NoMe", ...)`

### Broadcast Semantics by Role

| Caller | `SendTGMessage(0, msg)` | `SendTGMessageToGroup("NoMe", msg)` |
|--------|------------------------|--------------------------------------|
| Client | → host only (1 peer) | → host only (1 peer) |
| Host | → all clients | → all clients (host excluded from group) |

---

## Why Mod Custom Types Work

### Kobayashi Maru (types 205, 211-214)

1. KM Python writes `chr(205)` as first byte of TGMessage payload
2. Sends via `SendTGMessage(0, msg)` — broadcast to all peers
3. Transport layer wraps in type-0x00 transport message (opaque payload)
4. Host C++ relay (`FUN_006b51e0`) forwards to all other peers — no inspection
5. C++ switch at `0x0069f2a0` has no case for 205 → falls through silently
6. KM's Python handler reads 205 from payload → processes the custom message

### BC Remastered (types 53-57)

Same mechanism. Types 53-57 are `MAX_MESSAGE_TYPES + 10` through `+14`, which happen
to be the same values as stock MISSION_INIT through RESTART_GAME. This is not a conflict —
BC Remastered replaces the stock Python handlers with its own.

### The critical enabler

The C++ dispatcher's **silent fallthrough for unknown opcodes** is what makes all mod
message types work. If the switch had a default case that logged an error or dropped the
message, mods would break. But the original developers left it open.

---

## PythonEvent Dispatch: 0x06 vs 0x0D (NOT Relayed)

**Critical finding**: Neither PythonEvent (0x06) nor PythonEvent2 (0x0D) is relayed by the
server. Both route to the same handler (FUN_0069f880) which is LOCAL-ONLY — it deserializes
the event and posts it to the local EventManager. The relay handler (FUN_0069fda0) is NOT
involved.

### Dispatcher Analysis (FUN_0069f2a0 jump table at 0x0069F534)

| Case | Opcode | Handler | Relay? |
|------|--------|---------|--------|
| 0x04 (index 4) | 0x06 PythonEvent | FUN_0069f880 | NO — local only |
| 0x0B (index 11) | 0x0D PythonEvent2 | FUN_0069f880 | NO — same local handler |

Compare with relayed opcodes:
| Case | Opcode | Handler | Relay? |
|------|--------|---------|--------|
| 0x05 (index 5) | 0x07 StartFiring | FUN_0069fda0 | YES — "Forward" group |
| 0x06-0x10 | 0x08-0x12 | FUN_0069fda0 | YES — "Forward" group |

### How Clients Actually Receive PythonEvents

Clients receive 0x06 from the server, but these are **freshly constructed messages**,
not relays of anything a client sent:

1. **HostEventHandler** (LAB_006a1150): catches repair events (0x008000DF, 0x00800074,
   0x00800075), creates NEW opcode 0x06 msg, sends to "NoMe" group
2. **ObjectExplodingHandler** (LAB_006a1240): catches death event (0x0080004E), creates
   NEW opcode 0x06 msg, sends to "NoMe" group

These are the ONLY two producers of server-to-client PythonEvent messages.

### Trace Evidence (Valentine's Day, 33.5min, 3 players)

| Opcode | Wire Count | Factory Events | Ratio | Interpretation |
|--------|-----------|----------------|-------|----------------|
| 0x0D PythonEvent2 | 75 | 75 | 1:1 | NOT relayed |
| 0x07 StartFiring | 2,918 | 978 | 3:1 | Relayed (3 players) |
| 0x08 StopFiring | 1,448 | 483 | 3:1 | Relayed |
| 0x19 TorpedoFire | 1,089 | 363 | 3:1 | Relayed |

The 1:1 ratio for 0x0D confirms it is NOT relayed.

### What 0x0D Carries

All 75 observed 0x0D instances carry eventCode=0x0000010C (TGObjPtrEvent). These are
power reactor state notifications from clients to the host. The server processes them
locally and does not forward.

### OpenBC Parity Bug

OpenBC currently relays 0x0D to all peers. This is WRONG — it causes:
- Duplicate events on receiving clients
- Events that should be server-private leaking to other clients

**Fix**: Stop relaying 0x0D. Process locally on server only, same as 0x06.

---

## Key Addresses

| Address | Function | Role |
|---------|----------|------|
| 0x006b4560 | TGWinsockNetwork::Update | Main network tick |
| 0x006b5c90 | ProcessIncomingPackets | Wire → factory → queue |
| 0x006b4c10 | SendTGMessage | Send to peer/broadcast |
| 0x006b4de0 | SendTGMessageToGroup | Send to named group |
| 0x006b4ec0 | SendToGroupMembers | Iterate group, send each |
| 0x006b51e0 | BroadcastToOthers | Host: relay to all peers |
| 0x006b5080 | QueueForSend | Enqueue on peer send queue |
| 0x006b63a0 | HandleConnection | Process connect + auto-relay |
| 0x006bc6a0 | GameMessageFactory | Type-0x00 deserialize (opaque) |
| 0x006b83f0 | TGMessageFactory | Type-0x32 deserialize |
| 0x006b8530 | TGMessage::GetData | Returns payload ptr (this+4) |
| 0x0069f2a0 | MultiplayerGame_Dispatch | Game opcode switch (0x02-0x2A) |
| 0x00504c10 | MultiplayerWindow_Dispatch | UI opcodes (0x00, 0x01, 0x16) |
| 0x006a3cd0 | NetFile_Dispatch | Checksum opcodes (0x20-0x27) |
| 0x009962d4 | TransportFactoryTable | 256-entry factory pointer array |
| 0x005e4860 | RegisterMessageType | SWIG wrapper (never called by stock) |
