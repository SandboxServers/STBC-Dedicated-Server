# Player Disconnect Flow

Reverse-engineered from stbc.exe via Ghidra decompilation, source code analysis, and packet trace inspection.
Confidence: **High** for code paths (verified against decompiled functions); **Verified** for graceful disconnect runtime behavior (wire trace captured 2026-02-19, stock-dedi loopback session).

## Overview

Player disconnects follow a three-path-convergence architecture:

```
TIMEOUT PATH (~45 seconds):
  TGNetwork_Update (FUN_006b4560)
    └─ iterates peer array
    └─ compares currentTime - peer+0x30 > connectionTimeout
    └─ creates TGBootPlayerMessage (bootReason=1)
    └─> FUN_006b75b0 (peer deletion)

GRACEFUL DISCONNECT (transport 0x05):
  ProcessIncomingPackets (FUN_006b5c90)
    └─ receives transport message type 0x05
    └─ dispatches to FUN_006b6a20
    └─ reads peer ID from message
    └─> FUN_006b75b0 (peer deletion)

BOOT/KICK:
  ET_BOOT_PLAYER event (0x8000F6)
    └─ BootPlayerHandler (MultiplayerWindow, FUN_00506170)
    └─ sends kick to target peer
    └─ target peer disconnects
    └─> FUN_006b75b0 (peer deletion)

ALL THREE PATHS CONVERGE:
  FUN_006b75b0 (Peer Deletion Entry Point)
    ├─ binary-searches WSN peer array (WSN+0x2C)
    ├─ posts ET_NETWORK_DELETE_PLAYER (0x60005)
    ├─ sets peer+0xBC = 1 (IsDisconnected flag)
    ├─ sets peer+0xB8 = currentTime (disconnect timestamp)
    └─> event cascade to game layer

EVENT CASCADE (game layer):
  DeletePlayerHandler (FUN_006a0ca0, registered for 0x60005)
    ├─ sends 0x14 DestroyObject to remaining clients
    ├─ sends 0x17 DeletePlayerUI to remaining clients
    ├─ sends 0x18 DeletePlayerAnim to remaining clients
    └─ Python DeletePlayerHandler: RebuildPlayerList()
```

## 1. Disconnect Detection Paths

### 1.1 Peer Timeout (~45 seconds)

**Location**: FUN_006b4560 (TGNetwork_Update tick function)

The WSN (TGWinsockNetwork) tick function runs every frame for hosts in state 2 (hosting). It iterates the peer array at `WSN+0x2C` (array pointer) / `WSN+0x30` (count), checking each peer's last-receive timestamp:

```
for each peer in WSN peer array:
    if peer+0x18 != self.peerID:        // skip self
        if peer+0xBC == 0:              // not already disconnected
            if currentTime - peer+0x30 > connectionTimeout:
                create TGBootPlayerMessage (bootReason=1)
                copy peer+0x18 (peerID) as boot target
                FUN_006b75b0(WSN, peer+0x18)    // delete peer
                send boot message to all peers
```

The timeout threshold is stored at a global (DAT_0088bd58), compared against `currentTime - peer->lastRecvTime`. Based on the keepalive interval of ~12 seconds seen in traces and the standard ~45-second timeout in similar engines, the threshold is approximately 45 seconds.

**Key peer fields** (peer object layout):
| Offset | Type | Field |
|--------|------|-------|
| +0x18 | int | Peer ID (network-assigned) |
| +0x1C | int | Peer address (IP) |
| +0x2C | float | Keepalive send timestamp |
| +0x30 | float | Last receive timestamp |
| +0xB8 | float | Disconnect timestamp |
| +0xBC | byte | IsDisconnected flag (0=active, 1=disconnected) |

### 1.2 Graceful Disconnect (Transport Message 0x05)

**Handler**: FUN_006b6a20 (dispatched from FUN_006b5f70, type 5 case)

When a client cleanly exits (ALT+F4, menu quit), it sends transport message type 0x05 (DisconnectMessage). This is verified on the wire — see Section 9 for the captured disconnect packet. The handler:

```c
// FUN_006b6a70 — Graceful disconnect handler
void __thiscall FUN_006b6a70(WSN *this, TGMessage *param_1)
{
    char *data = FUN_006b8530(param_1, NULL);    // get message payload
    int peerID = (int)*data;                     // first byte = peer ID

    if (peerID == -1) {
        // Special case: host disconnected from us
        this->field_0x10d = 1;      // set shutdown flag
        this->field_0x100 = param_1->field_0x40;  // store reason
        this->state = 2;            // transition to state 2
        return;
    }

    FUN_006b75b0(this, peerID);     // normal peer deletion

    if (peerID == this->field_0x18) {
        // This was the host peer
        this->field_0x10d = 1;      // set shutdown flag
        this->field_0x100 = param_1->field_0x40;
    }
}
```

The graceful disconnect path reaches `FUN_006b75b0` immediately, without the timeout delay.

### 1.3 Boot/Kick (Host-Initiated)

**Event**: ET_BOOT_PLAYER (0x8000F6)
**Handler**: MultiplayerWindow BootPlayerHandler (FUN_00506170)

The kick path is triggered by the anti-cheat system (subsystem hash mismatch) or by explicit host action. The flow:

1. ET_BOOT_PLAYER event fires with target peer ID
2. BootPlayerHandler constructs a TGBootPlayerMessage
3. Message sent to the target peer
4. Target peer receives the boot message and disconnects
5. The host-side also calls `FUN_006b75b0` to remove the peer locally

This path also converges at the same `FUN_006b75b0` peer deletion function.

## 2. Peer Deletion (Convergence Point)

**Function**: FUN_006b75b0
**Convention**: `__thiscall(ECX=WSN, int peerID)`

This is the single convergence point for all disconnect paths. Decompiled logic:

```c
void __thiscall FUN_006b75b0(WSN *this, int peerID)
{
    if (this->peerArray == NULL)         // WSN+0x2C
        goto fallback;

    // Binary search the peer array for peerID
    int idx = FUN_00401cc0(this->peerArray, peerID);
    if (idx < 0)
        goto fallback;

    Peer *peer = this->peerArray[idx];
    if (peer == NULL)
        goto fallback;

    // Create ET_NETWORK_DELETE_PLAYER event
    TGEvent *event = allocate(0x2C);
    event = FUN_006bb840(event);         // construct as network event
    event->eventType = 0x60005;          // ET_NETWORK_DELETE_PLAYER
    event->field_0x28 = peerID;          // store peer ID in event

    FUN_006d62b0(event, this);           // set event source
    FUN_006d6270(event, this);           // set event destination
    FUN_006da2a0(&eventManager, event);  // post to global event queue

    // Mark peer as disconnected
    peer->isDisconnected = 1;            // peer+0xBC
    peer->disconnectTime = currentTime;  // peer+0xB8 = DAT_0099c6bc
    return;

fallback:
    FUN_006b7590(this, peerID);          // alternative cleanup path
}
```

**Important**: The peer is NOT immediately removed from the array. It is marked as disconnected (`peer+0xBC = 1`) and given a timestamp. Actual removal from the peer array happens later in `FUN_006b7660` (called during the next WSN tick cycle), which binary-searches for the peer, calls its destructor, and shifts the array down.

## 3. Event Cascade

### 3.1 Event Routing

The ET_NETWORK_DELETE_PLAYER event (0x60005) is posted to the global event manager at `DAT_0097f838`. Two systems register handlers for this event:

**C++ Handler (MultiplayerGame)**:
- Registered in the MultiplayerGame constructor (FUN_0069efe0)
- Handler address: FUN_006a0ca0 (DeletePlayerHandler)
- Registered via: `FUN_006db380(&eventMgr, 0x60005, this, "MultiplayerGame::DeletePlayerHandler", ...)`

**Python Handler (Mission scripts)**:
- Registered in each mission's `SetupEventHandlers`:
  ```python
  App.g_kEventManager.AddBroadcastPythonFuncHandler(
      App.ET_NETWORK_DELETE_PLAYER, pMission,
      __name__ + ".DeletePlayerHandler")
  ```

### 3.2 DisconnectHandler is EMPTY

The handler registered for ET_NETWORK_DISCONNECT (0x60003) at address 0x006a0a20 is a **no-op** — it contains only a `RET` instruction. This event type fires only on full network shutdown (all peers lost), not on individual peer disconnects. The game intentionally handles per-peer cleanup exclusively through ET_NETWORK_DELETE_PLAYER (0x60005).

### 3.3 DeletePlayerHandler (C++ Layer)

**Address**: FUN_006a0ca0
**Event**: ET_NETWORK_DELETE_PLAYER (0x60005)

This handler is **undefined in Ghidra** — it exists only as a function pointer stored by the event registration system, making it invisible to auto-analysis. Based on the opcodes it sends and the Python-level behavior, its responsibilities are:

1. Look up the disconnecting player's ship object
2. Send **opcode 0x14** (DestroyObject) to remaining clients — removes the ship from the game world
3. Send **opcode 0x17** (DeletePlayerUI) to remaining clients — removes the player from the scoreboard
4. Send **opcode 0x18** (DeletePlayerAnim) to remaining clients — creates "Player X has left" floating text
5. Clean up the player's slot in the MultiplayerGame player array (this+0x74, 16 slots of 0x18 bytes each)
6. Clean up checksum/file transfer state for that player (via NetFile)

## 4. Cleanup Messages to Remaining Clients

### 4.1 DestroyObject (Opcode 0x14)

**Handler**: FUN_006a01e0
**Direction**: Server → All Clients

Removes the disconnected player's ship from the game world.

```
Offset  Size  Type    Field
------  ----  ----    -----
0       1     u8      opcode = 0x14
1       4     i32     object_id     (ship object ID)
```

The handler looks up the object by ID (FUN_00434e00, type 0x8003). If the object is a ship (type 0x8006), it calls `vtable[0x138](1, 0)` to mark dead/hide, then `vtable[0](1)` as the destructor with cleanup.

### 4.2 DeletePlayerUI (Opcode 0x17)

**Handler**: FUN_006a1360
**Direction**: Server → All Clients

Removes the player from the client's scoreboard and player list.

```
Offset  Size  Type    Field
------  ----  ----    -----
0       1     u8      opcode = 0x17
1       var   stream  connection_id + data_length
```

Decompiled behavior:
1. Reads the connection ID from the message stream
2. Creates a TGEvent with the connection ID
3. Posts the event to the event queue
4. Event is consumed by the UI to remove the player entry

**Trace note**: 0x17 was observed 6 times in the battle trace and 1 time in the stock-dedi trace, but all instances were at **join time**, not disconnect time. This suggests the opcode serves double duty — removing stale entries when a player slot is reused.

### 4.3 DeletePlayerAnim (Opcode 0x18)

**Handler**: FUN_006a1420
**Direction**: Server → All Clients

Creates a floating "Player X has left" text notification on clients.

Decompiled behavior:
1. Reads player name from the message stream
2. Opens `data/TGL/Multiplayer.tgl` resource file
3. Looks up the `Delete_Player` entry (a format string template)
4. Creates a text animation object (FUN_0055c790) with the formatted player name
5. Sets alpha/duration: `0x3FA00000` (1.25) opacity, `0x40A00000` (5.0) seconds duration
6. Attaches to the 3D scene via NiNode

**Trace note**: 0 instances observed in either available trace, consistent with no player disconnects occurring.

## 5. Python Layer Cleanup

All four mission scripts (Mission1-5, excluding Mission4 which doesn't exist) have identical `DeletePlayerHandler` implementations:

```python
def DeletePlayerHandler(TGObject, pEvent):
    import Mission1Menus    # (or Mission2Menus, etc.)

    # We only handle this event if we're still connected.
    # If we've been disconnected, then we don't handle this
    # event since we want to preserve the score list to
    # display as the end game dialog.
    pNetwork = App.g_kUtopiaModule.GetNetwork()
    if (pNetwork):
        if (pNetwork.GetConnectStatus() == App.TGNETWORK_CONNECTED
            or pNetwork.GetConnectStatus() == App.TGNETWORK_CONNECT_IN_PROGRESS):
            # We do not remove the player from the dictionary.
            # This way, if the player rejoins, his score will
            # be preserved.

            # Rebuild the player list since a player was removed.
            Mission1Menus.RebuildPlayerList()
    return
```

**Key design decisions visible in the code:**

1. **Score preservation**: The handler intentionally does NOT remove the disconnected player from score dictionaries. This enables score persistence if the player reconnects.

2. **Connection guard**: The handler only runs if the network is still connected. During game-end scenarios where the network is torn down, it skips cleanup to preserve the final scoreboard display.

3. **Minimal cleanup**: Only `RebuildPlayerList()` is called — the Python layer doesn't need to clean up game objects (the C++ layer handles that via opcodes 0x14/0x17/0x18).

## 6. Event Handler Architecture

### 6.1 MultiplayerGame Event Registrations (29 Handlers)

Registered in the constructor via `FUN_006db380` (event types) and `FUN_006da130` (handler names):

| Event ID | Handler Address | Handler Name |
|----------|----------------|--------------|
| 0x60001 | 0x0069f2a0 | ReceiveMessageHandler (main opcode dispatch) |
| 0x60003 | 0x006a0a20 | DisconnectHandler (**empty — single RET**) |
| 0x60004 | 0x006a0a30 | NewPlayerHandler |
| 0x60005 | 0x006a0ca0 | DeletePlayerHandler |
| 0x8000C8 | 0x006a0f90 | ObjectCreatedHandler |
| — | 0x006a1150 | HostEventHandler |
| — | 0x006a1590 | NewPlayerInGameHandler |
| — | 0x006a1790 | StartFiringHandler |
| — | 0x006a17a0 | StartWarpHandler |
| — | 0x006a17b0 | TorpedoTypeChangeHandler |
| — | 0x006a18d0 | StopFiringHandler |
| — | 0x006a18e0 | StopFiringAtTargetHandler |
| — | 0x006a18f0 | StartCloakingHandler |
| — | 0x006a1900 | StopCloakingHandler |
| — | 0x006a1910 | SubsystemStatusHandler |
| — | 0x006a1920 | AddToRepairListHandler |
| — | 0x006a1930 | ClientEventHandler |
| — | 0x006a1940 | RepairListPriorityHandler |
| — | 0x006a1970 | SetPhaserLevelHandler |
| — | 0x006a1a60 | DeleteObjectHandler |
| — | 0x006a1a70 | ChangedTargetHandler |
| — | 0x006a1b10 | ChecksumCompleteHandler |
| — | 0x006a1240 | ObjectExplodingHandler |
| — | 0x006a07d0 | EnterSetHandler |
| — | 0x006a0a10 | ExitedWarpHandler |
| — | 0x006a2640 | KillGameHandler |
| — | 0x006a2a40 | RetryConnectHandler |
| 0x8000E9 | 0x006a2640 | KillGameHandler (also registered for ET_KILL_GAME) |
| 0x8000FF | 0x006a2a40 | RetryConnectHandler (also registered for retry event) |

**Analysis note**: Only 5 of these 29 handlers are defined as functions in Ghidra's auto-analysis (17%). The remaining 24 are only reachable via function pointers stored by the event system, making them invisible to standard code flow analysis.

### 6.2 Network Event Types

| Event ID | Constant | Description |
|----------|----------|-------------|
| 0x60001 | ET_NETWORK_MESSAGE_EVENT | Incoming game message |
| 0x60002 | (connect established) | Connection established |
| 0x60003 | ET_NETWORK_DISCONNECT | Full network shutdown |
| 0x60004 | ET_NETWORK_NEW_PLAYER | New peer connected |
| 0x60005 | ET_NETWORK_DELETE_PLAYER | Peer removed |
| 0x8000C8 | (object created) | Game object created |
| 0x8000E6 | (checksum result) | Individual checksum done |
| 0x8000E7 | ET_SYSTEM_CHECKSUM_FAILED | Checksum mismatch |
| 0x8000E8 | ET_CHECKSUM_COMPLETE | All checksums passed |
| 0x8000E9 | ET_KILL_GAME | Game killed |
| 0x8000F6 | ET_BOOT_PLAYER | Anti-cheat kick |
| 0x8000FF | (retry connect) | Connection retry |

## 7. Known Issues and Proxy Considerations

### 7.1 PatchRemovePeerAddress (Fix #18)

**Address**: 0x006B9F40 (TGWinsockNetwork::RemovePeerAddress)
**Convention**: `__thiscall(ECX=WSN, DWORD ipAddress)`

During peer cleanup, the engine calls `RemovePeerAddress` to remove the peer's IP from a singly-linked list at `WSN+0x348`. When this list is empty (head == NULL), the original code dereferences NULL:

```asm
006b9f40: MOV EAX,[ECX+0x348]   ; load list head
006b9f46: MOV EDX,[ESP+0x4]     ; load param_1 (IP addr)
006b9f4a: CMP [EAX],EDX         ; CRASH when EAX==0
```

**Fix**: Code cave at function entry adds `TEST EAX,EAX / JZ .early_ret`, returning cleanly via `RET 0x4` when the list head is NULL. This happens during client disconnect when `RemovePeerAddress` is called for a peer that was never fully added to the address list.

### 7.2 DeletePlayerHandler Not Registered (Headless Server)

In the headless dedicated server, the mission scripts may not register their Python `DeletePlayerHandler` for `ET_NETWORK_DELETE_PLAYER`. This means the Python-level cleanup (rebuilding the player list) may not fire. The C++ DeletePlayerHandler still runs since it's registered by the MultiplayerGame constructor.

**Impact**: Low. The Python handler only rebuilds the UI player list, which is irrelevant for a headless server. Score dictionaries are preserved regardless.

### 7.3 Disconnect Trace Evidence

**Graceful disconnect captured** in the 2026-02-19 stock-dedi loopback trace (22,119 lines, ~91-second session). See Section 9 for full wire trace analysis.

Prior trace evidence:
- **0x17 DeletePlayerUI**: 6 instances in battle trace, 1 in stock-dedi — **all at join time** (reuse of player slots), not disconnect
- **0x18 DeletePlayerAnim**: 0 instances in either trace
- **0x14 DestroyObject**: Observed for ship destruction (combat kills), not specifically for disconnect-triggered removal
- **Transport 0x05 Disconnect**: 1 instance captured (2026-02-19 trace, packet #1764)

## 8. Key Functions

| Address | Name | Role |
|---------|------|------|
| FUN_006b4560 | TGNetwork_Update | WSN tick: timeout detection, keepalive, packet processing |
| FUN_006b5c90 | ProcessIncomingPackets | Receives UDP packets, dispatches transport messages |
| FUN_006b6a20 | GracefulDisconnectHandler | Handles transport 0x05: calls FUN_006b75b0 |
| FUN_006b75b0 | PeerDeletion | Convergence point: marks peer, posts 0x60005 event |
| FUN_006b7660 | PeerArrayRemove | Actually removes peer from array, calls destructor |
| FUN_006b7590 | PeerCleanupFallback | Alternative cleanup when peer not found in array |
| FUN_006b9f40 | RemovePeerAddress | Removes IP from WSN+0x348 linked list (patched) |
| FUN_006a0a20 | DisconnectHandler | **EMPTY** (handles 0x60003, not used for per-peer) |
| FUN_006a0ca0 | DeletePlayerHandler | Game-level cleanup: sends 0x14, 0x17, 0x18 |
| FUN_006a01e0 | DestroyObject_Net | Opcode 0x14 handler: removes object from game world |
| FUN_006a1360 | DeletePlayerUI | Opcode 0x17 handler: removes player from scoreboard |
| FUN_006a1420 | DeletePlayerAnim | Opcode 0x18 handler: "Player X has left" text |
| FUN_00506170 | BootPlayerHandler | MultiplayerWindow: initiates kick/boot |
| FUN_00401cc0 | BinarySearchPeerArray | Binary search helper used by FUN_006b75b0 |

## 9. Verified Graceful Disconnect (Wire Trace, 2026-02-19)

**Source**: stock-dedi loopback trace, OBSERVE_ONLY proxy build (zero patches). Session: client connects at 11:37:53, disconnects at 11:39:24 (~91 seconds of gameplay).

### 9.1 Pre-Disconnect Activity

Last game data packets (PythonEvents seq=39, 40) at 11:39:21.416. Client ACKs for seq=39 and seq=40 are retransmitted 3 times (11:39:21.419, 22.085, 22.753) — this is the ACK-outbox accumulation bug (see [fragmented-ack-bug.md](fragmented-ack-bug.md)).

### 9.2 Disconnect Packet (Client → Server)

```
#1764 C->S Peer#0(127.0.0.1:60271) len=20 [Disconnect]
Decrypted:
  0000: 02 03 05 0A C0 02 00 02 0A 0A 0A EF 01 27 00 00  |.............'..|
  0010: 01 28 00 00                                      |.(..|
DECODE: peer=C(2) msgs=3
  [msg 0] Disconnect (0x05) byte1=0x0A
  [msg 1] ACK seq=39
  [msg 2] ACK seq=40
```

**Wire format breakdown**:
- `02` — peer_id (client = 2)
- `03` — msg_count (3 transport messages in this packet)
- `05` — **transport type 0x05 = DisconnectMessage** (verified)
- `0A C0 02 00 02 0A 0A 0A EF` — disconnect payload (9 bytes, content TBD)
- `01 27 00 00` — stale ACK for seq=39 (type 0x01, seq LE 0x0027, flags 0x00, non-fragmented)
- `01 28 00 00` — stale ACK for seq=40

**Key observation**: The disconnect message is **multiplexed** with stale ACKs from the ACK-outbox in a single UDP packet. The ACK-outbox accumulation bug means every outbound packet — including the disconnect — carries all accumulated stale ACKs.

### 9.3 Server ACK Response

Server immediately responds with an ACK for the disconnect (seq=2, low-type):

```
#1765 S->C len=6 [ACK]
  01 01 01 02 00 02
DECODE: peer=S(1) msgs=1
  [msg 0] ACK seq=2
```

The server then **retransmits this ACK 7 times** over ~4 seconds:

| Packet | Time | Content |
|--------|------|---------|
| #1765 | 11:39:24.854 | ACK seq=2 |
| #1766 | 11:39:25.519 | ACK seq=2 |
| #1767 | 11:39:26.187 | ACK seq=2 |
| #1768 | 11:39:26.853 | ACK seq=2 |
| #1769 | 11:39:27.520 | ACK seq=2 |
| #1770 | 11:39:28.188 | ACK seq=2 |
| #1771 | 11:39:28.855 | ACK seq=2 |

Interval: ~0.67 seconds between retransmits. This is the ACK-outbox accumulation bug again — the server's ACK for the disconnect message is never removed from its outbox, so it retransmits until the peer entry is eventually cleaned up.

### 9.4 GameSpy Heartbeat

Immediately after the disconnect retransmits stop:

```
#1772 S->C Peer#1(81.205.81.173:27900) len=47 GAMESPY_HEARTBEAT
  \heartbeat\0\gamename\bcommander\statechanged\1
```

The `statechanged=1` signals to the master server that the server's player count has changed (player disconnected). This is the **only externally-visible artifact** of a disconnect.

### 9.5 Complete Verified Graceful Disconnect Timeline

```
11:39:21.416  Last game data: PythonEvent seq=39, seq=40 (S→C)
11:39:21.419  Client ACKs seq=39, seq=40 (C→S) — first send
11:39:22.085  Client retransmits ACKs seq=39, seq=40 (stale ACK bug)
11:39:22.753  Client retransmits ACKs again
11:39:24.851  Client sends DISCONNECT (0x05) + stale ACKs (C→S)
11:39:24.854  Server ACKs disconnect (seq=2) (S→C)
11:39:25.519  Server retransmits ACK seq=2
   ... 5 more retransmits at ~0.67s intervals ...
11:39:28.855  Last ACK retransmit
11:39:29.016  GameSpy heartbeat with statechanged=1
```

Total disconnect processing time: **~4.2 seconds** from disconnect message to GameSpy notification. The ~3.3-second gap between the last game data and the disconnect message is the client's shutdown sequence (saving state, closing UI, etc.).

---

## Appendix: Complete Disconnect Sequence (Timeout Path)

The most common disconnect scenario — a player's network connection drops silently:

```
Time 0s:     Player stops sending packets (network failure, process crash, etc.)
Time 0-45s:  Server continues sending StateUpdates and keepalives to the peer
             peer+0x30 (lastRecvTime) stops advancing
Time ~12s:   Keepalive response from player fails to arrive
Time ~24s:   Second keepalive cycle missed
Time ~36s:   Third keepalive cycle missed
Time ~45s:   TGNetwork_Update detects timeout:
               currentTime - peer+0x30 > connectionTimeout
             Creates TGBootPlayerMessage (bootReason=1)
             Calls FUN_006b75b0(WSN, peerID):
               - Searches peer array for peerID
               - Sets peer+0xBC = 1 (IsDisconnected)
               - Sets peer+0xB8 = currentTime
               - Posts ET_NETWORK_DELETE_PLAYER (0x60005)
             Sends boot message to remaining peers

Time ~45s+:  Event system delivers 0x60005 to handlers:
             C++ DeletePlayerHandler (FUN_006a0ca0):
               - Sends 0x14 DestroyObject (removes ship)
               - Sends 0x17 DeletePlayerUI (removes from scoreboard)
               - Sends 0x18 DeletePlayerAnim ("Player X has left")
               - Cleans up player slot in MultiplayerGame
             Python DeletePlayerHandler:
               - Calls RebuildPlayerList()
               - Scores preserved in dictionaries

Time ~45s+:  RemovePeerAddress (FUN_006b9f40) removes IP from list
             (protected by PatchRemovePeerAddress NULL check)

Next tick:   FUN_006b7660 removes peer from WSN peer array
             Peer object destructed
             Player fully removed from server state
```
