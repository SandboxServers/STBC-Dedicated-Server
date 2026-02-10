# Client Join Flow: Post-Checksum Message Sequence

## Overview
After checksums pass, the server sends a precise sequence of messages that the
client must receive in order to transition from "Synchronizing Game Data" to the
ship selection screen. Understanding this sequence is critical for diagnosing
client disconnects.

## The C++ Event Chain (Normal Game)
```
ChecksumAllPassed (FUN_006a4bb0)
  -> Posts event 0x8000e8 (ET_SYSTEM_CHECKSUM_PASSED)
  -> Handled by SystemChecksumPassedHandler (registered at 09_mp line 5469)
     -> Verifies ALL peer checksums via FUN_006a5860
     -> Posts event 0x8000e6 (ET_CHECKSUM_COMPLETE) at line 3977
  -> Handled by ChecksumCompleteHandler (FUN_006a1b10)
     1. Verifies checksums against all other connected players
     2. Builds & sends opcode 0x00 packet (settings)
     3. Builds & sends opcode 0x01 packet (status byte)
     ** NOTE: Does NOT post 0x8000f1 - only sends network packets **

Separately (via ReceiveMessageHandler dispatch at LAB_0069f2a0):
  -> NewPlayerInGameHandler (FUN_006a1e70) called from 0x0069f30d
     1. Reads checksum data, stores in player slot
     2. Posts event 0x8000f1 (ET_NEW_PLAYER_IN_GAME) at line 975
     3. Calls Python Mission1.InitNetwork(peerID) via FUN_006f8ab0
     4. Iterates all game object groups (DAT_0097e9cc)
        - For each active object, serializes via vtable+0x10c
        - Sends object data to new peer
     5. Calls FUN_00595c60 for objects responding to type 0x8007
     6. Registers peer in "Forward" event dispatch table

Also: MultiplayerGame constructor self-posts 0x8000f1 for host (line 5518)
  -> SWIG thunk at LAB_006a1590 handles 0x8000f1 events
```

## What the Client Receives

### Message 1: C++ Opcode 0x00 (Settings Packet)
- Handler: FUN_00504d30 (via FUN_00504c10 dispatch)
- Wire format: `[0x00][f32:gameTime][u8:setting1][u8:setting2][u8:playerSlot][u16:mapLen][bytes:mapName][u8:checksumFlag][if 1: checksum data]`
- Actions:
  - Stores gameTime in clock object (DAT_009a09d0 + 0x90)
  - Stores setting1 in DAT_008e5f59
  - Stores setting2 in this+0xb4
  - Stores playerSlot in DAT_0097fa84, computes DAT_0097fa8c
  - Loads mission script via FUN_0044b500("Multiplayer", "Mission", mapName)
  - Sets UI status to "Synchronizing Game Data"
  - If checksumFlag=1, processes checksum match data via FUN_006f4000

### Message 2: C++ Opcode 0x01 (Connection Completed)
- Handler: FUN_00504f10 (via FUN_00504c10 dispatch)
- Wire format: `[0x01]` (single byte)
- Actions:
  - Calls FUN_006f8ab0("AI_Setup", "GameInit") -- runs Python GameInit
  - Creates MultiplayerGame object via FUN_0069e590("Multiplayer.MultiplayerGame", 0x10)
  - If IsMultiplayer, reads g_iPlayerLimit from Python and sets on game object
  - Sets UI status to "Connection Completed"

### Message 3: Python MISSION_INIT_MESSAGE (via TGMessage/TGNetwork)
- Sent by Mission1.InitNetwork(peerID) (Python function)
- Message type: App.MAX_MESSAGE_TYPES + 10
- Contents: playerLimit, system, timeLimit, fragLimit
- This triggers BuildMission1Menus on client -> ship selection UI

### Message 4: Python SCORE_MESSAGE (optional, per-player)
- Sent by Mission1.InitNetwork for each player with scores
- Message type: App.MAX_MESSAGE_TYPES + 12
- Contents: playerID, kills, deaths, score
- Empty for first player joining

## Critical Gate: this+0xb0
The client's FUN_00504c10 checks `*(char*)(this + 0xb0) != 0` before processing
ANY game message. This flag appears to be set during the connection setup
(FUN_00504890 sets it at line `*(undefined1*)((int)this + 0xb0) = 0` initially,
and it gets set to non-zero when connection succeeds). If opcode 0x00 never
arrives, this gate stays closed and the client ignores everything.

## For First Player Joining Empty Game
- Object replication loop (step 3 of FUN_006a1e70): NO-OP, no objects exist
- Forward table registration: NO-OP, no other peers to forward to
- Score messages: NO-OP, dictionaries are empty
- ONLY opcode 0x00, opcode 0x01, and MISSION_INIT_MESSAGE matter

## Timing
- Checksum exchange: ~18 ticks (~600ms) from player detection
- C++ ChecksumCompleteHandler fires IMMEDIATELY on checksum completion (0 delay)
- Our workaround INITNET_DELAY_TICKS: should be 20-30 (not 120)
- Connection timeout: 45 seconds (set in MultiplayerMenus.py:3052)

## Key Addresses
- 0x006a4bb0: ChecksumAllPassed (posts 0x8000e8)
- 0x006a1b10: ChecksumCompleteHandler (sends 0x00 + 0x01)
- 0x006a1e70: NewPlayerInGameHandler (calls InitNetwork + objects)
- 0x00504c10: Client ReceiveMessageHandler (dispatches 0x00/0x01/0x16)
- 0x00504d30: Client opcode 0x00 handler
- 0x00504f10: Client opcode 0x01 handler
