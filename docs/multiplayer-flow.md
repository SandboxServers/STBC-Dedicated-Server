# Complete Multiplayer Join Flow (Client -> Server -> Ship Selection)

## Phase 1: Client Clicks "Start" on Join Multiplayer

### MultiplayerWindow::StartGameHandler (FUN_00504890)
1. If already in multiplayer (DAT_0097fa8a): passes event to TopWindow vtable+0x68
2. Otherwise: calls FUN_00505480 (UI setup), shows "Connecting..." status
3. Reads config: "Multiplayer Options" -> Game_Name, Player_Name, Password
4. Calls **FUN_00445d90** (UtopiaModule::InitMultiplayer) with (server_addr, password, port)

### FUN_00445d90 - Network Initialization
Called as __thiscall on UtopiaModule (0x0097FA00):
```
1. new TGWinsockNetwork(0x34C bytes) -> UtopiaModule+0x78
2. FUN_006b9bb0(WSN, port, 0) - stores port at WSN+0x338
3. If IsMultiplayer: force param_1=0, port=0x5655 (for host path)
4. If password empty: param_2 = NULL
5. TGNetwork_HostOrJoin(WSN, addr_or_0, password)
   - addr=0: HOST mode (sets WSN+0x10E=1, state=2, fires 0x60002 event)
   - addr!=0: JOIN mode (sets WSN+0x10E=0, state=3, sets WSN+0x10F=1)
   - Calls vtable+0x60 to create UDP socket
   - Calls FUN_006b7070 to set address info
6. new NetFile(0x48 bytes) via FUN_006a30c0 -> UtopiaModule+0x80
   - Creates 3 hash tables (A/B/C) for checksum tracking
   - Registers NetFile::ReceiveMessageHandler for event 0x60001
7. new GameSpy(0xF4 bytes) -> UtopiaModule+0x7C (if not already exists)
```

## Phase 2: Connection Established

### Server Side: TGNetwork_Update processes connection
1. ProcessIncomingPackets (FUN_006b5c90) receives connection packet
2. Internal peer management creates new peer entry
3. ET_NETWORK_NEW_PLAYER event fired

### MultiplayerGame::NewPlayerHandler (FUN_006a0a30)
When +0x1F8 = 1 (ready for new players):
1. Iterates player slots (0-15, each 0x18 bytes at this+0x74)
2. Counts active players (slot+0x00 != 0)
3. If active < maxPlayers (this+0x1FC):
   - FUN_006a7770 initializes player slot
   - Sets slot active flag, stores peer network ID
   - **Calls FUN_006a3820(ChecksumManager, peerID)** - starts checksum exchange
4. If full: creates reject message (type 3), sends via TGNetwork::Send

When +0x1F8 = 0 (not ready):
- Creates timer event to retry later (with exponential backoff)

## Phase 3: Checksum Exchange

### Server: FUN_006a3820 (ChecksumRequestSender)
1. Cleans up any existing state for this player (FUN_006a6500)
2. Builds 4 checksum request entries:
   | # | Directory | Filter | Recursive |
   |---|-----------|--------|-----------|
   | 0 | scripts/ | App.pyc | 0 |
   | 1 | scripts/ | Autoexec.pyc | 0 |
   | 2 | scripts/ships/ | *.pyc | 1 |
   | 3 | scripts/mainmenu/ | *.pyc | 0 |
3. For each: calls FUN_006a39b0 which:
   - Creates network message with opcode 0x20 + [index][dir_len][dir][filter_len][filter][recursive]
   - Sets reliable flag (msg+0x3A = 1)
   - **Only for index 0**: also calls TGNetwork::Send immediately
   - Queues message in NetFile hash table B (keyed by player ID)

### Client: FUN_006a5df0 (Checksum Request Handler - opcode 0x20)
1. Parses: skip opcode, read index byte, read dir string, read filter string, read recursive flag
2. If index == 0: calls FUN_006a6630 (initialization for first request)
3. Calls FUN_0071f270 to compute file checksums for the directory
4. If files found (non-zero return):
   - Builds response: [0x21][index][reference_hash(if idx=0)][dir_hash][file_checksums]
   - Sends via TGNetwork::Send(WSN, host_peer_id, msg, 0)
   - Shows "Server Found" status
5. **If NO files found (returns 0): response NOT sent! Silent failure!**

### Server: FUN_006a3cd0 -> FUN_006a4260 -> FUN_006a4560 (Response Handler)
1. NetFile::ReceiveMessageHandler dispatches opcode 0x21
2. FUN_006a4260 checks byte[1]: if != 0xFF, calls FUN_006a4560 (always for indices 0-3)
3. FUN_006a4560:
   - Looks up queued request in hash table B for this player
   - Finds the queued message matching the response index
   - Extracts dir/filter/recursive from queued message (FUN_006a4d80)
   - Computes SERVER-SIDE checksum via FUN_0071f270
   - Compares client hash vs server hash (FUN_007202e0):
     - **For index 0**: also checks reference string hash (PTR_DAT_008d9af4)
     - If match: FUN_006a5290 (success), dequeues from queue
     - If mismatch: FUN_006a4a00 (fail - fires event + sends opcode 0x22/0x23)
   - After successful verification:
     - Checks hash table C for pending file transfers
     - **If more items in queue B**: clones next message, sends via TGNetwork::Send
     - **If queue B empty**: calls FUN_006a4bb0

### Server: FUN_006a4bb0 (All Checksums Passed)
- Creates event with type 0x8000e8 (ET_CHECKSUM_COMPLETE)
- Posts to EventManager

## Phase 4: Post-Checksum (Server sends game info)

### MultiplayerGame::ChecksumCompleteHandler (FUN_006a1b10)
1. Gets player slot index from player ID
2. Looks up peer in WSN peer array
3. Verifies checksums against ALL other connected players' checksums
4. Builds verification message (opcode 0x00):
   - [0x00][gameTime:f32][setting1:u8][setting2:u8][playerSlot:u8]
   - [mapNameLen:u16][mapName:bytes][passFail:u8]
5. Sends via TGNetwork::Send (reliable)
6. Builds status message: [0x01] (1 byte)
7. Sends via TGNetwork::Send (reliable)

### Client: Receives opcode 0x00
- Processed by MultiplayerGame::ReceiveMessageHandler (0x0069f2a0)
- Extracts player slot, map name, game settings
- Transitions to game setup / ship selection screen

### Client: Receives opcode 0x01
- Status confirmation
- Client ready for gameplay

## Key Functions Reference
| Address | Name | Role |
|---------|------|------|
| 0x00445d90 | UtopiaModule::InitMultiplayer | Creates WSN + NetFile + GameSpy |
| 0x00504890 | StartGameHandler | UI entry point for join/host |
| 0x006a0a30 | NewPlayerHandler | Assigns player slot, starts checksums |
| 0x006a3820 | ChecksumRequestSender | Queues 4 requests, sends #0 |
| 0x006a39b0 | ChecksumRequestBuilder | Builds individual request message |
| 0x006a3cd0 | NetFile::ReceiveMessageHandler | Opcode dispatcher (0x20-0x27) |
| 0x006a4260 | Opcode 0x21 entry | Checks index, routes to 006a4560 |
| 0x006a4560 | ChecksumResponseVerifier | Compares hashes, sends next request |
| 0x006a4a00 | ChecksumFail | Fires fail event + sends 0x22/0x23 |
| 0x006a4bb0 | ChecksumAllPassed | Fires ET_CHECKSUM_COMPLETE |
| 0x006a5df0 | Client: ChecksumRequestHandler | Computes checksums, sends response |
| 0x006a1b10 | ChecksumCompleteHandler | Sends verification + settings to client |
| 0x006a5860 | FileTransferProcessor | Sends files or completion message |
| 0x006b3ec0 | TGNetwork_HostOrJoin | Socket creation, state setup |
| 0x006b4c10 | TGNetwork::Send | Queue message for sending |
| 0x0071f270 | ComputeChecksum | Scans directory, computes file hashes |
| 0x007202e0 | HashString | Computes hash of a file/string |

## Phase 5: Post-Settings (InitNetwork + DeferredInitObject)

### Server: InitNetwork Scheduling (GameLoopTimerProc)
After checksums pass and Settings/GameInit are sent, the server must call
`Mission1.InitNetwork(peerID)` to send `MISSION_INIT_MESSAGE` to the client.

**Detection mechanism**: GameLoopTimerProc scans the WSN peer array (`WSN+0x2C` pointer,
`WSN+0x30` count). Each peer at `pp+0x18` has a peer ID. When a new ID appears:
1. Schedule InitNetwork for 30 ticks later (~1 second)
2. Call `Mission1.InitNetwork(peerID)` via RunPyCode
3. This sends `MISSION_INIT_MESSAGE` to the client

**Timing**: ~1.4 seconds after connect (stock is ~2 seconds).

**Historical bug**: Previously used the `bc` flag at `peer+0xBC` which took 200+ ticks
(or never flipped), causing MISSION_INIT_MESSAGE to arrive 13+ seconds late.

### Server: DeferredInitObject (Ship Creation)
After InitNetwork, the client selects a ship and sends ObjCreateTeam. The engine creates
a ship object on the server, but without a NIF model (subsystems are NULL). GameLoopTimerProc
detects this and triggers Python to complete initialization:

1. Poll every 30 ticks: check for ships owned by the new player
2. If ship exists with NULL ShipRef (+0x2E0): call `DeferredInitObject(playerID)`
3. Python determines ship class → calls `ship.LoadModel(nifPath)`
4. Engine creates 33 subsystem objects, populates ship+0x284 linked list
5. StateUpdate now sends `flags=0x20` with real subsystem health data
6. Collision damage and subsystem damage work

### Timing Summary (Dedicated Server)

| Event | Stock-Dedi | Our Server (Fixed) | Our Server (Broken) |
|-------|-----------|-------------------|-------------------|
| Client connects | T+0.0s | T+0.0s | T+0.0s |
| Checksums complete | T+1.1s | T+1.0s | T+1.0s |
| Settings + GameInit sent | T+1.1s | T+1.0s | T+1.0s |
| InitNetwork / MISSION_INIT | T+2.0s | T+1.4s | **T+13.0s** |
| Client selects ship | T+5.5s | T+5.0s | Client already silent |
| DeferredInitObject | N/A (real renderer) | T+8.0s | Never reached |
| Collision damage works | T+5.7s | T+8.0s | Never |

## Potential Failure Points in Our Server
1. **FUN_0071f270 on server side** - if it can't find/scan script directories, verification fails
2. **Reference string hash** (PTR_DAT_008d9af4) - checked only for index 0, mismatch = immediate fail
3. **DAT_0097f94c** (SkipChecksum flag) - if set, changes behavior completely
4. **Client FUN_0071f270 returning 0** - client silently drops response
5. **Opcode 0x00/0x01 not in NetFile dispatcher** - handled by different handler (MultiplayerGame)
