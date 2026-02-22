> [docs](../README.md) / [engine](README.md) / decompiled-functions.md

# Decompiled Function Reference

## Initialization Flow

### FUN_00445d90 - UtopiaModule::InitMultiplayer
- __thiscall, this = UtopiaModule (0x0097FA00)
- param_1 = server addr (0 for host), param_2 = password TGString, param_3 = port
- When IsMultiplayer(+0x8A) set: overrides param_1=0, param_3=0x5655
- Creates: TGWinsockNetwork(0x34C) -> +0x78, NetFile(0x48) -> +0x80, GameSpy(0xF4) -> +0x7C
- Calls TGNetwork_HostOrJoin for socket creation
- **Our Phase 1 calls this correctly**

### TGNetwork_HostOrJoin (0x006b3ec0)
- __thiscall, ECX = TGWinsockNetwork*
- Requires state == 4 (disconnected)
- param_1 == 0: HOST (sets +0x10E=1, state=2, fires event 0x60002)
- param_1 != 0: JOIN (sets +0x10E=0, state=3, +0x10F=1)
- Calls vtable+0x60 (-> 0x006b9460) for socket creation
- Sets +0x10D = 0
- Calls FUN_006b7070 for address info

### FUN_006a30c0 - NetFile Constructor
- Creates object at UtopiaModule+0x80 (= 0x0097FA80)
- Initializes 3 hash tables: A(+0x18), B(+0x28), C(+0x38) - all capacity 0x25
- Registers handler for event 0x60001 via FUN_006db380(&0x0097F864, ...)
- **This is BOTH the ChecksumManager AND the message opcode dispatcher**

## Network Core

### TGNetwork::Update (0x006B4560)
- __thiscall, ECX = TGWinsockNetwork*
- Early exit if state != 2 and state != 3
- Three unconditional sub-calls:
  1. FUN_006b55b0 - SendOutgoingPackets (checks +0x10C flag, iterates peers)
  2. FUN_006b5c90 - ProcessIncomingPackets (recv from socket, deserialize)
  3. FUN_006b5f70 - DispatchIncomingQueue (validate sequences, deliver)
- State 2 (host): dequeue loop at 0x6b4779 fires events into EventManager
- +0x10D is NOT "process packets" - it's force-disconnect trigger (client path only)

### FUN_006b4c10 - TGNetwork::Send
- Binary searches peer array at WSN+0x2C by peer ID at peer+0x18
- Queues message via FUN_006b5080
- Used by all outbound game traffic

### FUN_006b55b0 - SendOutgoingPackets
- First check: (char)WSN[0x43] (= WSN+0x10C) != 0 (send enabled flag)
- Iterates peers, serializes queued messages, sends via vtable+0x70 (0x006b9870)

### FUN_006b5c90 - ProcessIncomingPackets
- recvfrom loop, dispatches reliable ACKs via FUN_006b61e0

### FUN_006b5f70 - DispatchIncomingQueue
- Sequence number validation, queues for app delivery

### FUN_006b61e0 - Reliable ACK Handler
- Iterates priority queue (peer+0x9C) looking for matching sequence/flags
- If found: resets retry counter (FUN_006b8670)
- If not found: creates new ACK tracking entry, ADDS to priority queue

### FUN_006b6ad0 - Dispatch to Application
- Sequence validation (checks ushort at param_1+5 against param_2+0x24/0x28)
- Discards if out of window, otherwise queues for application delivery

## Checksum Flow - Server Side

### FUN_006a0a30 - NewPlayerHandler
- __thiscall, this = MultiplayerGame
- Guards: WSN != NULL, IsMultiplayer != 0
- +0x1F8 == 0: creates pending player + timer (deferred)
- +0x1F8 != 0: assigns slot in 16-slot array (this+0x74, stride 0x18)
  - Calls FUN_006a3820(ChecksumManager, peerID) to start checksums
  - If full: sends rejection (type 3) via TGNetwork::Send

### FUN_006a3820 - ChecksumRequestSender
- __thiscall, this = NetFile/ChecksumManager (0x0097FA80)
- Cleans up existing state for player (FUN_006a6500)
- Builds 4 requests, queues ALL in hash table B, sends #0 immediately
- Requests: scripts/App.pyc, scripts/Autoexec.pyc, scripts/ships/*.pyc, scripts/mainmenu/*.pyc

### FUN_006a39b0 - Individual Checksum Request Builder
- Creates message: [0x20][index:u8][dir_len:u16][dir][filter_len:u16][filter][recursive:u8]
- Sets reliable flag (msg+0x3A = 1)
- Only calls TGNetwork::Send for param_1 == 0 (index 0)
- Queues in NetFile hash table B for all indices

### FUN_006a3cd0 - NetFile::ReceiveMessageHandler (MESSAGE DISPATCHER)
- Registered for event type 0x60001 (ET_NETWORK_MESSAGE_EVENT)
- Reads first byte (opcode) and switches:
  - 0x20: FUN_006a5df0 (client: checksum request handler)
  - 0x21: FUN_006a4260 (server: checksum response handler)
  - 0x22/0x23: FUN_006a4c10 (checksum fail notification)
  - 0x25: file transfer (with "Receive File Warning" dialog for first time)
  - 0x27: FUN_006a4250

### FUN_006a4260 - Checksum Response Entry (opcode 0x21)
- Checks byte[1]: if != 0xFF (always true for indices 0-3), calls FUN_006a4560
- The 0xFF path is for file transfer responses (not checksum)

### FUN_006a4560 - Checksum Response Verifier
- Looks up queued request in hash table B matching response index
- Extracts dir/filter/recursive from queued message (FUN_006a4d80)
- Computes server-side checksum (FUN_0071f270 + FUN_007202e0)
- For index 0: also checks reference string hash (PTR_DAT_008d9af4)
- Match: FUN_006a5290 (success), dequeues, **sends NEXT from queue via Send**
- Mismatch: FUN_006a4a00 (fail event + sends opcode 0x22/0x23)
- When queue empty: calls FUN_006a4bb0 (fires ET_CHECKSUM_COMPLETE)

### FUN_006a4a00 - Checksum Fail Handler
- Fires event type 0x8000e7 (ET_SYSTEM_CHECKSUM_FAILED)
- Sends opcode 0x22 (file mismatch) or 0x23 (reference mismatch)

### FUN_006a4bb0 - All Checksums Passed
- Fires event type 0x8000e8 (ET_CHECKSUM_COMPLETE)

### FUN_006a1b10 - ChecksumCompleteHandler (ET_CHECKSUM_COMPLETE)
- Verifies client checksums against all other connected players
- Sends verification message (opcode 0x00): gameTime, settings, playerSlot, mapName, passFail
- Sends status byte (opcode 0x01): just [0x01]
- Both sent as reliable via TGNetwork::Send

### FUN_006a5860 - File Transfer Processor
- Called after checksum processing
- If hash table C has entries: reads files and sends with opcode 0x25
- If no entries: sends opcode 0x28 (completion) + fires event

## Checksum Flow - Client Side

### FUN_006a5df0 - Client Checksum Request Handler (opcode 0x20)
- Parses: skip opcode, read index, dir string, filter string, recursive flag
- If index == 0: calls FUN_006a6630 (initialization)
- Calls FUN_0071f270(checksumObj, dir, filter, recursive) to compute hashes
- If files found: builds response [0x21][index][hashes...], sends via TGNetwork::Send
- **If NO files found: response NOT sent (silent failure!)**

## Event System

### FUN_006da2c0 - EventManager::ProcessEvents
- __fastcall, param_1 = EventManager (0x0097F838)
- While event queue non-empty: dequeue, dispatch via FUN_006da300, free
- FUN_006da300 calls FUN_006db620(this+0x2C, event) to dispatch to registered handlers

### FUN_006db380 - Register Event Handler
- __thiscall, this = handler registry (0x0097F864 = EventManager+0x2C)
- Maps event_type -> handler chain (hash table of handler lists)

### FUN_006da130 - Register Handler Function
- Global registration of named handler functions

## Other Key Functions

### UtopiaApp_MainTick (0x0043b4f0)
- __fastcall, ECX = UtopiaApp (0x0097FA00)
- Does NOT call TGNetwork_Update (that's in simulation pipeline)
- Calls: TimerManager updates, ProcessEvents, subsystem updates, render

### FUN_00504890 - MultiplayerWindow::StartGameHandler
- Entry point for Join/Host button click
- Reads config, calls FUN_00445d90

### Handler Registration Functions
- FUN_005046b0: Registers MultiplayerWindow handlers (Connect, Disconnect, etc.)
- FUN_0069efe0: Registers MultiplayerGame handlers (NewPlayer, Checksum, etc.)
- FUN_006a3560: Registers NetFile::ReceiveMessageHandler

## Key Addresses Quick Reference
| Address | Function | Notes |
|---------|----------|-------|
| 0x00445d90 | InitMultiplayer | Creates WSN+NetFile+GameSpy |
| 0x00504890 | StartGameHandler | UI entry point |
| 0x006a0a30 | NewPlayerHandler | __thiscall on MultiplayerGame |
| 0x006a3820 | ChecksumRequestSender | __thiscall on NetFile |
| 0x006a39b0 | ChecksumRequestBuilder | Individual request |
| 0x006a3cd0 | NetFile::ReceiveMsgHandler | Opcode dispatcher |
| 0x006a4260 | Opcode 0x21 entry | Routes to 006a4560 |
| 0x006a4560 | ChecksumResponseVerifier | Hash compare + next send |
| 0x006a4a00 | ChecksumFail | Event + opcode 0x22/23 |
| 0x006a4bb0 | ChecksumAllPassed | ET_CHECKSUM_COMPLETE |
| 0x006a5df0 | Client: ChecksumHandler | Computes + sends response |
| 0x006a5860 | FileTransferProcessor | File sends or completion |
| 0x006a1b10 | ChecksumCompleteHandler | Sends settings to client |
| 0x006b3ec0 | HostOrJoin | Socket + state setup |
| 0x006B4560 | TGNetwork::Update | __thiscall |
| 0x006b4c10 | TGNetwork::Send | Queues for sending |
| 0x006b55b0 | SendOutgoingPackets | Sends from peer queues |
| 0x006b5c90 | ProcessIncomingPackets | Receives from socket |
| 0x006b5f70 | DispatchIncomingQueue | Sequence validation |
| 0x006b9b20 | CreateUDPSocket | bind + non-blocking |
| 0x006da2c0 | ProcessEvents | __fastcall on EventMgr |
| 0x006db380 | RegisterHandler | Binds handler to event type |
| 0x006a30c0 | NetFile Constructor | Creates hash tables + registers |
| 0x0043b4f0 | MainTick | __fastcall on UtopiaApp |
| 0x0069efe0 | RegisterMPGameHandlers | All MultiplayerGame handlers |
| 0x005046b0 | RegisterMPWindowHandlers | All MultiplayerWindow handlers |
| 0x0071f270 | ComputeChecksum | File hash computation |
| 0x007202e0 | HashString | String/file hashing |
