> [docs](../README.md) / [networking](README.md) / network-protocol.md

# Network Protocol - Architecture & Debug Reference

## STATUS: CLIENT DISCONNECTS AFTER SHIP SELECTION
Checksums pass, Settings/GameInit/ObjCreateTeam all sent correctly. Client reaches ship
selection screen with ship model visible. Disconnects ~3 sec later due to empty StateUpdate
packets (flags=0x00 instead of flags=0x20 with subsystem data).
See [docs/black-screen-investigation.md](../analysis/black-screen-investigation.md) for current investigation.

## Previously Solved Issues
- **Black screen** (no cursor, no scoreboard): Fixed by NewPlayerInGame handshake in GameLoopTimerProc
- **Checksum stall** (priority queue stuck at 3): Was a misdiagnosis — actually resolved by
  getting the full checksum exchange working correctly
- **First connection timeout**: Still exists (client must reconnect once), not yet investigated

## Complete Checksum Protocol (Fully Traced)

### Server-Side Flow:
1. Client connects -> TGNetwork fires ET_NETWORK_NEW_PLAYER
2. NewPlayerHandler (0x006a0a30) assigns player slot
3. Calls FUN_006a3820 on NetFile (0x0097FA80) to start checksum exchange
4. FUN_006a3820 builds 4 requests, queues ALL in hash table B, sends #0 via TGNetwork::Send
5. Client responds with opcode 0x21
6. NetFile::ReceiveMessageHandler (FUN_006a3cd0) dispatches to FUN_006a4260
7. FUN_006a4260 checks byte[1] != 0xFF (always true), calls FUN_006a4560
8. FUN_006a4560 verifies checksum (server hash vs client hash):
   - Match: dequeues from queue, **sends NEXT via TGNetwork::Send**
   - Mismatch: FUN_006a4a00 fires ET_SYSTEM_CHECKSUM_FAILED, sends opcode 0x22/0x23
9. When queue empty: FUN_006a4bb0 fires ET_CHECKSUM_COMPLETE (type 0x8000e8)
10. ChecksumCompleteHandler (0x006a1b10) sends:
    - Opcode 0x00: [gameTime:f32][settings:2bits][playerSlot:u8][mapNameLen:u16][mapName][passFail:bit]
    - Opcode 0x01: 1-byte status

### Client-Side Flow:
1. Receives opcode 0x20 -> FUN_006a5df0 computes file checksums
2. Sends response: opcode 0x21, [index:u8], [hashes...]
3. If FUN_0071f270 returns 0 (no files found), response NOT sent (silent failure!)
4. Receives opcode 0x00 -> gets player slot, map name, settings
5. Proceeds to game setup/ship selection

### Checksum Requests (4 total):
| # | Directory | Filter | Recursive |
|---|-----------|--------|-----------|
| 0 | scripts/ | App.pyc | No |
| 1 | scripts/ | Autoexec.pyc | No |
| 2 | scripts/ships/ | *.pyc | Yes |
| 3 | scripts/mainmenu/ | *.pyc | No |

Note: `scripts/Custom/` directory is EXEMPT from checksums. `scripts/Local.py` is also exempt.

### Packet Opcodes (Checksum/NetFile):
| Opcode | Direction | Handler | Purpose |
|--------|-----------|---------|---------|
| 0x20 | Server->Client | FUN_006a5df0 | Checksum request |
| 0x21 | Client->Server | FUN_006a4260->006a4560 | Checksum response |
| 0x22 | Server->Client | FUN_006a4c10 | Checksum fail (file mismatch) |
| 0x23 | Server->Client | FUN_006a4c10 | Checksum fail (reference mismatch) |
| 0x25 | Both | FUN_006a5860/FUN_006a3ea0 | File transfer |
| 0x27 | ? | FUN_006a4250 | File transfer ACK |

## Two Message Dispatchers

1. **NetFile dispatcher** (`FUN_006a3cd0` at UtopiaModule+0x80): Handles opcodes 0x20-0x27
   - Registered for event type `0x60001` (ET_NETWORK_MESSAGE_EVENT)
   - Sets `DAT_0097fa8b = 1` during processing

2. **MultiplayerGame dispatcher** (registered as `ReceiveMessageHandler`): Handles game opcodes
   - Forwards to per-opcode handlers based on first byte of payload
   - Jump table at 0x0069F534 (opcode minus 2)

These are SEPARATE dispatchers on SEPARATE objects.

## NetFile Object
**UtopiaModule+0x80 (0x0097FA80) is BOTH the ChecksumManager AND the message dispatcher.**

- Created by FUN_006a30c0 (0x48 bytes) during FUN_00445d90 (Phase 1)
- Registers NetFile::ReceiveMessageHandler for event type 0x60001
- Contains 3 hash tables:
  - A (vtable+0x18, buckets+0x24): Used by FUN_006a4260 for tracking
  - B (vtable+0x28, buckets+0x34): Queued checksum requests (FUN_006a39b0)
  - C (vtable+0x38, buckets+0x44): Pending file transfers (FUN_006a5860)

## Event System Architecture
- EventManager object at 0x0097F838
- Handler registry at EventManager+0x2C = 0x0097F864
- ProcessEvents (FUN_006da2c0) dispatches to handlers via FUN_006db620(this+0x2C, event)
- Handler registration: FUN_006db380(&0x0097F864, event_type, target, name, ...)
- Event posting: FUN_006da2a0(&0x0097F838, event)
- Handler function registration: FUN_006da130(func_ptr, name_string)

## Key Event Types
| Type | Name | Meaning |
|------|------|---------|
| 0x60001 | ET_NETWORK_MESSAGE_EVENT | Incoming network message |
| 0x60002 | (hosting start) | Host session created |
| 0x8000e6 | (checksum result?) | Individual checksum done |
| 0x8000e7 | ET_SYSTEM_CHECKSUM_FAILED | Checksum mismatch |
| 0x8000e8 | ET_CHECKSUM_COMPLETE | All checksums passed |
| 0x8000e9 | ET_KILL_GAME | Game killed |
| 0x8000f6 | ET_BOOT_PLAYER | Anti-cheat kick (subsystem hash mismatch) |
| 0x8000ff | (retry connect) | Connection retry |

## MultiplayerGame Event Handlers (FUN_0069efe0)
| Address | Handler Name |
|---------|-------------|
| 0x0069f2a0 | ReceiveMessageHandler |
| 0x006a0a20 | DisconnectHandler |
| 0x006a0a30 | NewPlayerHandler |
| 0x006a0c60 | SystemChecksumPassedHandler |
| 0x006a0c90 | SystemChecksumFailedHandler |
| 0x006a0ca0 | DeletePlayerHandler |
| 0x006a0f90 | ObjectCreatedHandler |
| 0x006a1150 | HostEventHandler |
| 0x006a1590 | NewPlayerInGameHandler |
| 0x006a1790 | StartFiringHandler |
| 0x006a1930 | ClientEventHandler |
| 0x006a1b10 | ChecksumCompleteHandler |
| 0x006a2640 | KillGameHandler |
| 0x006a2a40 | RetryConnectHandler |
| 0x006a07d0 | EnterSetHandler |

## MultiplayerWindow Event Handlers (FUN_005046b0)
| Address | Handler Name |
|---------|-------------|
| 0x00504890 | StartGameHandler |
| 0x00504c10 | ReceiveMessageHandler |
| 0x00505040 | ConnectHandler |
| 0x00505110 | DisconnectHandler |
| 0x00505d70 | SetMissionNameHandler |
| 0x00505e00 | RefreshServerListHandler |
| 0x00506200 | SelectServerHandler |
| 0x00506a50 | SortServerListHandler |
| 0x00506170 | BootPlayerHandler |

## TGNetwork::Update Internal Flow (0x006B4560)
Three core sub-functions called unconditionally:
1. FUN_006b55b0 - SendOutgoingPackets (checks WSN+0x10C flag, iterates peers)
2. FUN_006b5c90 - ProcessIncomingPackets (recv from socket, deserialize)
3. FUN_006b5f70 - DispatchIncomingQueue (validate sequences, deliver)
For host state 2: dequeue loop at 0x006b4779 fires ET_NETWORK_MESSAGE_EVENT (0x60001).

## Peek-Based UDP Router (Working)
Located in GameLoopTimerProc. Solves the shared socket problem:
- GameSpy and TGNetwork share the SAME UDP socket (WSN+0x194)
- Router uses MSG_PEEK + select() to check first byte without consuming
- '\'-prefixed packets -> qr_handle_query (0x006ac1e0) for GameSpy
- Binary packets -> left in socket buffer for TGNetwork_Update
- qr_t+0xE4 set to 0 to disable GameSpy's own recvfrom loop

## Normal Game Initialization (FUN_00445d90)
Called as __thiscall on UtopiaModule (0x0097FA00):
1. Creates TGWinsockNetwork (0x34C bytes) -> stored at +0x78 (0x0097FA78)
2. FUN_006b9bb0 sets port on WSN (+0x338 = port)
3. TGNetwork_HostOrJoin (0x006b3ec0) creates socket, sets state
4. Creates NetFile (0x48 bytes) via FUN_006a30c0 -> stored at +0x80 (0x0097FA80)
5. Creates GameSpy (0xF4 bytes) -> stored at +0x7C (0x0097FA7C)
Our Phase 1 calls this function correctly with (this=0x0097FA00, addr=0, pw=empty, port=0x5655).

## IAT Hooks (Currently Installed)
- sendto: HookedSendto logs outbound packets with hex dump
- recvfrom: HookedRecvfrom logs inbound packets (non-PEEK only)
- Both hooked via PatchIATEntry in HookGameIAT

## Peer Send Queue Monitoring
After MainTick: checks peer+0x7C (unreliable), +0x98 (reliable), +0xB4 (priority reliable)
Only logs when queue sizes change. Also in periodic 10-second status log.
