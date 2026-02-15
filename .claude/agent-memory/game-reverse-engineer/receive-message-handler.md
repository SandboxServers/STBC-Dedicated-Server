# MultiplayerGame::ReceiveMessageHandler (0x0069f2a0) - Full Disassembly Analysis

## Status: COMPLETE (2026-02-14)

## Summary
Address 0x0069f2a0 is NOT a Ghidra-defined function (registered as LAB_0069f2a0 via FUN_006da130).
Full analysis obtained via raw binary disassembly with objdump.

## Key Findings

### 1. Range Check: YES, there is a strict range check
- First check (0x69f2ce): `cmp eax, 0x32` - verifies stream type == 0x32 (reliable). Non-reliable messages are SILENTLY DROPPED.
- Second check (0x69f2e6): `cmp eax, 0x28 / ja default` - opcode must be 0x02..0x2A (unsigned). Out of range -> default case.
- The opcode is adjusted by -2 before the check (`add eax, -2` at 0x69f2e3).

### 2. Default Case (0x69f525): DOES NOTHING
```asm
69f525: mov BYTE [0x0097fa8b], 0   ; clear "processing message" flag
69f52c: pop esi
69f52d: pop edi
69f52e: ret 4
```
- No relay. No forwarding. No event posting. Just clears the flag and returns.
- Opcode 0x2C (chat) falls into this default case. The C++ dispatcher IGNORES it.

### 3. No C++ Auto-Relay for Unknown Opcodes
The C++ ReceiveMessageHandler does NOT forward unknown opcodes. It only handles 0x02-0x2A.
Chat relay is handled ENTIRELY in Python (MultiplayerMenus.ProcessMessageHandler on stock, ChatRelayHandler on dedicated).

### 4. Global Flag at 0x0097fa8b
- Set to 1 at entry (0x69f2be), cleared to 0 at every exit point
- Meaning: "currently processing a network message" - used as a reentrancy guard

### 5. Event Broadcast Architecture
Multiple handlers receive ET_NETWORK_MESSAGE_EVENT (0x60001) independently:
- C++ MultiplayerGame::ReceiveMessageHandler (0x0069f2a0) - handles 0x02-0x2A
- C++ NetFile::ReceiveMessageHandler - handles 0x20-0x27 (checksums/file transfer)
- C++ ChatObjectClass::ReceiveMessageHandler (0x00461550) - CLIENT-SIDE display only, no relay
- Python MissionShared.ProcessMessageHandler - handles END_GAME_MESSAGE
- Python Mission1.ProcessMessageHandler - handles MISSION_INIT, SCORE messages
- Python MultiplayerMenus.ProcessMessageHandler (stock) / ChatRelayHandler (dedicated) - chat relay

## Jump Table (0x0069f534, 41 entries)
Opcodes with `** DEFAULT **` go to 0x0069f525 (no-op):

| Opcode | Address | Handler Function |
|--------|---------|-----------------|
| 0x02 | 0x0069F31E | FUN_0069f620(stream, 0) - ObjCreate |
| 0x03 | 0x0069F334 | FUN_0069f620(stream, 1) - ObjCreateTeam |
| 0x04 | DEFAULT | (unused) |
| 0x05 | DEFAULT | (unused) |
| 0x06 | 0x0069F3F1 | FUN_0069f880 - PythonEvent |
| 0x07 | 0x0069F34A | FUN_0069fda0(stream, 0x8000d7) - EventForward(StartFiring) |
| 0x08 | 0x0069F363 | FUN_0069fda0(stream, 0x8000d9) - EventForward(StopFiring) |
| 0x09 | 0x0069F37C | FUN_0069fda0(stream, 0x8000db) - EventForward(StopFiringAtTarget) |
| 0x0A | 0x0069F395 | FUN_0069fda0(stream, 0x80006c) - EventForward(SubsysStatus) |
| 0x0B | 0x0069F3AE | FUN_0069fda0(stream, 0x8000df) - EventForward |
| 0x0C | 0x0069F3C7 | FUN_0069fda0(stream, 0) - EventForward(generic) |
| 0x0D | 0x0069F3F1 | FUN_0069f880 - PythonEvent (same as 0x06) |
| 0x0E | 0x0069F405 | FUN_0069fda0(stream, 0x8000e3) - EventForward(StartCloak) |
| 0x0F | 0x0069F41E | FUN_0069fda0(stream, 0x8000e5) - EventForward(StopCloak) |
| 0x10 | 0x0069F437 | FUN_0069fda0(stream, 0x8000ed) - EventForward(StartWarp) |
| 0x11 | 0x0069F3C7 | FUN_0069fda0(stream, 0) - EventForward(generic) |
| 0x12 | 0x0069F3C7 | FUN_0069fda0(stream, 0) - EventForward(generic) |
| 0x13 | 0x0069F2F6 | FUN_006a01b0 - HostMsg |
| 0x14 | 0x0069F47D | FUN_006a01e0 - DestroyObj |
| 0x15 | 0x0069F491 | FUN_006a2470 - Unknown_15 |
| 0x16 | DEFAULT | (unused) |
| 0x17 | 0x0069F4A5 | FUN_006a1360 - RequestReplication |
| 0x18 | 0x0069F4B9 | FUN_006a1420 - SendReplication |
| 0x19 | 0x0069F4CD | FUN_0069f930 - TorpedoFire |
| 0x1A | 0x0069F4E1 | FUN_0069fbb0 - BeamFire |
| 0x1B | 0x0069F450 | FUN_0069fda0(stream, 0x8000fd) - EventForward(TorpTypeChange) |
| 0x1C | 0x0069F3DD | FUN_0069ff50 - StateUpdate |
| 0x1D | 0x0069F4F5 | FUN_006a0490 - ObjNotFound |
| 0x1E | 0x0069F51D | FUN_006a02a0 - RequestObj |
| 0x1F | 0x0069F509 | FUN_006a05e0 - EnterSet |
| 0x20-0x28 | DEFAULT | (handled by NetFile dispatcher, not here) |
| 0x29 | 0x0069F469 | FUN_006a0080 - Explosion |
| 0x2A | 0x0069F30A | FUN_006a1e70 - NewPlayerInGame |

## FUN_0069fda0 - Event Forwarding (used by opcodes 0x07-0x0C, 0x0E-0x10, 0x1B)
- Looks up "Forward" group in network player list (this+0xf4)
- Calls FUN_006b4ec0 to send message to "Forward" group (all other players)
- If sender != host, also re-posts message as local event via FUN_006da300
- This is C++ auto-relay but ONLY for opcodes that use this handler
