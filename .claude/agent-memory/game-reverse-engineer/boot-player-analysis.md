# TGBootPlayerMessage (type=0x04) Sub-command Analysis

## Message Type: TGBootPlayerMessage
- Network message type = 0x04
- Constructor: FUN_006bac70 (allocates 0x44 bytes)
- Sub-command stored at offset 0x40 in message object (piVar[0x10] in decompiled code)
- SWIG name: TGBootPlayerMessage, with Get/SetBootReason accessors
- Python constant: App.TGMESSAGE_BOOT_PLAYER

## Sub-command Values (Boot Reasons)
| Value | Meaning | Sender Function | Address |
|-------|---------|----------------|---------|
| 1 | Timeout disconnect | FUN_006b4560 (connection timeout) + RetryConnectHandler path2 | 0x006b486b, 0x006a2b0c |
| 2 | Password/bandwidth reject | FUN_006b6640 (connection validation) | 0x006b694e |
| 3 | Server full | FUN_006a0a30 (NewPlayerHandler) | 0x006a0c04 |
| 4 | **Kicked by host** | BootPlayerHandler (0x00506170) | 0x005061cd |
| 5 | Connection accepted | FUN_006b6640 (connection validation) | 0x006b66cc |

## BootPlayerHandler (0x00506170) - THE sub-command 4 sender
- Full name: MultiplayerWindow::BootPlayerHandler
- Registered for event ET_BOOT_PLAYER (0x8000f6)
- Event registration: FUN_006d92b0(&DAT_009872e0, &DAT_008000f6, handler_name)
- Part of MultiplayerWindow class (UI)

### Key Logic:
1. Check IsMultiplayer (0x0097FA8A) - exit if not MP
2. Get TGWinsockNetwork* from 0x0097FA78 - exit if NULL
3. Get playerSlot from event->data[0x28] - exit if == local player ID
4. Allocate TGBootPlayerMessage (0x44 bytes)
5. Set boot reason = 4 at [msg+0x40]
6. Set payload = 1 byte (player slot to boot)
7. SendMessage(targetSlot=0, message, flags=0) -- broadcast to all
8. Call next handler

### What Fires ET_BOOT_PLAYER (0x8000f6):
ONLY ONE SOURCE: FUN_005b21c0 (ship network state update receiver)
- This is the cheat detection in the 0x1C state update handler
- Checks: if IsMultiplayer AND checksum(subsystems) doesn't match
- FUN_005b5eb0 computes a hash over all ship subsystem states
- If received hash != computed hash, fires ET_BOOT_PLAYER event
- The event carries the offending player's slot in its data

## RetryConnectHandler (0x006a2a40) - sends sub-command 1
- Full name: MultiplayerGame::RetryConnectHandler
- Registered for event ET_RETRY_CONNECT (0x8000ff)
- Two paths:
  - retryCount < 45: reschedule timer, no network message
  - retryCount >= 45: give up, send TGBootPlayerMessage with reason=1 (timeout)

## Implications for Headless Server
- BootPlayerHandler is a MultiplayerWindow method (UI class)
- On headless server, MultiplayerWindow should NOT exist
- BUT: the event system still dispatches registered handlers
- If FUN_005b21c0 runs on server and detects checksum mismatch,
  it posts ET_BOOT_PLAYER, which triggers BootPlayerHandler
- The server has no ship objects -> subsystem hash = 0
- Client sends valid subsystem hash from its ship
- 0 != client_hash -> CHEAT DETECTION FALSE POSITIVE -> BOOT!

## Packet Format (observed)
`04 07 C0 02 00 04 02`
- 04 = message type (TGBootPlayerMessage)
- 07 C0 = header LE: 0xC007 (flags=3, size=7)
- 02 00 = connection/source ID
- 04 = boot reason (sub-command 4 = kicked)
- 02 = payload: player slot being booted
