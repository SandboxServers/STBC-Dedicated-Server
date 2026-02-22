> [docs](../README.md) / [protocol](README.md) / python-messages.md

# Python Message Dispatch

Two entirely separate mechanisms exist for sending Python-originated data over the network:

## Mechanism 1: Engine Event Forwarding (opcodes 0x06, 0x0D, 0x07-0x12, 0x1B)

These are C++-level messages that forward engine events. The payload is a serialized TGEvent.

**Opcode 0x06 / 0x0D - Python Event**: `FUN_0069f880` strips the opcode byte, creates a stream
from remaining data, constructs TGEvent via `FUN_006d6200`, posts to the event manager. Both
opcodes route to the same handler.

**Opcodes 0x07-0x0C, 0x0E-0x10, 0x1B - Event Forwarding**: `FUN_0069fda0` forwards engine-level
events (weapon fire state, cloak, warp, subsystem toggle) to all peers. Each opcode maps to a
hardcoded event code. These are NOT user-level Python messages.

## Mechanism 2: TGMessage Script Messages (opcodes 0x2C+)

These are the user-level "script messages" that Python mods create via `TGMessage_Create()` and
send via `SendTGMessage()` or `SendTGMessageToGroup()`. They travel as **standard type 0x32
TGMessage** transport messages on the wire, with the script-defined payload as the message data.

**There is no special C++ dispatcher for these.** They bypass the C++ jump table entirely because
the MultiplayerGame switch only handles opcodes 0x02-0x2A. Instead, ALL type 0x32 TGMessages
arriving from the network are posted as `ET_NETWORK_MESSAGE_EVENT` (event type `0x60001`) to the
engine's event manager. Python handlers registered on this event read the first payload byte
themselves to determine the message type.

## MAX_MESSAGE_TYPES Constant

`MAX_MESSAGE_TYPES = 43` (0x2B), stored as a SWIG constant in the Appc module (registered at
`0x00654f31` in the SWIG init function, value stored at `0x0090b490`).

This constant defines the boundary between C++ game opcodes and Python script message types.
Python scripts define their message types as `MAX_MESSAGE_TYPES + N`:

| Constant | Value | Hex | Module |
|----------|-------|-----|--------|
| MAX_MESSAGE_TYPES | 43 | 0x2B | Appc (SWIG) |
| CHAT_MESSAGE | 44 | 0x2C | MultiplayerMenus |
| TEAM_CHAT_MESSAGE | 45 | 0x2D | MultiplayerMenus |
| MISSION_INIT_MESSAGE | 53 | 0x35 | MissionShared |
| SCORE_CHANGE_MESSAGE | 54 | 0x36 | MissionShared |
| SCORE_MESSAGE | 55 | 0x37 | MissionShared |
| END_GAME_MESSAGE | 56 | 0x38 | MissionShared |
| RESTART_GAME_MESSAGE | 57 | 0x39 | MissionShared |
| SCORE_INIT_MESSAGE | 63 | 0x3F | Mission5 |
| TEAM_SCORE_MESSAGE | 64 | 0x40 | Mission5 |
| TEAM_MESSAGE | 65 | 0x41 | Mission5 |

Mods can use any value >= 43 as their message type byte. Since the byte is written via
`WriteChar(chr(N))`, custom types up to 255 are valid.

## How Python Scripts Create and Send Messages

The canonical pattern (from `MissionShared.py`):

```python
pMessage = App.TGMessage_Create()       # Allocates TGMessage (0x40 bytes)
pMessage.SetGuaranteed(1)               # Sets +0x3A = 1 (reliable delivery)

kStream = App.TGBufferStream()          # Allocates TGBufferStream (0x30 bytes)
kStream.OpenBuffer(256)                 # Allocates 256-byte write buffer

kStream.WriteChar(chr(END_GAME_MESSAGE))  # Writes 0x38 as first byte
kStream.WriteInt(iReason)                 # Writes 4-byte LE int

pMessage.SetDataFromStream(kStream)     # Copies stream bytes into TGMessage

pNetwork.SendTGMessage(0, pMessage)     # Broadcasts to all peers
kStream.CloseBuffer()                   # Frees stream buffer
```

**SetDataFromStream** (`0x006b8a00`): Calls `stream.GetBuffer()` (vtable+0xF4, returns `+0x1C`)
and `stream.GetPos()` (vtable+0xD8, returns `+0x24`), then calls BufferCopy (`FUN_006b84d0`) to
copy exactly the written bytes into the TGMessage's data buffer (`+0x04` ptr, `+0x08` length).
No header or framing is added -- the stream content IS the TGMessage payload.

## TGBufferStream Write Primitives

All writes are **little-endian** (native x86 store instructions).

| Python Method | C++ vtable slot | Size | Format |
|---------------|----------------|------|--------|
| `WriteChar(chr(N))` | +0x54 (`0x006cf730`) | 1 byte | `uint8` |
| `WriteShort(N)` | +0x5C (`0x006cf7f0`) | 2 bytes | `uint16 LE` |
| `WriteInt(N)` | +0x64 (`0x006cf830`) | 4 bytes | `int32 LE` |
| `WriteLong(N)` | +0x6C (`0x006cf870`) | 4 bytes | `int32 LE` (same as WriteInt on Win32) |
| `WriteFloat(N)` | +0x70 (`0x006cf8b0`) | 4 bytes | `float32 LE` (IEEE 754) |
| `WriteBool(N)` | +0x58 (`0x006cf7a0`) | 1 byte | `uint8` (0 or 1) |
| `Write(buf, len)` | +0x14 (`0x006cf2b0`) | N bytes | raw memcpy |
| `WriteCString(s)` | +0x24 (`0x006cf460`) | 2+N bytes | `[uint16 LE strlen] [raw chars, NO null]` |

## SendTGMessage vs SendTGMessageToGroup

**`pNetwork.SendTGMessage(targetID, pMessage)`** (`FUN_006b4c10`, `__thiscall`):
- SWIG format: `"OiO|i"` (self, targetID:int, message:TGMessage*, optional:int)
- `targetID == 0`: **Broadcast** -- iterates all connected peers, copies message for each, sends to all
- `targetID > 0`: **Unicast** -- binary searches peer array by ID, sends to that specific peer
- `targetID == -1`: Special mode using the optional 4th param to locate peer
- Returns 0 on success, error code otherwise

**`pNetwork.SendTGMessageToGroup(groupName, pMessage)`** (`FUN_006b4de0`, `__thiscall`):
- SWIG format: `"OOO"` (self, groupName:string, message:TGMessage*)
- Binary searches the group table (`+0xF4`, sorted by name) for the group string
- Found: calls `FUN_006b4ec0` which iterates group members, sends to each valid peer
- Not found: returns error 0x10

**Built-in Groups** (created by MultiplayerGame constructor, `FUN_0069e590`):
- **"NoMe"** (`0x008e5528`): All connected peers EXCEPT the local player
- **"Forward"** (`0x008d94a0`): Same membership; used for engine event forwarding

## Byte-By-Byte Wire Example: CHAT_MESSAGE

Given this Python code:
```python
pMessage = App.TGMessage_Create()
pMessage.SetGuaranteed(1)
kStream = App.TGBufferStream()
kStream.OpenBuffer(256)
kStream.WriteChar(chr(CHAT_MESSAGE))  # 0x2C
kStream.WriteLong(pNetwork.GetLocalID())  # e.g., 0x00000002
kStream.WriteShort(5)  # string length
kStream.Write("hello", 5)  # raw bytes
pMessage.SetDataFromStream(kStream)
pNetwork.SendTGMessage(pNetwork.GetHostID(), pMessage)
```

The TGMessage payload (at `+0x04`, length `+0x08 = 12`) is:
```
2C 02 00 00 00 05 00 68 65 6C 6C 6F
^^                                      message type (CHAT_MESSAGE = 44)
   ^^ ^^ ^^ ^^                         sender ID (uint32 LE = 2)
               ^^ ^^                    string length (uint16 LE = 5)
                     ^^ ^^ ^^ ^^ ^^    "hello" (raw bytes, no null terminator)
```

This payload is serialized by `TGMessage::WriteToBuffer` (`FUN_006b8340`) into a type 0x32
transport message:
```
32 0F 80 01 00 2C 02 00 00 00 05 00 68 65 6C 6C 6F
^^                                                     transport type (0x32)
   ^^ ^^                                               flags_len (0x800F)
                                                         bits 0-12: 0x0F = 15 (total msg size)
                                                         bit 15: 1 = reliable
         ^^ ^^                                          seq_num (0x0001, reliable sequence #)
               ^^ ^^ ^^ ^^ ^^ ^^ ^^ ^^ ^^ ^^ ^^ ^^  payload (12 bytes)
```

Then in the UDP packet (after AlbyRules! encryption on bytes 1+):
```
01 01 32 0F 80 01 00 2C 02 00 00 00 05 00 68 65 6C 6C 6F
^^                                                           peer_id (0x01 = server)
   ^^                                                        msg_count (1 message)
      ^^ ... (encrypted, but shown decrypted here)           the type 0x32 message
```

## Byte-By-Byte Wire Example: Custom Mod Message (type 205)

Given this mod Python code:
```python
MY_MESSAGE = App.MAX_MESSAGE_TYPES + 162  # = 43 + 162 = 205 = 0xCD
pMessage = App.TGMessage_Create()
pMessage.SetGuaranteed(1)
kStream = App.TGBufferStream()
kStream.OpenBuffer(256)
kStream.WriteChar(chr(MY_MESSAGE))  # 0xCD
kStream.WriteInt(42)
pMessage.SetDataFromStream(kStream)
pNetwork.SendTGMessageToGroup("NoMe", pMessage)
```

TGMessage payload (5 bytes):
```
CD 2A 00 00 00
^^              custom message type (205)
   ^^ ^^ ^^ ^^ int value 42 (uint32 LE)
```

Type 0x32 transport message (10 bytes):
```
32 0A 80 01 00 CD 2A 00 00 00
^^                              transport type
   ^^ ^^                        flags_len: 0x800A (reliable, size=10)
         ^^ ^^                  seq_num: 0x0001
               ^^ ^^ ^^ ^^ ^^  payload (5 bytes)
```

## Receive Side Dispatch

1. `WSN::ReceivePacket` (`FUN_006b95f0`): recvfrom, decrypt bytes 1+ with AlbyRules!
2. `ProcessIncomingMessages` (`FUN_006b5c90`): reads peer_id, msg_count; for each message, reads
   type byte, dispatches through factory table. Type 0x32 calls `FUN_006b83f0` (TGMessage factory)
   which deserializes the flags/length/seq/payload into a TGMessage object.
3. `FUN_006b52b0`: Dequeues completed messages (handles reliable ordering, fragment reassembly)
4. `TGWinsockNetwork::Update` (`FUN_006b4560`): For each dequeued message, creates a
   `TGMessageEvent` (`FUN_006bfe80`, size 0x2C), sets event type to `ET_NETWORK_MESSAGE_EVENT`
   (0x60001), attaches the TGMessage via `FUN_006bff30`, posts to event manager.
5. **C++ handlers** (`MultiplayerGame_ReceiveMessage` at `0x0069f2a0`): Checks `GetType() == 0x32`,
   reads first payload byte, dispatches via switch for opcodes 0x02-0x2A. Opcodes outside this
   range (including all Python script messages 0x2C+) fall through the switch and are ignored.
6. **Python handlers**: Registered via `AddBroadcastPythonFuncHandler(ET_NETWORK_MESSAGE_EVENT, ...)`.
   The handler calls `pEvent.GetMessage().GetBufferStream()` to get a read view, reads the first
   byte as message type, then dispatches based on value.

Multiple handlers can be registered for `ET_NETWORK_MESSAGE_EVENT`. In stock BC:
- `MultiplayerGame::ReceiveMessageHandler` (C++, handles 0x02-0x2A)
- `MultiplayerWindow::ReceiveMessageHandler` (C++, handles 0x00, 0x01, 0x16)
- `NetFile::ReceiveMessageHandler` (C++, handles 0x20-0x27)
- `MissionShared.ProcessMessageHandler` (Python, handles 0x35-0x39)
- `MultiplayerMenus.ProcessMessageHandler` (Python, handles 0x2C-0x2D)
- Mission-specific handlers (Python, handle mission-specific types)

All handlers receive the same event. Each reads the first byte and acts on types it recognizes,
ignoring types meant for other handlers.

## Guaranteed vs Unreliable

`SetGuaranteed(1)` sets `TGMessage+0x3A = 1`, which causes:
- The `reliable` flag (bit 15) to be set in the wire format's `flags_len` field
- A 2-byte sequence number to be included after `flags_len`
- The transport layer to send ACKs (type 0x01) and retransmit on timeout
- The reliable sequence counter (`peer+0xA8` for type 0x32) to be incremented

`SetGuaranteed(0)` (default after `TGMessage_Create`): Message is sent once with no ACK or
retransmit. The `flags_len` has bit 15 = 0 and no sequence number field.

Stock BC scripts **always** call `SetGuaranteed(1)` for script messages. In theory, unreliable
script messages are supported but never used in practice.
