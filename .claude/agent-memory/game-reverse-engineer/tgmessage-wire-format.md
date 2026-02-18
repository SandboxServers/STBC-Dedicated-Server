# TGMessage Script Message Wire Format (2026-02-17)

## Summary

Python script messages (CHAT, SCORE, END_GAME, etc.) are sent as standard type 0x32 TGMessage
transport messages. The Python script's payload (from TGBufferStream) IS the TGMessage data with
NO additional C++ header. The first byte of the payload is the message type, written by the script.

## Key Constants

- MAX_MESSAGE_TYPES = 43 (0x2B), at 0x0090b490, registered at 0x00654f31
- ET_NETWORK_MESSAGE_EVENT = 0x60001 (event type for all incoming TGMessages)

## Message Type Table

| Name | Value | Hex | Defined In |
|------|-------|-----|------------|
| MAX_MESSAGE_TYPES | 43 | 0x2B | Appc SWIG constant |
| CHAT_MESSAGE | 44 | 0x2C | MultiplayerMenus.py |
| TEAM_CHAT_MESSAGE | 45 | 0x2D | MultiplayerMenus.py |
| (gap: 46-52 unused) | | | |
| MISSION_INIT_MESSAGE | 53 | 0x35 | MissionShared.py |
| SCORE_CHANGE_MESSAGE | 54 | 0x36 | MissionShared.py |
| SCORE_MESSAGE | 55 | 0x37 | MissionShared.py |
| END_GAME_MESSAGE | 56 | 0x38 | MissionShared.py |
| RESTART_GAME_MESSAGE | 57 | 0x39 | MissionShared.py |
| (gap: 58-62 unused) | | | |
| SCORE_INIT_MESSAGE | 63 | 0x3F | Mission5.py |
| TEAM_SCORE_MESSAGE | 64 | 0x40 | Mission5.py |
| TEAM_MESSAGE | 65 | 0x41 | Mission5.py |

## Key Functions

| Address | Name | Signature | Role |
|---------|------|-----------|------|
| 0x006b82a0 | TGMessage ctor | __fastcall(this) | Inits 0x40-byte object, vtable=0x008958d0 |
| 0x006b9430 | TGMessage::GetType | __thiscall(this) -> int | Returns 0x32 always |
| 0x006b8340 | TGMessage::WriteToBuffer | __thiscall(this, buf, buflen) | Serialize to wire |
| 0x006b83f0 | TGMessage::ReadFromBuffer | static(buf) -> TGMessage* | Deserialize from wire |
| 0x006b8640 | TGMessage::GetBufferSpaceRequired | __thiscall(this) -> int | 3 + [2 if reliable] + [1-2 if frag] + data_len |
| 0x006b8530 | TGMessage::GetData | __thiscall(this, &len) -> ptr | Returns +0x04, writes len to param |
| 0x006b89e0 | TGMessage::GetBufferStream | __thiscall(this) -> stream* | Singleton at 0x996810 |
| 0x006b8a00 | TGMessage::SetDataFromStream | __thiscall(this, stream) | Copies stream buf/pos to msg |
| 0x006b84d0 | TGMessage::BufferCopy | __thiscall(this, srcPtr, srcLen) | Alloc+memcpy into +0x04/+0x08 |
| 0x006b4c10 | WSN::SendTGMessage | __thiscall(this, targetID, msg, opt) | 0=broadcast, >0=unicast, -1=by-opt |
| 0x006b4de0 | WSN::SendTGMessageToGroup | __thiscall(this, name, msg) | Binary search group table |
| 0x006b4ec0 | WSN::SendToGroupMembers | __thiscall(this, group, msg) | Iterates group peers |
| 0x006b5080 | WSN::SendHelper | __thiscall(this, msg, peer) | Queue to peer, manage seq counters |
| 0x006b4560 | WSN::Update | __fastcall(this) | Main loop: recv, send, post events |
| 0x006b52b0 | WSN::GetNextReceivedMsg | __thiscall(this, flag) -> msg* | Dequeue with ordering |
| 0x006b70d0 | WSN::AddGroup | __thiscall(this, group) | Register named group |
| 0x0069e590 | MultiplayerGame ctor | Creates "NoMe"/"Forward" groups, registers event handlers |
| 0x006bfe80 | TGMessageEvent ctor | Size 0x2C; event+0x28=TGMessage* |

## TGMessage Object Layout (+0x00 to +0x3F, total 0x40)

| Offset | Size | Field | Init Value |
|--------|------|-------|-----------|
| +0x00 | 4 | vtable | 0x008958d0 |
| +0x04 | 4 | data_ptr | NULL |
| +0x08 | 4 | data_length | 0 |
| +0x0C | 4 | from_id | 0 |
| +0x10 | 4 | field_10 | 0 |
| +0x14 | 2 | sequence_number | 0 |
| +0x18 | 4 | field_18 | 0 |
| +0x1C | 4 | first_resend_time | 0 |
| +0x20 | 4 | first_send_time | 0 |
| +0x24 | 4 | timestamp | 0 |
| +0x28 | 4 | to_id | 0 |
| +0x2C | 4 | num_retries | 0 (init by ctor) |
| +0x30 | 4 | backoff_time | 1.0 (0x3F800000) |
| +0x34 | 4 | backoff_factor | 1.0 (0x3F800000) |
| +0x38 | 1 | total_fragments | 0 |
| +0x39 | 1 | fragment_index | 0 |
| +0x3A | 1 | is_guaranteed | 0 (SetGuaranteed changes) |
| +0x3B | 1 | is_high_priority | 0 (SetHighPriority changes) |
| +0x3C | 1 | is_fragment | 0 |
| +0x3D | 1 | override_old | 1 (init by ctor) |
| +0x3E | 1 | is_multipart | 0 |
| +0x3F | 1 | is_aggregate | 0 |

## TGMessage Vtable (0x008958d0, 10 slots)

| Slot | Offset | Address | Method |
|------|--------|---------|--------|
| 0 | +0x00 | 0x006b9430 | GetType() -> 0x32 |
| 1 | +0x04 | 0x006b82f0 | Release(flag) |
| 2 | +0x08 | 0x006b8340 | WriteToBuffer(buf, buflen) -> bytes_written |
| 3 | +0x0C | 0x006b9440 | Merge(other) -> false (stub) |
| 4 | +0x10 | 0x006b9450 | IsAggregate() -> false (stub) |
| 5 | +0x14 | 0x006b8640 | GetBufferSpaceRequired() |
| 6 | +0x18 | 0x006b8610 | Clone() |
| 7 | +0x1C | 0x006b8720 | FragmentMessage(max_size) |
| 8 | +0x20 | 0x006b9c50 | ReadyToResend? |
| 9 | +0x24 | 0x006b34d0 | BreakUpMessage? |

## TGBufferStream Vtable (0x00895c58, 66 slots)

Key write methods (used by Python scripts):

| Slot | Offset | Address | Method | Size |
|------|--------|---------|--------|------|
| 5 | +0x14 | 0x006cf2b0 | Write(buf, len) | N bytes (raw memcpy) |
| 9 | +0x24 | 0x006cf460 | WriteCString(str) | 2+N bytes (u16 len + chars, no null) |
| 21 | +0x54 | 0x006cf730 | WriteChar(c) | 1 byte |
| 23 | +0x5C | 0x006cf7f0 | WriteShort(n) | 2 bytes LE |
| 25 | +0x64 | 0x006cf830 | WriteInt(n) | 4 bytes LE |
| 27 | +0x6C | 0x006cf870 | WriteLong(n) | 4 bytes LE (same as WriteInt on Win32) |
| 28 | +0x70 | 0x006cf8b0 | WriteFloat(f) | 4 bytes LE IEEE754 |

Key read methods (used by Python handlers):

| Slot | Offset | Address | Method | Size |
|------|--------|---------|--------|------|
| 4 | +0x10 | 0x006cf230 | Read(buf, len) | N bytes |
| 8 | +0x20 | 0x006cf410 | ReadCString() | 2+N bytes |
| 20 | +0x50 | 0x006cf540 | ReadChar() | 1 byte |
| 22 | +0x58 | 0x006cf600 | ReadWChar() | 2 bytes |
| 24 | +0x60 | 0x006cf640 | ReadShort() | 2 bytes LE |
| 26 | +0x68 | 0x006cf670 | ReadInt() | 4 bytes LE |
| 54 | +0xD8 | 0x006cf9b0 | GetPos() | returns current offset |
| 61 | +0xF4 | 0x006cf0c0 | GetBuffer() | returns buffer pointer |

TGBufferStream object layout:
- +0x00: vtable (0x00895c58)
- +0x04: error state ptr
- +0x1C: buffer pointer (set by OpenBuffer)
- +0x20: buffer capacity
- +0x24: current read/write position

## Wire Format Layers (for a guaranteed script message)

```
Layer 1: UDP packet
  [peer_id:u8] [msg_count:u8] [encrypted transport messages...]

Layer 2: Type 0x32 transport message (after decryption)
  [0x32] [flags_len:u16 LE] [seq_num:u16 LE if reliable] [payload...]

Layer 3: TGMessage payload (the script's data)
  [msg_type:u8] [app-specific fields...]
```

No additional framing between layers. The script's WriteChar/WriteInt/etc output
IS the Layer 3 payload, which IS the TGMessage data, which IS the type 0x32 payload.

## Groups

- "NoMe" at 0x008e5528: all peers except self (used by script messages)
- "Forward" at 0x008d94a0: same membership (used by engine event forwarding)
- Both created by MultiplayerGame ctor (FUN_0069e590) via WSN::AddGroup
- Group table at WSN+0xF4, sorted array, binary searched by name
