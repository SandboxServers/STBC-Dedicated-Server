# TGNetwork Transport Layer (2026-02-17)

## Factory Table at DAT_009962d4

256-slot function pointer table. 7 slots populated:

| Slot | Class | Factory Fn | GetType() | Role |
|------|-------|-----------|-----------|------|
| 0x00 | TGDataMessage | FUN_006bc6a0 | 0 (0x006bd100) | Control data, 14-bit length, NO fragments |
| 0x01 | TGHeaderMessage | FUN_006bd1f0 | 1 | ACK/NACK for reliable delivery |
| 0x02 | TGConnectMessage | FUN_006bdd10 | 2 | Connection request |
| 0x03 | TGConnectAckMsg | FUN_006be860 | 3 | Connection acknowledgment |
| 0x04 | TGBootMessage | FUN_006badb0 | 4 | Peer kick notification |
| 0x05 | TGDisconnectMsg | FUN_006bf410 | 5 | Graceful disconnect |
| 0x32 | TGMessage (base) | FUN_006b83f0 | 0x32 (0x006b9430) | **ALL game payloads**, 13-bit length, fragment support |

Registration: FUN_006b8290 writes FUN_006b83f0 to DAT_0099639C (= 0x009962d4 + 0x32*4).

## Wire Format: Type 0x32 (TGMessage base -- game data)

```
[type: 0x32]
[flags_len: u16 LE]    bits 12-0 = total length (13-bit, max 8191)
                        bit 13   = fragment flag
                        bit 14   = ordered
                        bit 15   = reliable
[if reliable:]
  [seq_num: u16 LE]    reliable sequence number
[if fragmented:]
  [frag_idx: u8]       fragment index (0-based)
  [if frag_idx == 0:]
    [total_frags: u8]  total number of fragments
[payload bytes...]
```

Serializer: FUN_006b8340 (TGMessage::WriteToBuffer)
Deserializer: FUN_006b83f0 (factory)
Size calculator: FUN_006b8640 (TGMessage::GetSize)

## Wire Format: Type 0x00 (TGDataMessage -- control data)

```
[type: 0x00]
[flags_len: u16 LE]    bits 13-0 = total length (14-bit, max 16383)
                        bit 14   = ordered
                        bit 15   = reliable
[if reliable:]
  [seq_num: u16 LE]    reliable sequence number
[payload bytes...]     (NO fragment support)
```

Serializer: FUN_006bc610 (TGDataMessage::WriteToBuffer)
Deserializer: FUN_006bc6a0 (factory)

## Wire Format: Type 0x01 (TGHeaderMessage -- ACK)

```
[type: 0x01]
[ack_seq: u16 LE]      sequence number being acknowledged
[frag_ack: varies]     fragment acknowledgment (if applicable)
```

## Dual Sequence Counters

FUN_006b5080 (send helper) maintains TWO reliable sequence counters per peer:
- **peer+0x98**: for message types < 0x32
- **peer+0xA8**: for message types >= 0x32

This means game data (type 0x32) and control data (types 0x00-0x05) have independent sequence spaces.

## Fragment Reassembly

Fragmenter: FUN_006b8720 splits large TGMessages into type-0x32 fragments.
Reassembler: FUN_006b6cc0 collects fragments and reassembles when all indices 0..total-1 received.

**There is NO "more fragments" bit.** Last fragment is detected when all fragments (0 through total_frags-1) have been collected. Previous docs incorrectly stated bit 0x01 in the flags byte was "more fragments" -- it is actually bit 8 of the 13-bit length field.

## TGMessage Object Layout (base class, type 0x32)

| Offset | Type | Field |
|--------|------|-------|
| +0x00 | void** | vtable (0x008955e0 for base) |
| +0x04 | u8 | type (0x32) |
| +0x08 | u16 | flags_len (reliable, ordered, fragment, length) |
| +0x0C | u8* | data pointer (payload bytes) |
| +0x10 | u16 | reliable sequence number |
| +0x14 | u8 | fragment_index |
| +0x15 | u8 | total_fragments |
| +0x18 | int | reassembly state |
| +0x24 | int | some flag/state |

## TGMessage Vtable (0x008955e0)

| Slot | Offset | Address | Method |
|------|--------|---------|--------|
| 0 | +0x00 | 0x006b86f0 | Destructor |
| 1 | +0x04 | 0x006b9430 | GetType (returns 0x32) |
| 2 | +0x08 | 0x006b8340 | WriteToBuffer |
| 3 | +0x0C | 0x006b83f0 | ReadFromBuffer (factory) |
| 4 | +0x10 | 0x006b8450 | (unknown) |
| 5 | +0x14 | 0x006b8640 | GetSize |
| 6 | +0x18 | 0x006b8460 | GetData |
| 7 | +0x1C | 0x006b84d0 | CopyBuffer |

## Encryption Boundary (CRITICAL)

SendPacket (0x006b9870): encrypts buffer+1 with length-1. Byte 0 is NOT encrypted.
ReceivePacket (0x006b95f0): decrypts buffer+1 with length-1. Byte 0 is NOT decrypted.

However: the first PRNG output byte with the "AlbyRules!" key happens to be 0x00, so XOR with 0x00 = identity. Byte 0 appears unchanged whether encrypted or not. The code explicitly skips it anyway.

## Packet Envelope (after decryption)

```
[byte 0: sender player ID]  (NOT encrypted -- skipped by cipher)
[byte 1: message count]     (encrypted, 0x01 typical)
[bytes 2+: messages]         (encrypted, each starts with type byte as factory index)
```

## Key Functions

| Address | Name | Role |
|---------|------|------|
| 0x006b5c90 | ProcessIncomingMessages | Main receive loop: reads playerID, count, dispatches via factory |
| 0x006b55b0 | SendOutgoingPackets | Assembles buffer: playerID + count + serialized messages |
| 0x006b5080 | SendHelper | Routes to reliable or unreliable path, manages seq counters |
| 0x006b8720 | FragmentMessage | Splits large TGMessage into type-0x32 fragments |
| 0x006b6cc0 | ReassembleFragment | Collects fragments, returns complete message when all received |
| 0x006b9870 | WSN::SendPacket | Encrypts buffer+1, calls sendto |
| 0x006b95f0 | WSN::ReceivePacket | Calls recvfrom, decrypts buffer+1 |
| 0x006b83f0 | TGMessage::ReadFromBuffer | Type 0x32 factory/deserializer |
| 0x006b8340 | TGMessage::WriteToBuffer | Type 0x32 serializer |
| 0x006bc6a0 | TGDataMessage::ReadFromBuffer | Type 0x00 factory/deserializer |
| 0x006bc610 | TGDataMessage::WriteToBuffer | Type 0x00 serializer |
| 0x006b8290 | RegisterType0x32 | Writes factory fn to DAT_0099639C |
| 0x006c2490 | Encrypt | Cipher: plaintext feedback stream cipher |
| 0x006c2520 | Decrypt | Cipher: ciphertext-to-plaintext recovery |
| 0x006c2280 | CipherReset | Resets cipher state (called per-packet) |
