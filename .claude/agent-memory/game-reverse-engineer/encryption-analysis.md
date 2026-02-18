# TGNetwork Encryption Analysis

## Summary
Byte 0 (sender player ID) is NOT encrypted. Bytes 1+ are encrypted via stream cipher.
SendPacket/ReceivePacket explicitly skip byte 0: encrypt(buffer+1, length-1).

## Cipher Details
- **Type**: Stream cipher with plaintext feedback (not simple XOR -- each byte affects PRNG state)
- **Key**: "AlbyRules!" (hardcoded at 0x0095abb4, 10 bytes)
- **Object**: Allocated 0x58 bytes, vtable at PTR_LAB_008958c0 (destructor only at 0x006b8220)
- **Location**: WSN+0xF0 (int* index 0x3C)
- **Reset**: FUN_006c2280 resets state + copies "AlbyRules!" to this+0x48 (key schedule)
- **PRNG Step**: FUN_006c22f0 (5 rounds of FUN_006c23c0 PRNG), produces this+0x3C output
- **Encrypt**: FUN_006c2490(cipher, buffer, length) -- resets, then per-byte: load plaintext -> PRNG step -> XOR -> modify key state -> store ciphertext
- **Decrypt**: FUN_006c2520(cipher, buffer, length) -- resets, then per-byte: load ciphertext -> PRNG step -> XOR -> modify key state -> store plaintext
- **Feedback**: Key bytes at this+0x48..0x51 are XORed with current byte each iteration, creating cipher-byte-dependent state evolution

## Per-Packet Reset
Both encrypt and decrypt call FUN_006c2280 (reset) as their FIRST operation. This means:
- Each packet starts from the same cipher state
- Same plaintext always produces same ciphertext (no inter-packet state)
- The first PRNG output byte XOR happens to be 0x00 with "AlbyRules!" key

## Encryption Boundary (CONFIRMED from disassembly 2026-02-17)
- SendPacket (0x006b9870): encrypts buffer+1, length-1 -- byte 0 NOT encrypted
- ReceivePacket (0x006b95f0): decrypts buffer+1, length-1 -- byte 0 NOT decrypted
- Byte 0 (player ID) is transmitted in PLAINTEXT on the wire
- See [transport-layer.md](transport-layer.md) for full transport layer analysis

## Wire Format
```
[byte 0: sender player ID]  -- PLAINTEXT (not encrypted, skipped by cipher)
[byte 1: message count]     -- ENCRYPTED
[bytes 2..N: messages]      -- ENCRYPTED (each starting with type byte as factory table index)
```

Note: The first PRNG output byte with "AlbyRules!" key happens to be 0x00, so even
if byte 0 WERE encrypted, XOR with 0x00 = identity. The code explicitly skips it anyway
(encrypt/decrypt called with buffer+1, length-1).

## Plaintext Format (after decrypting bytes 1+)
```
[byte 0: sender player ID] (0x01=server, 0x02=first client, 0xFF=unassigned/-1)
[byte 1: message count] (0x00-0xFF, typically 0x01)
[bytes 2..N: messages, each starting with type byte used as factory table index]
```

## Call Chain

### Send Path
1. `FUN_006b4c10` (TGNetwork::Send) -- queues message to peer's send lists
2. `FUN_006b55b0` (SendOutgoingPackets) -- assembles buffer: byte[0]=playerID, byte[1]=msgCount, byte[2+]=serialized messages
3. vtable[0x70] at 0x006b9870 (TGWinsockNetwork::SendPacket) -- encrypts buffer, calls sendto
4. `sendto()` -- Winsock API

### Receive Path
1. `recvfrom()` -- Winsock API
2. vtable[0x6c] at 0x006b95f0 (TGWinsockNetwork::ReceivePacket) -- calls recvfrom, decrypts buffer
3. `FUN_006b5c90` (ProcessIncomingPackets) -- reads byte[0]=senderID, byte[1]=count, dispatches each message via factory table at 0x009962d4

## Previously Unanalyzed Functions (NOW ANALYZED 2026-02-17)
- 0x006b95f0: TGWinsockNetwork::ReceivePacket -- DISASSEMBLED via objdump, confirmed decrypt(buf+1, len-1)
- 0x006b9870: TGWinsockNetwork::SendPacket -- DISASSEMBLED via objdump, confirmed encrypt(buf+1, len-1)
- 0x006b9e40: TGWinsockNetwork::DisconnectPeer (vtable[0x74]) -- still unanalyzed

## Evidence (packet trace correlation)
Server sends packet #3 (wire): `01 D7 33 68 C3 BF 76 DB` (8 bytes)
Client decodes to messages: [type=0x03, 6 bytes: `03 06 C0 00 00 02`]
Plaintext reconstruction: `01 01 03 06 C0 00 00 02`
XOR at position 0: 0x00 (cipher's initial output)
XOR at position 1: 0xD6 (consistent across packets with same byte 0)

## Vtable Maps

### TGWinsockNetwork vtable (0x008958f0)
| Offset | Address | Function |
|--------|---------|----------|
| 0x00 | 0x006b9c50 | Destructor |
| 0x04 | 0x006b34d0 | (unknown) |
| 0x08 | 0x006b34e0 | (unknown) |
| 0x0C | 0x006f1650 | (from FUN table) |
| 0x10 | 0x006d9100 | (from FUN table) |
| 0x58 | 0x006bac50 | GetOverhead |
| 0x60 | 0x006b9460 | (unknown) |
| 0x64 | 0x006b9560 | (unknown) |
| 0x68 | 0x006b9950 | (unknown) |
| 0x6c | 0x006b95f0 | ReceivePacket (recvfrom + decrypt) |
| 0x70 | 0x006b9870 | SendPacket (encrypt + sendto) |
| 0x74 | 0x006b9e40 | DisconnectPeer |

### Cipher vtable (0x008958c0, only 1 entry)
| Offset | Address | Function |
|--------|---------|----------|
| 0x00 | 0x006b8220 | Destructor |

### SetCipher function
- FUN_006b7090: TGNetwork::SetCipher(cipherObj) -- stores at this+0xF0
- Only works when connection state != 2 and != 3 (must be set before connecting)
