# Transport Message Header Format (2026-02-17)

## CRITICAL CORRECTION: 16-bit flags_len field

The transport message header for data-carrying types (0x00, 0x03, 0x04, 0x05, 0x32) uses
a 16-bit LE field at offset +1, NOT separate u8 totalLen + u8 flags bytes.

### Previous (WRONG) understanding:
```
[type:1][totalLen:1][flags:1][seq_hi:1][seq_lo:1][payload...]
```

### Correct (VERIFIED) format:
```
[type:1][flags_len:2 LE][seq:2 LE][payload...]
```

Where flags_len (16-bit LE) contains:
- bit 15 (0x8000): reliable flag -> msg+0x3A
- bit 14 (0x4000): priority flag -> msg+0x3B
- bits 13-0: total message length INCLUDING the type byte (max 16383)

### Header sizes:
- If flags_len == 0: 3 bytes total (type + 2 zero bytes), payload_len = 0 (shouldn't happen)
- If flags_len != 0: 5 bytes header (type + flags_len + seq), payload_len = (flags_len & 0x3FFF) - 5

### Evidence (4 identical factories decompiled):
- FUN_006bc6a0 (Type 0x00 Keepalive factory) at 11_tgnetwork.c:6584
- FUN_006be860 (Type 0x03 Connect factory) at 11_tgnetwork.c:7008
- FUN_006badb0 (Type 0x04 ConnectData factory) at 11_tgnetwork.c:6183
- FUN_006bf410 (Type 0x05 ConnectAck factory) at 11_tgnetwork.c:7162

All share IDENTICAL code:
```c
uVar1 = *(ushort *)(param_1 + 1);           // 16-bit LE at offset +1
bVar2 = (byte)(uVar1 >> 8);                 // high byte = flags
uVar5 = (uVar1 & 0x3fff) - 3;              // total len - 3 (header without seq)
if (uVar1 != 0) {
    uVar6 = *(undefined2 *)puVar7;           // read 2-byte seq
    puVar7 = (undefined4 *)(param_1 + 5);    // advance past seq
    uVar5 = (uVar1 & 0x3fff) - 5;           // total len - 5 (header with seq)
}
*(byte *)((int)puVar4 + 0x3a) = bVar2 >> 7; // reliable = bit 15
*(byte *)((int)puVar4 + 0x3b) = bVar2 >> 6 & 1; // priority = bit 14
```

### Reinterpretation of observed wire bytes:

**Pattern A** (checksum round 2, flagged fragments):
- Wire: `[32][XX][A1]` -> flags_len LE = 0xA1XX
  - bit 15 = 1 (reliable)
  - bit 13 = 1 (fragment flag, value 0x2000)
  - bit 8 = 1 (more-fragments, value 0x0100)
  - bits 7-0 of low byte = partial length
- Wire: `[32][XX][A0]` -> flags_len LE = 0xA0XX
  - bit 15 = 1 (reliable), bit 13 = 1 (fragment)
  - bit 8 = 0 (last fragment)

**Pattern B** (checksum round 0xFF, large single message):
- Wire: `[32][11][81]` -> flags_len LE = 0x8111
  - bit 15 = 1 (reliable)
  - bits 13-0 = 0x0111 = 273 (total message length)
  - NOT fragmented at all -- just a large message that fits in one packet

### ACK (Type 0x01) - DIFFERENT FORMAT
ACK does NOT use flags_len. It has its own format (from FUN_006bd190 WriteTo):
```
[type:1][seq:2 LE][flags:1]              (4 bytes, no fragment)
[type:1][seq:2 LE][flags:1][frag_idx:1]  (5 bytes, with fragment ack)
```

ACK flags: bit 0 = fragment_flag (+0x3C), bit 1 = unknown (+0x40)

### Fragment payload format (inside the data portion):
When fragment flag is set (bit 13 of flags_len):
```
First fragment:  [total_fragments:u8][inner_payload...]
Subsequent:      [continuation_data...]
```

Note: The fragment_index is stored in the TGMessage object at +0x39 but appears to be
tracked by the reliable delivery layer, not embedded in every fragment's payload.
The WriteTo function for data messages was at 0x006b8340 (not decompilable in Ghidra).

### TGMessage Object Layout (0x40 bytes, from FUN_006b8550 copy ctor):
```
+0x00: vtable ptr
+0x04: data_ptr (payload buffer, allocated by BufferCopy)
+0x08: data_len (payload size)
+0x0C: sender_peer_id
+0x14: seq_number (u16)
+0x18: retransmit_count (int, used by FUN_006b8670)
+0x1C: retransmit_timeout (float)
+0x20: retransmit_timer (float)
+0x24-0x28: unknown (copied in clone)
+0x2C: retransmit_mode (int, 0/1/2)
+0x30: retransmit_base (float)
+0x34: retransmit_increment (float)
+0x38: total_fragments (u8)
+0x39: fragment_index (u8)
+0x3A: reliable_flag (u8)
+0x3B: priority_flag (u8)
+0x3C: fragment_flag (u8)
+0x3D: unknown_flag (u8, set to 1 in ctor)
```

### Message Type Dispatch Table (DAT_009962d4):
```
type 0x00: FUN_006bc6a0 (Keepalive)
type 0x01: LAB_006bd1f0 (ACK) -- not a recognized function
type 0x02: LAB_006bdd10 -- not a recognized function
type 0x03: FUN_006be860 (Connect)
type 0x04: FUN_006badb0 (ConnectData)
type 0x05: FUN_006bf410 (ConnectAck)
type 0x32: LAB_006b83f0 -- not a recognized function (base TGMessage factory)
```

### High-byte flag bits (tentative mapping):
```
bit 7 (0x80 in high byte = 0x8000 in u16): reliable
bit 6 (0x40 in high byte = 0x4000 in u16): priority
bit 5 (0x20 in high byte = 0x2000 in u16): fragment flag
bit 0 (0x01 in high byte = 0x0100 in u16): more-fragments
```

Bits 5 and 0 of the high byte are NOT extracted by the factories into named fields.
They may be handled by the type-0x32 factory specifically, or by the fragment
reassembly path in DispatchIncomingQueue (FUN_006b5f70).

### ProcessIncomingPackets cursor advancement:
After each factory creates a TGMessage, GetSize (vtable+0x14) is called to determine
how many wire bytes to skip. The cursor advances by exactly GetSize bytes.
This means GetSize returns: (flags_len & 0x3FFF) for data messages, or 4-5 for ACK.

### SendOutgoingPackets serialization (FUN_006b55b0):
- Allocates buffer of param_1[0x2b] bytes (= 0x200 = 512)
- Skips first 2 bytes for [direction][msg_count] header
- Iterates 3 queues per peer: priority (+0xB4), reliable (+0x98), unreliable (+0x7C)
- Calls WriteTo (vtable+0x08) on each TGMessage, which returns bytes written
- Sets buf[0]=direction, buf[1]=msg_count
- Sends via vtable+0x70 (UDP sendto)
