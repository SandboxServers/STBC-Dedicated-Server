# Checksum Protocol Analysis (2026-02-17)

## Wire Format: ChecksumReq (opcode 0x20)

Built by `FUN_006a39b0` (SendChecksumRequest), `__thiscall` on NetFile object.

### Stream primitives:
- `FUN_006cf730(stream, byte)` = WriteByte
- `FUN_006cf7f0(stream, ushort)` = WriteShort (LE)
- `FUN_006cf2b0(stream, data, len)` = WriteRawBytes
- `FUN_006cf770(stream, bool)` = WriteBit (bit-packed byte, up to 5 bits per byte)
- `FUN_006cf870(stream, int32)` = WriteInt32

### Packet layout written by FUN_006a39b0:
```
WriteByte(0x20)         // opcode
WriteByte(roundIndex)   // 0-3 for normal rounds, 0xFF for Multiplayer round
WriteShort(strlen(dir)) // directory string length (NOT including NUL)
WriteRawBytes(dir, strlen(dir)) // directory string (NO trailing NUL)
if filter != NULL:
    WriteShort(strlen(filter))
    WriteRawBytes(filter, strlen(filter))
else:
    WriteShort(0)       // zero-length filter = scan all
WriteBit(recursive)     // 0=non-recursive, 1=recursive
```

### CRITICAL: WriteBit encoding (FUN_006cf770)
The bit packer uses a SINGLE BYTE to hold up to 5 boolean values:
- Bits [4:0] = packed bit values (bit N at position N)
- Bits [7:5] = count of bits packed so far (1-4; when count reaches 5, byte is flushed)

For the FIRST bit written to a fresh byte:
- count = 0 (fresh), so allocates a new byte position
- Sets `stream+0x2c = 1` (bit mask for next bit)
- If value=true: byte |= 1 (bit 0 set)
- If value=false: byte stays 0
- Then count incremented: bits[7:5] = 1 (= 0x20)

Result for a single WriteBit(0): byte = `0x20` (count=1, no bits set)
Result for a single WriteBit(1): byte = `0x21` (count=1, bit 0 set)

### Stock server round table (FUN_006a3820 at 0x006a3926):
```c
struct { char *filter; char *dir; char recursive; } rounds[4] = {
    { "App.pyc",       "scripts/",       0 },  // round 0
    { "Autoexec.pyc",  "scripts/",       0 },  // round 1
    { "*.pyc",         "scripts/ships",  1 },  // round 2
    { "*.pyc",         "scripts/mainmenu", 0 }, // round 3
};
```

String addresses:
- 0x0095a3e4 = "App.pyc"
- 0x0095a3d4 = "Autoexec.pyc"
- 0x0095a328 = "*.pyc"
- 0x008dc630 = "scripts/"
- 0x0095a3c4 = "scripts/ships"
- 0x0095a3b0 = "scripts/mainmenu"

### CRITICAL: FUN_0071f890 (NormalizePath)
Called on the directory string BEFORE file scanning:
1. Replaces all `\` with `/`
2. Strips trailing `\r` or `\n`
3. **Strips trailing `/`**

So `"scripts/"` becomes `"scripts"` before use.

### FUN_0071f8e0 (BuildSearchPath)
Concatenates: `dir + DAT_008daca0 + filter`
DAT_008daca0 = "/" (path separator)
If filter==NULL, uses DAT_0095c884 = "*.*" (wildcard all)

Result for round 2: `"scripts/ships" + "/" + "*.pyc"` = `"scripts/ships/*.pyc"`

### Stock server wire bytes for round 2:
```
20                      // opcode 0x20
02                      // round index 2
0D 00                   // dirLen=13 (LE short)
73 63 72 69 70 74 73 2F 73 68 69 70 73  // "scripts/ships" (13 bytes)
05 00                   // filterLen=5 (LE short)
2A 2E 70 79 63          // "*.pyc" (5 bytes)
21                      // bitByte: recursive=1, count=1 -> 0x21
```

NOTE: The directory string "scripts/ships" has NO trailing separator.
The stock server sends the string as-is from the data section.
FUN_0071f890 normalizes it on the CLIENT side before use.

### 0xFF Round (Scripts/Multiplayer)
Sent from FUN_006a6630 -> indirectly through the completion handler chain.
Uses "Scripts/Multiplayer" (0x0095a314) and "*.pyc" filter, recursive=1.
Index byte = 0xFF signals special "last round" to client.

### Client-side handler: FUN_006a5df0 (opcode 0x20 in NetFile dispatcher)
1. Reads opcode (already consumed by dispatcher)
2. ReadByte -> roundIndex
3. ReadShort -> dirLen; ReadRawBytes(dir, dirLen); NUL-terminate
4. ReadShort -> filterLen; if > 0: ReadRawBytes(filter, filterLen); NUL-terminate
5. ReadBit -> recursive flag
6. If roundIndex == 0: calls FUN_006a6630() (reset/init checksums)
7. Creates file scanner, calls FUN_0071f270(scanner, dir, filter, recursive)
8. Builds response (opcode 0x21) with checksums and sends to server

### Client-side response handler: FUN_006a4260 (opcode 0x21, server receives)
At entry: checks `byte[1] != 0xFF`
- If not 0xFF: calls FUN_006a4560 (process normal round response)
- If 0xFF: processes the Multiplayer round response, then calls FUN_006a5860
  which sends next queued request or fires checksum-complete event

### Checksum state machine:
Server sends 4 rounds (0-3) via FUN_006a39b0
-> Each round queued on NetFile hash table (keyed by peerID)
-> Round 0 is sent immediately; rounds 1-3 are queued
-> Client processes opcode 0x20, builds checksum, sends opcode 0x21
-> Server receives 0x21, processes response via FUN_006a4560
-> FUN_006a5860 sends next queued round or fires event 0x008000e8
-> Event 0x008000e8 = ChecksumComplete -> calls ChecksumCompleteHandler (FUN_006a1b10)
-> ChecksumCompleteHandler sends Settings (0x00) + GameInit (0x01)

### WHERE IS THE 0xFF ROUND SENT?
The 0xFF round is NOT in the initial 4-round table.
It appears to be sent as a RESPONSE-triggered action from ChecksumCompleteHandler flow.
Looking at ChecksumCompleteHandler, it does NOT send a 0xFF round.
The 0xFF round seems to come from FUN_006a4560's completion path.

Actually: FUN_006a4560 at 0x006a484c path when *local_84c == 0 (all rounds done):
calls FUN_006a4bb0 which posts event 0x008000e8 (checksum complete).
The 0xFF appears to come from a different path entirely.
