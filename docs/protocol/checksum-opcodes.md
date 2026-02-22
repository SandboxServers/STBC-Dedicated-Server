> [docs](../README.md) / [protocol](README.md) / checksum-opcodes.md

# Checksum/NetFile Opcodes (0x20-0x28)

Dispatcher: `FUN_006a3cd0` (NetFile::ReceiveMessageHandler)

After the type 0x32 transport framing is stripped, the game-layer payload starts with the opcode byte (0x20-0x28 for checksum/NetFile operations).

## 0x20 - Checksum Request (Server -> Client)

Handler: `FUN_006a5df0`

```
Offset  Size  Type    Field
------  ----  ----    -----
0       1     u8      opcode = 0x20
1       1     u8      request_index (0x00-0x03, or 0xFF for final round)
2       2     u16     directory_name_length
4       var   string  directory_name (e.g. "scripts/")
+0      2     u16     filter_name_length
+2      var   string  filter_name (e.g. "App.pyc")
+0      bit   bool    recursive_flag
```

There are **5 checksum rounds** sent sequentially (server waits for each response before sending the next):

| Round | Index | Directory | Filter | Recursive | Purpose |
|-------|-------|-----------|--------|-----------|---------|
| 1 | `0x00` | `scripts/` | `App.pyc` | No | Core application module |
| 2 | `0x01` | `scripts/` | `Autoexec.pyc` | No | Startup script |
| 3 | `0x02` | `scripts/ships` | `*.pyc` | **Yes** | All ship definition modules |
| 4 | `0x03` | `scripts/mainmenu` | `*.pyc` | No | Menu system modules |
| 5 | `0xFF` | `Scripts/Multiplayer` | `*.pyc` | **Yes** | Multiplayer mission scripts |

Client computes file hashes and responds with 0x21.

## 0x21 - Checksum Response (Client -> Server)

Handler: `FUN_006a4260` -> `FUN_006a4560` (verify) or `FUN_006a5570` (mismatch)

The response echoes the round index from the request:

```
Offset  Size  Type    Field
------  ----  ----    -----
0       1     u8      opcode = 0x21
1       1     u8      request_index (echoes the request's round index)
2+      var   data    hash_data (variable length, opaque)
```

The server handler uses `byte[1]` to route processing:
- `byte[1] == 0xFF`: final round response (Scripts/Multiplayer), handled by main path
- `byte[1] != 0xFF`: standard round response, handled by `FUN_006a4560`

Round 2 responses are significantly larger (~400 bytes, fragmented) due to the number of ship `.pyc` files.

## 0x22 / 0x23 - Checksum Fail (Server -> Client)

Handler: `FUN_006a4c10`

0x22 = file/version mismatch ("VersionDifferent"), 0x23 = system checksum fail ("SystemChecksumFail")

```
Offset  Size  Type    Field
------  ----  ----    -----
0       1     u8      sub_opcode (0x22 or 0x23)
1       2     u16     filename_length
3       var   string  failing_filename
```

Client shows error dialog with the failing filename.

## 0x25 - File Transfer Request/Data

Handler: `FUN_006a3ea0` (if `this+0x14 != 0`, i.e., already in transfer mode)

Initial entry (this+0x14 == 0): Sets up receive-file warning dialog.

**Transfer data format**:
```
Offset  Size  Type    Field
------  ----  ----    -----
0       1     u8      opcode = 0x25
1       2     u16     filename_length
3       var   string  filename
+0      var   data    file_data (remainder of packet)
```

After writing the file, client checks if it's a `.pyc` in `Scripts/` and reimports the module.

Client responds with 0x27 (ACK).

## 0x27 - File Transfer ACK

Handler: `FUN_006a4250`

```
Offset  Size  Type    Field
------  ----  ----    -----
0       1     u8      opcode = 0x27
```

Calls `FUN_006a5860` to continue file transfer sequence or signal completion.

## 0x28 - Checksum Complete (Server -> Client)

No dedicated handler — signals that all checksum rounds have passed. Observed in stock dedi traces immediately before Settings (0x00) and GameInit (0x01).

```
Offset  Size  Type    Field
------  ----  ----    -----
0       1     u8      opcode = 0x28
```

Single byte, no additional payload.

## 0x24, 0x26 - Unknown/Unused

These opcode slots exist in the NetFile dispatcher range but no handler or packet trace evidence has been found for either.
