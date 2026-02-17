# GameSpy Master Server Registration in Bridge Commander

## Overview

Star Trek: Bridge Commander includes a GameSpy SDK integration for both server browser (client-side) and Query/Reporting (host-side) functionality. However, analysis of the binary reveals that the **QR (heartbeat) initialization code is dead/unreachable** -- Bridge Commander never actually registers with the GameSpy master server for internet-visible server listing. Only LAN discovery works in the shipping game.

This document catalogs every component of the GameSpy implementation found in stbc.exe, including the complete but unused QR heartbeat system.

## Architecture

### GameSpy Object

The GameSpy object is a C++ class at UtopiaModule+0x7C (global address 0x0097FA7C).

**Constructor**: FUN_0069bfa0 (__thiscall)
- Size: 0xF4 bytes
- Vtable: PTR_FUN_00895564
- Base class: TGScriptableObject (FUN_006d8f90, vtable PTR_FUN_00896044)
- Loads `data/TGL/Multiplayer.tgl` for UI strings
- Registers event handler `"GameSpy :: ProcessQueryHandler"` for event 0x60006
- Sets `this+0xEE = 1` (QR mode ON by default)
- Sets `this+0xDC = 0` (qr_t pointer, NULL = uninitialized)
- Sets `this+0xE0 = 0` (server list pointer)

**Destructor**: FUN_0069c140 (__fastcall)
- If QR active (`+0xEE != 0` and `+0xDC != 0`):
  - Copies "exiting" to `+0x14` (settings field)
  - Calls FUN_006abe00 (sends statechanged heartbeat with "exiting" status)
  - Calls FUN_006abe40 (QR shutdown -- closes sockets, frees qr_t)
- If server list active (`+0xE0 != 0`): calls FUN_006aa2b0 (cleanup)
- Unregisters from event system

**Creation**: In FUN_00445d90 (UtopiaModule::InitializeNetwork), called from MW::StartGameHandler (0x00504890) when processing ET_START event.

### GameSpy Object Field Map

| Offset | Type | Description |
|--------|------|-------------|
| +0x00 | void** | Vtable (PTR_FUN_00895564) |
| +0x10 | DWORD | Base class field |
| +0x14 | char[32] | Game mode / settings string (init: "settings") |
| +0xDC | qr_t* | QR struct pointer (NULL = use static default) |
| +0xE0 | void* | Server browser list struct pointer |
| +0xE4 | float | Last update time |
| +0xE8 | void* | TGL file handle (data/TGL/Multiplayer.tgl) |
| +0xEC | byte | Client mode flag (1=client browsing, 0=not) |
| +0xED | byte | Server browser initialized flag |
| +0xEE | byte | QR mode flag (1=QR active, 0=browser mode) |
| +0xEF | byte | QR shutdown-only mode flag |
| +0xF0 | byte | Sort toggle flag |

### GameSpy Vtable (PTR_FUN_00895564)

| Slot | Address | Name |
|------|---------|------|
| 0 | 0x0069c110 | scalar_deleting_destructor |
| 1 | 0x0069c080 | (tiny stub, undefined) |
| 2 | 0x0069c090 | (tiny stub, undefined) |
| 3 | 0x006f1650 | base class virtual |
| 4 | 0x0069c530 | (tiny stub, undefined -- likely StartQR?) |
| 5 | 0x0069c540 | (tiny stub, undefined -- likely StopQR?) |
| 6 | 0x006f27f0 | base class virtual |
| 7 | 0x006f2810 | base class virtual |
| 8 | 0x006f15c0 | base class virtual |
| 9 | 0x0069c0d0 | (tiny stub, undefined) |
| 10 | 0x0069c0e0 | (tiny stub, undefined) |

### SWIG Interface

The GameSpy class has NO direct SWIG wrappers. Access is through UtopiaModule:
- `Appc.UtopiaModule_CreateGameSpy(self)` -> FUN_00445fc0 (creates GameSpy object)
- `Appc.UtopiaModule_GetGameSpy(self)` -> returns `self[0x1F]` = UtopiaModule+0x7C
- `Appc.UtopiaModule_TerminateGameSpy(self)` -> FUN_00446010 (destroys GameSpy object)

## Tick/Update Function (FUN_0069c440)

Called every frame. Logic branches:

```
if (+0xED == 0)  // not enabled
    return;

if (+0xEE != 0)  // QR mode
    if (+0xEF != 0)  // shutdown-only mode
        FUN_006abcc0(+0xDC)  // process queries only (no heartbeat)
    else
        FUN_006abca0(+0xDC)  // process queries + heartbeat timer
else  // browser mode
    if (enough time elapsed && +0xEC == 0)
        FUN_006aab40(+0xE0)  // process server list
```

## QR (Query/Reporting) System

### Static qr_t Struct

Address: 0x0095a740 (in .data section, zeroed at load time)
Default pointer: PTR_DAT_0095a830 -> 0x0095a740

All QR functions accept a qr_t pointer parameter. If NULL, they fall back to the static default at 0x0095a740.

### qr_t Field Map (reconstructed)

| Offset | Type | Description |
|--------|------|-------------|
| +0x00 | SOCKET | Query receive socket (incoming queries from browsers) |
| +0x04 | SOCKET | Heartbeat send socket (outgoing to master server) |
| +0x08 | char[32] | Game name string (e.g., "bcommander") |
| +0xC8 | func* | Basic info callback (fills `\hostname\`, `\mapname\`, etc.) |
| +0xCC | func* | Rules callback |
| +0xD0 | func* | Players callback |
| +0xD4 | func* | Status callback |
| +0xD8 | DWORD | Last heartbeat send timestamp (GetTickCount) |
| +0xDC | DWORD | (unused/padding in qr_t -- not the same as GameSpy+0xDC!) |
| +0xE4 | DWORD | Active/enabled flag (qr_t[0x39]) -- must be non-zero |
| +0xE8 | byte | Heartbeat retry counter (counts up to 10) |
| +0xEC | DWORD | Query counter (incremented on each incoming query) |
| +0xE0 | DWORD | Partial query counter |

### Master Server Sockaddr (Global)

Address: `to_00995880` (16-byte sockaddr_in)
- Used by the heartbeat sender (FUN_006aca60)
- Destination for `\heartbeat\` and `\statechanged\` UDP packets
- **Never initialized in reachable code** -- the qr_init code that would fill this is dead

### Master Server Hostname

Default: `stbridgecmnd01.activision.com` (at 0x0095a594, copied to 0x0095a4fc)
Override file: `masterserver.txt` (read by FUN_006aa100)

### QR Functions

#### FUN_006aca60 - send_heartbeat (qr_send_heartbeat)
```
void __cdecl FUN_006aca60(int qr_t_ptr, int include_statechanged)
```
- Formats: `\heartbeat\<port>\gamename\<name>`
- If include_statechanged: appends `\statechanged\<n>`
- Sends via UDP sendto() to `to_00995880` (master server)
- Updates last heartbeat timestamp at qr_t+0xD8

#### FUN_006abd80 - qr_process_heartbeat_timer
```
void __cdecl FUN_006abd80(int qr_t_ptr)
```
- Checks if socket at qr_t+0x04 is valid (!= -1)
- If >300,001ms since last heartbeat, OR last_time==0, OR GetTickCount wrapped: sends heartbeat
- If heartbeat retry counter at +0xE8 > 0 and >30,000ms elapsed: sends heartbeat, increments counter
- Counter resets to 0 after 10 retries (gives up)

Heartbeat timing:
- **Normal interval**: ~5 minutes (300,001ms = 0x493E1)
- **Retry interval**: 30 seconds (30,000ms)
- **Max retries**: 10

#### FUN_006abca0 - qr_process_queries_and_heartbeat
```
void __cdecl FUN_006abca0(SOCKET* qr_t_ptr)
```
- Falls back to static qr_t if NULL
- Calls FUN_006abd80 (heartbeat timer)
- Calls FUN_006abce0 (incoming query processing)

#### FUN_006abce0 - qr_process_incoming_queries
```
void __cdecl FUN_006abce0(SOCKET* qr_t_ptr)
```
- Checks qr_t[0x39] (active flag) != 0
- Non-blocking select() on query socket (qr_t[0])
- Receives UDP packets into buffer at 0x00995578
- Dispatches to FUN_006ac1e0 (query parser)

#### FUN_006ac1e0 - qr_parse_query (Query Dispatcher)
```
void __cdecl FUN_006ac1e0(SOCKET* qr_t_ptr, void* query_data, sockaddr* from)
```
Parses incoming queries for keywords from table at 0x0095a71C:

| Index | Keyword | Handler | Description |
|-------|---------|---------|-------------|
| 0 | "basic" | FUN_006ac5f0 | Calls basic info callback at qr_t+0xC8 |
| 1 | "info" | (same as basic) | Alias |
| 2 | "rules" | FUN_006ac7a0 | Calls rules callback at qr_t+0xCC |
| 3 | "players" | FUN_006ac810 | Calls players callback at qr_t+0xD0 |
| 4 | "status" | (all four) | Calls basic+rules+players+status |
| 5 | "packets" | (all with separators) | Calls all with FUN_006ac550 between each |
| 6 | "echo" | FUN_006ac8f0 | Echoes back with `\echo\<data>` |
| 7 | "secure" | (stored for later) | Challenge token for validation |

After all keywords processed, calls FUN_006ac950 (validation/final sender).

#### FUN_006ac950 - qr_send_validate_and_final
- Processes `\secure\` challenge: computes validate response via FUN_006abf70
- Sends `\validate\<response>`
- Sends `\final\`
- Sends accumulated buffer via FUN_006ac550

#### FUN_006ac550 - qr_flush_and_send
- Appends `\queryid\<N>.<M>` to buffer
- Sends via UDP sendto() to requesting client
- Increments query part counter

#### FUN_006abe00 - qr_send_statechanged
```
void __cdecl FUN_006abe00(undefined* qr_t_ptr)
```
- Falls back to static qr_t if NULL
- Calls FUN_006aca60 with statechanged=1

#### FUN_006abe40 - qr_shutdown
```
void __cdecl FUN_006abe40(SOCKET* qr_t_ptr)
```
- Falls back to static qr_t if NULL
- Closes query socket (qr_t[0]) if valid and active
- Closes heartbeat socket (qr_t[1]) if valid and different from query socket
- Frees qr_t memory (unless it's the static instance at 0x0095a740)
- Calls WSACleanup()

### Basic Info Callback (FUN_0069c580)

This function builds the server info response string. It includes:

| Key | Source | Description |
|-----|--------|-------------|
| `\hostname\` | MultiplayerWindow player name | Server name (appends `!` if password set) |
| `\missionscript\` | Current mission script path | e.g., "Multiplayer.Mission" |
| `\mapname\` | Python GetMissionShortName() | Human-readable map name |
| `\numplayers\` | FUN_006a2650 (player count) | Current player count |
| `\maxplayers\` | `g_iPlayerLimit` Python variable | Max player slots |
| `\gamemode\` | GameSpy+0x14 | Game mode string (default: "settings") |

## Server Browser System (Client-Side)

### Initialization (FUN_0069c3a0)
- Game name: "bcommander" (at 0x00959c24)
- **Secret key: "Nm3aZ9"** (hardcoded in binary)
- Creates server list struct at GameSpy+0xE0
- Sets `+0xED=1` (enabled), `+0xEE=0` (browser mode, NOT QR mode)
- Calls FUN_006aa100 which:
  - Reads `masterserver.txt` for custom master hostname
  - Falls back to `stbridgecmnd01.activision.com`
  - Allocates 0xA0-byte server list struct
  - Calls WSAStartup(0x101)

### Master Server TCP Connection (FUN_006aa410)
- Connects to master server on TCP port **28900** (0x70E4)
- Resolves hostname via inet_addr() first, then gethostbyname() if needed
- Socket stored at server_list+0x88

### Challenge-Response Handshake (FUN_006aa4c0)
1. Receives `\secure\<challenge>` from master server
2. Processes challenge through:
   - FUN_006ac050: RC4 cipher using secret key
   - FUN_006abf70: GameSpy validate encoding (base64-like)
3. Sends: `\gamename\bcommander\gamever\<ver>\location\0\validate\<response>\final\\queryid\1.1\`
4. Sends server list request:
   - Without filter: `\list\<type>\gamename\bcommander\final\`
   - With filter: `\list\<type>\gamename\bcommander\where\<filter>\final\`

### Internet vs LAN Browsing (FUN_0069ccd0)
- **LAN**: Calls FUN_006aa2f0 with broadcast
- **Internet**: Calls FUN_006aa6b0 with ports 0x5655 (22101) and 0x56b9 (22201)

### LAN Socket Setup (FUN_006aa720)
- Creates UDP socket: `socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)`
- Enables broadcast: `setsockopt(SOL_SOCKET, SO_BROADCAST, 1)`

### LAN Query (FUN_006aa770)
- Broadcasts `\status\` query to port range (param_2 to param_3 in steps of param_4)
- Destination: 255.255.255.255 (broadcast)

## Encryption Functions

### FUN_006ac050 - RC4 Cipher
Standard RC4 implementation used for GameSpy secure/validate processing.
- Initializes S-box with key
- XOR-encrypts/decrypts data in place

### FUN_006abf70 - GameSpy Validate Encoding
Custom encoding function for challenge-response validation.
Uses FUN_006ac020 (base64-like character mapping).

### FUN_006ac020 - Base64 Character Map
Maps 6-bit values to printable characters (A-Z, a-z, 0-9, +, /).

## Event System Integration

### Event Types
| ID | Name | Description |
|----|------|-------------|
| 0x0109 | ET_SET_GAME_MODE | Updates GameSpy+0x14 settings string |
| 0x0867 | (GameSpy query event) | Incoming query data from network layer |
| 0x60006 | (GameSpy message) | Event handler registration token |

### Event Handlers
- **SetGameModeHandler** (FUN_0069cc40): Copies game mode string to GameSpy+0x14
- **ProcessQueryHandler** (FUN_0069d720): Dispatches incoming queries (event 0x867) to qr_parse_query

### Registration
FUN_0069c4e0 registers both handlers with the event system via FUN_006da130.

## Dead Code: QR Initialization (0x006ab558-0x006ab5BF)

A block of code exists at 0x006ab558-0x006ab5BF that references:
- "Unable to resolve master" (0x0095a6e4)
- "Connection to master reset" (0x0095a6c8)

This code would resolve the master server hostname and fill `to_00995880` (the heartbeat destination sockaddr), and likely create/bind the QR UDP socket. However, **Ghidra finds no xrefs to this code block** -- it is completely unreachable. This is dead code from the GameSpy QR1 SDK that was compiled into the binary but never called.

The related string `\gamename\%s\gamever\%s\location\%d` at 0x00959c50 (the LAN heartbeat format) is also unreferenced.

## Why QR Never Activates

1. GameSpy constructor sets `+0xEE=1` (QR mode) and `+0xDC=0` (qr_t pointer)
2. Tick function calls `FUN_006abca0(NULL)` which uses static qr_t at 0x0095a740
3. Static qr_t is entirely zeroed -- all fields are 0
4. `qr_process_incoming_queries` checks `qr_t[0x39]` (active flag) -- it's 0, so returns immediately
5. `qr_process_heartbeat_timer` checks `qr_t+0x04` (heartbeat socket) against -1 -- socket 0 IS != -1, so it would try to send... but:
6. The `to_00995880` sockaddr is zeroed (family=0, port=0, addr=0.0.0.0) -- sendto() to 0.0.0.0:0 fails silently
7. No code ever calls the qr_init function to:
   - Create and bind the QR UDP socket
   - Resolve the master server hostname
   - Fill `to_00995880` with the resolved address
   - Set the active flag in the qr_t struct
   - Set up the info callbacks

## Implementation Plan for Dedicated Server

To register with a master server (e.g., 333networks), the dedicated server would need to:

1. **Initialize the qr_t struct** by either:
   - Calling the dead code at 0x006ab558 (would need to patch in a call)
   - Implementing qr_init in the proxy DLL directly

2. **Set up the QR socket**: Create UDP socket, bind to game port or game port + offset

3. **Resolve master server**: DNS lookup for the master hostname, fill `to_00995880`

4. **Send initial heartbeat**: `\heartbeat\<port>\gamename\bcommander`

5. **Process incoming queries**: Either via the existing event system (hook into 0x867 events) or by polling the QR socket in GameLoopTimerProc

6. **Respond to queries**: Fill basic/rules/players/status info

7. **Send periodic heartbeats**: Every ~5 minutes, or on state changes

8. **Handle \secure\ challenges**: Respond with `\validate\` using the existing crypto functions (FUN_006abf70, FUN_006ac050)

9. **Send final heartbeat on shutdown**: With "exiting" status

### Key Values for Registration
- **Game name**: "bcommander" (at 0x00959c24)
- **Secret key**: "Nm3aZ9" (hardcoded)
- **Master server port**: 27900 (heartbeat destination, UDP)
- **Master list port**: 28900 (server browser, TCP)
- **Default master hostname**: stbridgecmnd01.activision.com
- **Override file**: masterserver.txt

### 333networks Compatibility
333networks master servers use the same GameSpy protocol. To register:
1. Point masterserver.txt to a 333networks master server
2. Send heartbeats in the standard format
3. Respond to queries with valid server info
4. Handle secure/validate challenges

## Function Reference

| Address | Name | Description |
|---------|------|-------------|
| 0x0069bfa0 | GameSpy::ctor | Constructor (0xF4 bytes, registers event handlers) |
| 0x0069c140 | GameSpy::dtor | Destructor (sends "exiting", shuts down QR/browser) |
| 0x0069c440 | GameSpy::Tick | Per-frame update (QR or browser processing) |
| 0x0069c3a0 | GameSpy::InitBrowser | Server browser init ("bcommander", "Nm3aZ9") |
| 0x0069c4e0 | GameSpy::RegisterHandlers | Registers SetGameMode + ProcessQuery handlers |
| 0x0069c580 | GameSpy::BuildBasicInfo | Fills server info for query responses |
| 0x0069cc40 | GameSpy::SetGameModeHandler | Event handler: copies game mode to +0x14 |
| 0x0069ccd0 | GameSpy::StartBrowsing | Start internet/LAN server browsing |
| 0x0069d720 | GameSpy::ProcessQueryHandler | Event handler: dispatches to qr_parse_query |
| 0x00445d90 | UtopiaModule::InitializeNetwork | Creates TGWinsockNetwork + GameSpy object |
| 0x00445fc0 | UtopiaModule::CreateGameSpy | Destroys old + creates new GameSpy object |
| 0x00446010 | UtopiaModule::TerminateGameSpy | Destroys GameSpy object |
| 0x006aa100 | gs_list_init | Master server list init (reads masterserver.txt) |
| 0x006aa310 | gs_list_connect | Server list TCP connect + handshake |
| 0x006aa410 | gs_master_tcp_connect | TCP connect to master:28900 |
| 0x006aa4c0 | gs_master_handshake | \secure\ challenge, \validate\ response, \list\ request |
| 0x006aa720 | gs_lan_socket_init | LAN UDP broadcast socket setup |
| 0x006aa770 | gs_lan_query | Broadcasts \status\ to port range |
| 0x006abca0 | qr_process_queries_and_heartbeat | Main QR tick function |
| 0x006abce0 | qr_process_incoming_queries | Select + recvfrom on QR socket |
| 0x006abd80 | qr_heartbeat_timer | Periodic heartbeat check (5min/30s retry) |
| 0x006abe00 | qr_send_statechanged | Sends heartbeat with statechanged flag |
| 0x006abe40 | qr_shutdown | Closes sockets, frees qr_t, WSACleanup |
| 0x006ac050 | gs_rc4_cipher | RC4 encryption/decryption |
| 0x006ac1e0 | qr_parse_query | Dispatches basic/rules/players/status/echo/secure |
| 0x006ac550 | qr_flush_send | Appends queryid, sendto, clears buffer |
| 0x006ac5f0 | qr_handle_basic | Calls basic info callback |
| 0x006ac660 | qr_assemble_response | Buffer assembly with MTU splitting |
| 0x006ac7a0 | qr_handle_rules | Calls rules callback |
| 0x006ac810 | qr_handle_players | Calls players callback |
| 0x006ac880 | qr_handle_status | Calls status callback |
| 0x006ac8f0 | qr_handle_echo | Returns \echo\<data> |
| 0x006ac950 | qr_handle_secure_and_final | Validate response + \final\ |
| 0x006aca60 | qr_send_heartbeat | Formats + sends heartbeat/statechanged UDP |
| 0x006abf70 | gs_validate_encode | GameSpy validate encoding |
| 0x006ac020 | gs_base64_char | Base64-like character mapping |

## Global Data Reference

| Address | Type | Description |
|---------|------|-------------|
| 0x0095a4fc | char[64] | Active master server hostname (writable copy) |
| 0x0095a594 | char[30] | Default master: "stbridgecmnd01.activision.com" |
| 0x0095a740 | byte[0xF0] | Static qr_t struct (zeroed, never initialized) |
| 0x0095a830 | DWORD | Pointer to static qr_t (-> 0x0095a740) |
| 0x00995880 | sockaddr_in | Master server heartbeat destination (zeroed, never filled) |
| 0x00995578 | byte[256] | Incoming query receive buffer |
| 0x00959c24 | char[12] | Game name: "bcommander" |
| 0x00959c50 | char[36] | LAN heartbeat format (unreferenced dead string) |
| 0x0095a904 | char[26] | Heartbeat format: "\heartbeat\%d\gamename\%s" |
| 0x0095a8f0 | char[18] | Statechanged format: "\statechanged\%d" |
| 0x0095a71C | void*[8] | Query keyword pointer table (basic/info/rules/players/status/packets/echo/secure) |
