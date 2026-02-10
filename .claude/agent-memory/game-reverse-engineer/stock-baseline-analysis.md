# Stock Baseline Analysis: Known-Good Host vs Our Dedicated Server

Analysis of state dumps, tick traces, message traces, and packet traces from a working
stock Bridge Commander dedicated host session (2026-02-08), compared against our custom
dedicated server behavior.

## FINDING #1 (CRITICAL): 0x0097FA88 is IsClient, NOT IsHost

### Evidence
| Field | Stock Host | Stock Client | Our Server |
|-------|-----------|-------------|------------|
| 0x0097FA88 (IsClient) | **0** | **1** | **0 (CORRECT)** |
| 0x0097FA89 (IsHost) | **1** | **0** | **1 (CORRECT)** |
| 0x0097FA8A (IsMp) | 1 | 0 | 1 |
| WSN ConnState | 2 (host) | 2 (becomes 2) | 2 |

**Stock host has IsClient=0 and IsHost=1 throughout entire session (508 ticks).**
**Stock client has IsClient=1 and IsHost=0 throughout entire session (503 ticks).**

The correct semantics:
- **0x0097FA88 = "IsClient"** (1 = I am a joining client, 0 = I am the host)
- **0x0097FA89 = "IsHost"** (1 = I am the host, 0 = I am a client)
- **0x0097FA8A = "IsMultiplayer"** (1 = multiplayer active)

Our server correctly sets IsClient=0, IsHost=1, IsMp=1.

## FINDING #2: IsMultiplayer is Host-Only

The stock CLIENT has isMp=0, while the stock HOST has isMp=1.

| Field | Stock Host | Stock Client | Our Server |
|-------|-----------|-------------|------------|
| 0x0097FA8A (IsMp) | 1 | **0** | 1 |

IsMultiplayer is only set on the HOST side, not the client side. The client
proceeds with isMp=0, yet still functions correctly in multiplayer. Our server
correctly sets isMp=1.

## FINDING #3: MPG+0xB0 (Object Gate) is Always 0

On BOTH stock host and stock client, mpgB0 = 0x00000000 throughout the entire session.

This means the `this+0xB0 != 0` check in FUN_00504c10 (client message handler) would
ALWAYS fail if taken literally. Either:
1. The check uses a different offset than we measured
2. The gate is only momentarily set during message processing (between tick samples)
3. The gate is not needed on the host side at all

Since both sides have mpgB0=0 and the game works, this is likely not a blocking issue
for our server.

## FINDING #4: ReadyForNewPlayers (MPG+0x1F8) Behavior

| Field | Stock Host | Stock Client |
|-------|-----------|-------------|
| mpg1F8 | **1** (always) | **0** (always) |

The stock host always has ReadyForNewPlayers=1. The client never has it set.
Our server also sets this to 1, which matches correctly.

## FINDING #5: Game State Differences

### Stock Host GAME STATE
```
CurrentGame: <C Game instance at _ee40680_p_Game>
  .GetPlayer() = None                      <--- HOST HAS NO PLAYER SHIP
```

### Stock Client GAME STATE
```
CurrentGame: <C Game instance at _cf24f68_p_Game>
  .GetPlayer() = <C ShipClass instance>    <--- CLIENT HAS A PLAYER SHIP
```

The host NEVER has a player ship. `GetPlayer()` returns None on the host throughout
the entire session. This confirms the host is a "referee" - it processes game logic
but does not have its own ship.

## FINDING #6: Mission Module State

Both host and client have identical MissionShared globals including:
- g_bGameOver = 0 (game not ended)
- g_pStartingSet = valid SetClass instance
- g_pDatabase, g_pShipDatabase, g_pSystemDatabase = valid

Key difference: Client has `g_sPlayerShipController = Captain` in MissionLib (dump #2),
host does not. This confirms the client creates its own ship locally.

Client has `g_dConditionEventTriggers` populated with HelmMenuHandlers orbit condition,
host has it empty (no player = no conditions needed).

## FINDING #7: Message Flow Analysis

### Stock Host Message Trace (first 12 messages)
1. `type=0x03 size=15` - NewPlayerInGame (server->client)
2. `type=0x01 size=4` [01 00 00 02] - ACK/status
3. `type=0x01 size=4` [01 00 00 00] - ACK
4. `type=0x00 size=18` [00 12 C0 01 00 02 ...] - Settings packet with player name "Ace"
5. `type=0x32 size=26` - Checksum request (0x80 = reliable)
6-7. More ACKs
8. `type=0x32 size=22` - Checksum response
9-12. Checksum exchanges continue...

### Stock Client Message Trace (first 18 messages)
1. `type=0x01 size=4` [01 00 00 02] - ACK
2. `type=0x03 size=6` [03 06 C0 00 00 02] - Abbreviated NewPlayerInGame
3. `type=0x32 size=27` - Checksum: "scripts/App.pyc"
4. `type=0x01 size=4` [01 01 00 02] - ACK
5. `type=0x00 size=18` - Settings packet with player name "Ace"
6. `type=0x32 size=32` - Checksum: "scripts/Autoexec.pyc"
7-9. More checksum paths...
14. `type=0x32 size=36` - Checksum: "Scripts/Multiplayer/*.pyc"
16. `type=0x32 size=6` [32 06 80 05 00 28] - AllDone 0x28
17. `type=0x32 size=51` - Contains "Multiplayer.Episode.Mission1.Mission1" (mission load)
18. `type=0x32 size=6` [32 06 80 07 00 01] - Opcode 0x01 (game start)

### Key Observation: Message #78 on Host (Post-Checksum Game Data)
```
32 74 80 06 00 03 00 02 08 80 00 00 FF FF FF 3F
05 00 00 18 42 00 00 44 C2 00 00 0C C2 52 93 45
3F BB C9 22 BF E2 58 10 B3 25 8D 6C B2 00 00 00
00 00 00 00 03 41 63 65 06 4D 75 6C 74 69 31 FF
```
This is a game object replication message containing:
- Player name "Ace" (3 bytes + string)
- Mission name "Multi1" (6 bytes + string)
- Position floats (38.42, -49.00, -35.00)
- Orientation quaternion
- Ship subsystem/weapon status bytes (the FF bytes)

### Message #79 on Host (0x1C State Update)
```
32 2A 00 1C FF FF FF 3F 00 3C F3 42 ...
```
This is a 0x1C periodic state update - the ship network state packet that our server
was truncating. It starts appearing regularly after the client joins.

## FINDING #8: Periodic State Updates (0x1C Messages)

After the client joins and selects a ship (~18.4 seconds in), the stock host begins
sending 0x1C state update messages approximately every 100ms. These are 13-42 bytes:
- Small (13 bytes): `32 0D 00 1C FF FF FF 3F 00 XX XX XX 80` - position-only
- Large (36-42 bytes): Full state with subsystems and weapons

The 0x80 byte at the end of small updates likely means "no change" for subsystems.
The client also sends 0x1C updates back (showing its ship state).

In the stock host, these are properly formed with full subsystem/weapon data.

## FINDING #9: Tick Timing and Game Clock

### Stock Host
- gameTime starts at 109.734 (already running from boot)
- Ticks are ~100ms apart in steady state
- playerCount stays at 1 throughout (host only counts as 1 WSN peer)
- emQ (event manager queue) is mostly 0, occasionally spikes to 1-3

### Stock Client
- gameTime starts at 13.484, jumps to 110.047 at seq 4 (synced with server)
- playerCount goes from 1 to 2 at seq 1 (sees itself + host)
- emQ spikes to 8, 16 during initial load (Python events processing)
- connState becomes 2 after initial 3 (promotes to "host-like" connection)

### Client Conn State Transition
```
seq 0: conn=3 (client)
seq 1: conn=2 (promoted to host-like, players=2)
```
The client transitions from conn=3 to conn=2 almost immediately. This is interesting -
both sides end up with connState=2.

## FINDING #10: Session Lifecycle

### Full Timeline
1. **23:59:05.969** - First message exchange (connection established)
2. **23:59:05.973-06.785** - Checksum negotiation (8 rounds, 4 paths)
3. **23:59:06.785-08.054** - File integrity verification
4. **23:59:08.054** - Checksum complete, game state sync begins
5. **23:59:11.721** - First keepalive (type=0x02)
6. **23:59:16.725** - Second keepalive
7. **23:59:18.413** - Client selects ship, game data replication begins (message #78)
8. **23:59:18.413-20.xxx** - Continuous 0x1C state updates (~10Hz)
9. **~23:59:20+** - Active gameplay with periodic state sync
10. Host tick #507: players=0, conn=0 (session ended, 121 events in queue = cleanup)

## FINDING #11: Code Paths Comparison

### Stock Host Dump #1 (lobby, waiting for client) - 31 unique calls
Key functions: ProcessMessageHandler, HandleKeyboardTopButtonArea, UpdateJunkText,
PowerDisplay::Update, HelmMenuHandlers::ProcessFunc, CollisionAlertCheck

### Stock Host Dump #2 (client connected, playing) - 163 unique calls
Adds: Effects (CollisionEffect, ObjectExploding, CreateDebrisExplosion),
Mission1::ObjectKilledHandler, Mission1::UpdateScore, Mission1::DoKillSubtitle,
Mission1Menus::RebuildPlayerList, Mission1::ObjectCreatedHandler,
Mission1::ResetEnemyFriendlyGroups, Mission1::CheckFragLimit

This confirms the stock host fully processes game logic including:
- Kill tracking and scoring
- Object creation/destruction
- Player list management
- Frag limit checking
- Collision effects

## SUMMARY

### IsClient/IsHost/IsMp Flags (RESOLVED)
Our server correctly sets: IsClient=0, IsHost=1, IsMp=1 — matching stock host behavior.

### State Update (0x1C) Messages
Stock server sends flags=0x20 with subsystem health data cycling through startIdx 0,2,6,8,10.
Our server sends flags=0x00 because subsystem lists at ship+0x284 are NULL (NIF models don't
fully load without GPU). PatchNetworkUpdateNullLists correctly clears the flags to prevent
sending garbage, but the result is the client never gets subsystem acknowledgment.

## Raw Data References
- Stock host tick trace: `game/stock-dedi/tick_trace.log` (508 samples)
- Client tick trace: `game/client/tick_trace.log` (503 samples)
- Stock host state dumps: `game/stock-dedi/state_dump.log` (4 F12 dumps, ~21K lines)
- Client state dumps: `game/client/state_dump.log` (4 F12 dumps, ~21K lines)
- Stock host messages: `game/stock-dedi/message_trace.log`
- Client messages: `game/client/message_trace.log`
- Stock host packets: `game/stock-dedi/packet_trace.log`
- Client packets: `game/client/packet_trace.log`
