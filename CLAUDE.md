# STBC Dedicated Server - Development Context

Headless dedicated server for Star Trek: Bridge Commander multiplayer, implemented as a DDraw proxy DLL. Cross-compiled from WSL2, drives the game engine via C code + embedded Python 1.5.

## Repo Layout
- `src/proxy/ddraw_main.c` - **THE main file**. All C-side changes go here (~3600 lines)
- `src/proxy/` - Other proxy DLL sources (ddraw7, surface7, d3d7, header, def)
- `src/scripts/Custom/DedicatedServer.py` - Python server config (checksum exempt)
- `src/scripts/Local.py` - Custom hook (checksum exempt)
- `config/dedicated.cfg` - Empty trigger file (presence enables dedicated mode)
- `docs/` - Reverse engineering notes, protocol docs, API reference
- `reference/decompiled/` - Ghidra C output (19 files, ~15MB total)
- `reference/scripts/` - Decompiled game Python (~1228 .py files)

## Build & Deploy
```bash
make build          # Cross-compile ddraw.dll
make deploy         # Kill stbc.exe, copy dll + scripts + config to game dir
make run            # Deploy + launch stbc.exe
make logs           # View ddraw_proxy.log
make clean          # Remove build artifacts
# Override game path: make GAME_DIR="/path/to/game" deploy
```

## Current Status: CLIENT BLACK SCREEN
Server boots, checksums pass, packets exchange, but client shows black screen with music.
See [docs/black-screen-investigation.md](docs/black-screen-investigation.md) for full details.

### What Works
- Headless boot (all 4 bootstrap phases), Python DedicatedServer.TopWindowInitialized() runs
- MultiplayerGame: ReadyForNewPlayers=1, MaxPlayers=8, ProcessingPackets=1
- GameSpy LAN discovery, checksum exchange (4 rounds), keepalive
- Import hook patches mission handlers for headless mode (func_code replacement)
- VEH crash handler, PatchChecksumAlwaysPass (forces flag=1 at 0x006a1b75)
- Server stays in lobby mode (g_bGameStarted=0, no ET_START)

## Key Architecture

### Engine
- **NetImmerse 3.1** (predecessor to Gamebryo), DirectDraw 7 / Direct3D 7
- **Networking**: Winsock UDP (TGWinsockNetwork), NOT DirectPlay
- **Scripting**: Embedded Python 1.5, SWIG 1.x bindings (App/Appc modules)
- **Executable**: 32-bit Windows (stbc.exe, ~5.9MB, base 0x400000)

### Two Message Dispatchers
1. **NetFile dispatcher (FUN_006a3cd0)**: Checksums/file opcodes 0x20-0x27
2. **MultiplayerGame dispatcher (0x0069f2a0)**: Game opcodes 0x00-0x0F

### Settings Packet (opcode 0x00) - sent after checksums pass
`[0x00] [float:gameTime] [byte:0x008e5f59] [byte:0x0097faa2] [byte:playerSlot] [short:mapLen] [data:mapName] [byte:checksumFlag] [if 1: checksum data]`
Then opcode 0x01 (single byte).

### Key Globals
| Address | What |
|---------|------|
| 0x0097FA00 | UtopiaModule base |
| 0x0097FA78 | TGWinsockNetwork* (UtopiaModule+0x78) |
| 0x0097FA7C | GameSpy ptr (+0xDC=qr_t) |
| 0x0097FA80 | NetFile/ChecksumMgr |
| 0x0097FA88 | IsHost (BYTE) |
| 0x0097FA8A | IsMultiplayer (BYTE) |
| 0x008e5f59 | Settings byte 1 (sent in opcode 0x00, currently 0x01) |
| 0x0097faa2 | Settings byte 2 (sent in opcode 0x00, currently 0x00) |
| 0x0097e238 | TopWindow/MultiplayerGame ptr |
| 0x009a09d0 | Clock object ptr (+0x90=gameTime, +0x54=frameTime) |

## Python 1.5 Quirks (CRITICAL)
- `print "string"` (no parens), `except Exception, e:` (not `as e`)
- No list comprehensions, no ternary, no `os`/`string` module imports
- **`x in dict` FAILS** - use `dict.has_key(x)`
- **`'sub' in 'string'` FAILS** - use `strop.find(string, sub) >= 0`
- **`__import__('A.B.C')`** returns package A; actual module in `sys.modules['A.B.C']`
- **Always delete .pyc** after editing .py files

## Multiplayer Checksum System
- `scripts/Custom/` directory is EXEMPT from checksums
- `scripts/Local.py` is also exempt - vanilla clients can connect to modded servers

## Decompiled Source Reference
19 organized files in `reference/decompiled/`:
- `01_core_engine.c` - Core engine, memory, containers
- `02_utopia_app.c` - UtopiaApp, game init, Python bridge
- `03_game_objects.c` - Ships, weapons, systems, AI
- `04_ui_windows.c` - UI panes, windows, menus
- `05_game_mission.c` - Mission logic, scenarios
- `09_multiplayer_game.c` - MP game logic, handlers
- `10_netfile_checksums.c` - Checksums, file transfer
- `11_tgnetwork.c` - TGWinsockNetwork, packet I/O

## Documentation Index
- [docs/black-screen-investigation.md](docs/black-screen-investigation.md) - Current debugging focus
- [docs/multiplayer-flow.md](docs/multiplayer-flow.md) - Complete client/server join flow
- [docs/network-protocol.md](docs/network-protocol.md) - Protocol traces, packet formats
- [docs/swig-api.md](docs/swig-api.md) - SWIG function reference
- [docs/decompiled-functions.md](docs/decompiled-functions.md) - Key function analysis
- [docs/function-map.md](docs/function-map.md) - 18K-function organized map
- [docs/dedicated-server.md](docs/dedicated-server.md) - Bootstrap sequence & phases
- [docs/lessons-learned.md](docs/lessons-learned.md) - Python 1.5 quirks, gotchas

## Ghidra MCP Setup
This project uses a Ghidra MCP server for live decompilation. To set up:
```bash
claude mcp add ghidra --transport stdio -- \
  /path/to/python3 /path/to/GhidraMCP/bridge_mcp_ghidra.py \
  --ghidra-server http://<ghidra-host>:8090/
```
The Ghidra HTTP bridge must be running (GhidraMCP plugin in Ghidra with stbc.exe loaded).
