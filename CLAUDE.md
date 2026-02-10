# STBC Dedicated Server - Development Context

Headless dedicated server for Star Trek: Bridge Commander multiplayer, implemented as a DDraw proxy DLL. Cross-compiled from WSL2, drives the game engine via C code + embedded Python 1.5.

## Repo Layout
- `src/proxy/ddraw_main.c` - **THE main file**. All C-side changes go here (~3800 lines)
- `src/proxy/` - Other proxy DLL sources (ddraw7, surface7, d3d7, header, def)
- `src/scripts/Custom/DedicatedServer.py` - Python server config (checksum exempt)
- `src/scripts/Custom/ClientLogger.py` - Client-side diagnostic hooks (checksum exempt)
- `src/scripts/Local.py` - Server custom hook (checksum exempt)
- `src/scripts/ClientLocal.py` - Client custom hook (deployed as Local.py on client)
- `config/dedicated.cfg` - Empty trigger file (presence enables dedicated mode)
- `game/server/` - Live server game install (gitignored except readme.md)
- `game/client/` - Live client game install (gitignored except readme.md)
- `docs/` - Reverse engineering notes, protocol docs, API reference
- `reference/decompiled/` - Ghidra C output (19 files, ~15MB total)
- `reference/scripts/` - Decompiled game Python (~1228 .py files)

## Build & Deploy
```bash
make build          # Cross-compile ddraw.dll
make deploy         # Deploy to BOTH server and client game dirs
make deploy-server  # Deploy proxy DLL + server scripts to game/server/
make deploy-client  # Deploy client logger scripts to game/client/
make run-server     # Deploy + launch server
make run-client     # Deploy client + launch client
make logs-server    # View server logs (proxy, packet trace, dedicated init)
make logs-client    # View client debug log
make clean          # Remove build artifacts
```

## Current Status: CLIENT DISCONNECT AFTER SHIP SELECT
Client connects, checksums pass, reaches ship selection, sees ship, but disconnects ~3 sec later.
Message: "You have been disconnected from the host computer"

### What Works
- Headless boot (all 4 bootstrap phases), Python DedicatedServer.TopWindowInitialized() runs
- MultiplayerGame: ReadyForNewPlayers=1, MaxPlayers=8, ProcessingPackets=1
- GameSpy LAN discovery, checksum exchange (4 rounds), keepalive
- Import hook patches mission handlers for headless mode (func_code replacement)
- Client reaches ship selection screen, player appears on scoreboard
- Packet trace system: full hex dumps to `game/server/packet_trace.log`
- Client-side logging: `game/client/client_debug.log`
- CrashDumpHandler (SetUnhandledExceptionFilter) logs full diagnostics on any crash

### Known Issues
- Client disconnects ~3 sec after ship selection (empty StateUpdates - flags=0x00 instead of 0x20)
- Root cause: NIF models don't load headlessly -> subsystem list at ship+0x284 is NULL
- First connection always times out (client must reconnect)
- `scoring dict fix rc=-1` - Python code for SCORE_MESSAGE send has an error

### Key Fixes Applied (in ddraw_main.c)
1. **TGL FindEntry NULL fix** - code cave at 0x006D1E10, returns NULL when ECX is NULL
2. **Network NULL list guard** - code cave at 0x005B1D57, clears SUB/WPN flags when ship+0x284 NULL
3. **Subsystem hash check fix** - code cave at 0x005B22B5, prevents false anti-cheat kicks
4. **Compressed vector read guard** - validates vtable at 0x006D2EB0/0x006D2FD0
5. **CWD fix** - SetCurrentDirectoryA(g_szBasePath) in DllMain
6. **NewPlayerInGame handshake** - GameLoopTimerProc calls FUN_006a1e70 when player count increases
7. **Scoring dict registration** - adds player to scoring dictionaries after NewPlayerInGame
8. **Renderer pipeline proxy** - D3D7/DDraw7/Surface7 COM proxies provide valid objects to engine

### Diagnostic Logs
- `game/server/ddraw_proxy.log` - Main proxy log (boot, game loop, patches)
- `game/server/packet_trace.log` - Full packet hex dumps with opcode decoding
- `game/server/tick_trace.log` - Per-tick CSV: timing, queues, player counts (15 columns)
- `game/server/crash_dump.log` - Full crash diagnostics (registers, stack, code bytes)
- `game/server/dedicated_init.log` - Python-side boot/runtime log
- `game/client/client_debug.log` - Client-side handler tracing

## Key Architecture

### Engine
- **NetImmerse 3.1** (predecessor to Gamebryo), DirectDraw 7 / Direct3D 7
- **Networking**: Winsock UDP (TGWinsockNetwork), NOT DirectPlay
- **Scripting**: Embedded Python 1.5, SWIG 1.x bindings (App/Appc modules)
- **Executable**: 32-bit Windows (stbc.exe, ~5.9MB, base 0x400000)

### Two Message Dispatchers
1. **NetFile dispatcher (FUN_006a3cd0)**: Checksums/file opcodes 0x20-0x27
2. **MultiplayerGame dispatcher (0x0069f2a0)**: Game opcodes 0x00-0x2A (jump table at 0x0069F534)
   - 0x06/0x0D=PythonEvent, 0x07-0x0C/0x0E-0x10/0x1B=EventForward, 0x19=TorpedoFire, 0x1A=BeamFire
   - 0x14=DestroyObj, 0x1D=ObjNotFound, 0x1E=RequestObj, 0x29=Explosion, 0x2A=NewPlayerInGame

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
| 0x0097FA88 | IsClient (BYTE) - 0=host, 1=client |
| 0x0097FA89 | IsHost (BYTE) - 1=host, 0=client |
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
- [docs/black-screen-investigation.md](docs/black-screen-investigation.md) - Current status: client disconnect investigation
- [docs/dedicated-server.md](docs/dedicated-server.md) - Bootstrap sequence, patches, crash handling
- [docs/wire-format-spec.md](docs/wire-format-spec.md) - Complete wire format: opcodes, StateUpdate, compressed types
- [docs/network-protocol.md](docs/network-protocol.md) - Protocol architecture, event system, handler tables
- [docs/message-trace-vs-packet-trace.md](docs/message-trace-vs-packet-trace.md) - Stock-dedi opcode cross-reference
- [docs/empty-stateupdate-root-cause.md](docs/empty-stateupdate-root-cause.md) - Why flags=0x00 (5-step causal chain)
- [docs/veh-cascade-triage.md](docs/veh-cascade-triage.md) - Why VEH was removed (4-stage crash chain)
- [docs/multiplayer-flow.md](docs/multiplayer-flow.md) - Complete client/server join flow
- [docs/swig-api.md](docs/swig-api.md) - SWIG function reference
- [docs/decompiled-functions.md](docs/decompiled-functions.md) - Key function analysis
- [docs/function-map.md](docs/function-map.md) - 18K-function organized map
- [docs/lessons-learned.md](docs/lessons-learned.md) - Debugging techniques, pitfalls, protocol discoveries

## Agent Team

This project uses specialized agents for ALL analysis, research, and investigation work. The orchestrator (main conversation) does NOT perform these tasks directly — it delegates to agents, synthesizes their findings, and writes the actual code.

### Hard Rules
1. **Agents do research and analysis ONLY.** They must NEVER write or modify project source code. Code changes are exclusively the orchestrator's job.
2. **All Ghidra MCP tool usage** (`mcp__ghidra__*`) MUST go through the `game-reverse-engineer` agent. Never call Ghidra tools directly.
3. **Launch agents in parallel** when their tasks are independent. A crash investigation might need `win32-crash-analyst` + `game-reverse-engineer` + `x86-patch-engineer` simultaneously.
4. **Use 1 to all 7 agents** as the situation demands. Simple tasks need one agent; complex issues may need findings from multiple agents combined before writing code.
5. **Agents report findings back.** The orchestrator reads their reports, synthesizes a fix, writes the code, and tests it.

### Agent Roster

| Agent | Domain | Use For |
|-------|--------|---------|
| `game-reverse-engineer` | Binary RE, Ghidra decompilation, code archaeology | Decompiling functions, tracing xrefs, identifying vtable layouts, understanding what code does. **Only agent with Ghidra MCP access.** |
| `netimmerse-engine-dev` | NetImmerse 3.1.1 / Gamebryo engine internals | Scene graph questions, NIF format, renderer pipeline, NiNode hierarchy, engine object lifecycle, headless server architecture |
| `stbc-original-dev` | Design intent, original developer perspective | Ambiguous decompiled code, "was this a bug or intentional?", how features were meant to work, cut content reasoning |
| `python-152-reviewer` | Python 1.5.2 compatibility | Reviewing/writing Python code for BC's embedded interpreter, catching version-incompatible constructs |
| `x86-patch-engineer` | x86-32 instruction encoding, code caves, binary patches | Code cave construction, JMP/CALL displacement calculation, calling convention analysis, VEH handler logic, stack frame layout |
| `win32-crash-analyst` | Crash triage, VEH/SEH, register dumps | Analyzing crash logs, access violations, NULL dereference chains, bad vtable calls, determining root cause from register snapshots |
| `network-protocol-analyst` | UDP protocol, packet traces, handshake flows | Decoding packet_trace.log hex dumps, tracing opcode sequences, identifying where client/server conversations break down |

### Typical Workflows

**Crash investigation:**
1. `win32-crash-analyst` triages the crash log (registers, stack, access pattern)
2. `game-reverse-engineer` decompiles the crashing function and its callers
3. `x86-patch-engineer` designs the binary fix (code cave, EIP skip, or instruction patch)
4. Orchestrator writes the C code in ddraw_main.c

**Client disconnect debugging:**
1. `network-protocol-analyst` decodes the packet trace around the disconnect
2. `game-reverse-engineer` traces the message handler chain
3. `stbc-original-dev` explains expected handshake behavior
4. Orchestrator implements the fix

**New proxy method needed:**
1. `game-reverse-engineer` decompiles the caller to understand expected behavior
2. `netimmerse-engine-dev` explains what the engine expects from the COM interface
3. Orchestrator implements the proxy method

## Ghidra MCP Setup
This project uses a Ghidra MCP server for live decompilation. To set up:
```bash
claude mcp add ghidra --transport stdio -- \
  /path/to/python3 /path/to/GhidraMCP/bridge_mcp_ghidra.py \
  --ghidra-server http://<ghidra-host>:8090/
```
The Ghidra HTTP bridge must be running (GhidraMCP plugin in Ghidra with stbc.exe loaded).
