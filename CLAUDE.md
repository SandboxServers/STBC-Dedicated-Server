# STBC Dedicated Server - Development Context

Headless dedicated server for Star Trek: Bridge Commander multiplayer, implemented as a DDraw proxy DLL. Cross-compiled from WSL2, drives the game engine via C code + embedded Python 1.5.

## Repo Layout
- `src/proxy/ddraw_main.c` - Entry point, includes 7 split files (~6260 lines total)
- `src/proxy/ddraw_main/` - Split implementation files:
  - `binary_patches_and_python_bridge.inc.c` - All binary patches, Python bridge (RunPyCode)
  - `game_loop_and_bootstrap.inc.c` - GameLoopTimerProc, bootstrap phases, DeferredInitObject
  - `core_runtime_and_exports.inc.c` - DllMain, COM proxy setup, exports
  - `packet_trace_and_decode.inc.c` - Packet tracing, AlbyRules cipher, opcode decoding
  - `socket_and_input_hooks.inc.c` - sendto/recvfrom hooks, input handling
  - `runtime_hooks_and_iat.inc.c` - IAT hooking, runtime patches
  - `message_factory_hooks.inc.c` - TGMessage factory interception
- `src/proxy/` - Other proxy DLL sources (ddraw7, surface7, d3d7, header, def)
- `src/scripts/Custom/DedicatedServer.py` - Python server config (checksum exempt)
- `src/scripts/Custom/ClientLogger.py` - Client-side diagnostic hooks (checksum exempt)
- `src/scripts/Local.py` - Server custom hook (checksum exempt)
- `src/scripts/ClientLocal.py` - Client custom hook (deployed as Local.py on client)
- `config/dedicated.cfg` - Empty trigger file (presence enables dedicated mode)
- `game/server/` - Live server game install (gitignored except readme.md)
- `game/client/` - Live client game install (gitignored except readme.md)
- `tools/` - Ghidra annotation scripts and analysis utilities
- `engine/gamebyro-1.2-source/` - Gamebryo 1.2 full source (reference for NI class implementations)
- `engine/mwse/` - MWSE reverse-engineered NI 4.0.0.2 headers (identical struct sizes to NI 3.1)
- `engine/nif.xml` - NIF format spec from niftools (V3.1 field definitions for 21 of 42 NI 3.1-only classes)
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

## Current Status: FUNCTIONAL MULTIPLAYER (COLLISION + SUBSYSTEM DAMAGE WORKING)
Client connects, checksums pass, reaches ship selection, picks ship, and plays with working
collision damage and subsystem damage. The main multiplayer loop is functional.

### What Works
- Headless boot (all 4 bootstrap phases), Python DedicatedServer.TopWindowInitialized() runs
- MultiplayerGame: ReadyForNewPlayers=1, MaxPlayers=8, ProcessingPackets=1
- GameSpy LAN discovery, checksum exchange (4 rounds), keepalive
- Import hook patches mission handlers for headless mode (func_code replacement)
- Client reaches ship selection screen, player appears on scoreboard
- **DeferredInitObject**: Python-driven ship creation with real NIF models and subsystems
- **InitNetwork timing**: Peer-array detection fires within ~1.4s (matches stock ~2s timing)
- **Collision damage**: Ships take hull and subsystem damage from collisions
- **Subsystem damage**: Individual subsystems (shields, weapons, engines) take and report damage
- **StateUpdate flags=0x20**: Server sends real subsystem health data (was 0x00/empty)
- Packet trace system: full hex dumps to `game/server/packet_trace.log`
- Client-side logging: `game/client/client_debug.log`
- CrashDumpHandler (SetUnhandledExceptionFilter) logs full diagnostics on any crash

### Known Issues
- First connection always times out (client must reconnect) — stock-dedi does NOT have this issue
- `scoring dict fix rc=-1` - Python code for SCORE_MESSAGE send has an error
- Server's own ship object (player 0) still sends flags=0x00 (harmless — host's dummy ship)
- 0x35 GameState byte[1]: we send 0x01, stock sends 0x09 (lobby slot count)
- Double NewPlayerInGame: engine handler + our GameLoopTimerProc both fire

### Key Fixes Applied (in ddraw_main.c split files)
1. **TGL FindEntry NULL fix** - code cave at 0x006D1E10, returns NULL when ECX is NULL
2. **Network NULL list guard** - code cave at 0x005B1D57, clears SUB/WPN flags when ship+0x284 NULL
3. **Subsystem hash check fix** - code cave at 0x005B22B5, prevents false anti-cheat kicks
4. **Compressed vector read guard** - validates vtable at 0x006D2EB0/0x006D2FD0
5. **CWD fix** - SetCurrentDirectoryA(g_szBasePath) in DllMain
6. **NewPlayerInGame handshake** - GameLoopTimerProc calls FUN_006a1e70 when player count increases
7. **Scoring dict registration** - adds player to scoring dictionaries after NewPlayerInGame
8. **Renderer pipeline proxy** - D3D7/DDraw7/Surface7 COM proxies provide valid objects to engine
9. **DeferredInitObject** - Python-driven ship creation: loads NIF, creates subsystems, populates ship+0x284
10. **InitNetwork peer-array detection** - detects new peers from WSN peer array (replaces broken bc-flag)

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

### Three Message Dispatchers
1. **NetFile dispatcher (FUN_006a3cd0)**: Checksums/file opcodes 0x20-0x27
2. **MultiplayerGame dispatcher (0x0069f2a0)**: Game opcodes 0x00-0x2A (jump table at 0x0069F534, 41 entries)
3. **MultiplayerWindow dispatcher (FUN_00504c10)**: Opcodes 0x00, 0x01, 0x16 (UI-level settings)
4. **Python SendTGMessage**: Opcodes 0x2C-0x39 (chat, scoring, game flow) bypass C++ dispatcher

### Game Opcode Table (complete, verified from jump table + packet traces)
| Opcode | Name | Handler | Type |
|--------|------|---------|------|
| 0x00 | Settings | FUN_00504d30 | Game config (gameTime, map, collision) — MultiplayerWindow dispatcher |
| 0x01 | GameInit | FUN_00504f10 | Game start trigger — MultiplayerWindow dispatcher |
| 0x02 | ObjCreate | FUN_0069f620 | Non-team object creation |
| 0x03 | ObjCreateTeam | FUN_0069f620 | Ship creation with team |
| 0x04 | (dead) | DEFAULT | Jump table default; boot sent via TGBootPlayerMessage |
| 0x05 | (dead) | DEFAULT | Jump table default |
| 0x06 | PythonEvent | FUN_0069f880 | **Primary event forwarding** (3432/session) |
| 0x07 | StartFiring | FUN_0069fda0 | Weapon fire begin (2282/session) |
| 0x08 | StopFiring | FUN_0069fda0 | Weapon fire end |
| 0x09 | StopFiringAtTarget | FUN_0069fda0 | Stop firing at specific target |
| 0x0A | SubsysStatus | FUN_0069fda0 | Subsystem toggle (shields, etc.) |
| 0x0B | AddToRepairList | FUN_0069fda0 | Crew repair assignment |
| 0x0C | ClientEvent | FUN_0069fda0 | Generic event forward (preserve=0) |
| 0x0D | PythonEvent2 | FUN_0069f880 | Alternate Python event path |
| 0x0E | StartCloak | FUN_0069fda0 | Cloak engage (event 0x008000E3) |
| 0x0F | StopCloak | FUN_0069fda0 | Cloak disengage (event 0x008000E5) |
| 0x10 | StartWarp | FUN_0069fda0 | Warp drive engage |
| 0x11 | RepairListPriority | FUN_0069fda0 | Repair priority ordering |
| 0x12 | SetPhaserLevel | FUN_0069fda0 | Phaser power/intensity (event 0x008000E0) |
| 0x13 | HostMsg | FUN_006A01B0 | Host message dispatch (self-destruct etc.) |
| 0x14 | DestroyObject | FUN_006a01e0 | Object destruction |
| 0x15 | CollisionEffect | FUN_006a2470 | **Collision damage relay** (84/session) |
| 0x16 | UICollisionSetting | FUN_00504c70 | Collision toggle (MultiplayerWindow dispatcher) |
| 0x17 | DeletePlayerUI | FUN_006a1360 | Remove player from scoreboard |
| 0x19 | TorpedoFire | FUN_0069f930 | Torpedo launch (897/session) |
| 0x1A | BeamFire | FUN_0069fbb0 | Beam weapon hit |
| 0x1B | TorpTypeChange | FUN_0069fda0 | Torpedo type switch |
| 0x1D | ObjNotFound | FUN_006a0490 | Object lookup failure |
| 0x1E | RequestObj | FUN_006a02a0 | Request object data |
| 0x1F | EnterSet | FUN_006a05e0 | Enter game set |
| 0x29 | Explosion | FUN_006a0080 | Explosion damage (S→C only) |
| 0x2A | NewPlayerInGame | FUN_006a1e70 | Player join handshake |

### Python-Level Messages (via SendTGMessage, bypass C++ dispatcher)
| Byte | Name | Notes |
|------|------|-------|
| 0x2C | CHAT_MESSAGE | We forward this |
| 0x2D | TEAM_CHAT_MESSAGE | We forward this |
| 0x35 | MISSION_INIT_MESSAGE | Game config |
| 0x36 | SCORE_CHANGE_MESSAGE | Score deltas |
| 0x37 | SCORE_MESSAGE | Full score sync |
| 0x38 | END_GAME_MESSAGE | Game over |
| 0x39 | RESTART_GAME_MESSAGE | Game restart |

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
- [docs/dedicated-server.md](docs/dedicated-server.md) - Bootstrap sequence, patches, crash handling
- [docs/architecture-overview.md](docs/architecture-overview.md) - How the proxy DLL works, COM chain, bootstrap phases
- [docs/multiplayer-flow.md](docs/multiplayer-flow.md) - Complete client/server join flow (connect → play)
- [docs/wire-format-spec.md](docs/wire-format-spec.md) - Complete wire format: opcodes, StateUpdate, compressed types
- [docs/network-protocol.md](docs/network-protocol.md) - Protocol architecture, event system, handler tables
- [docs/message-trace-vs-packet-trace.md](docs/message-trace-vs-packet-trace.md) - Stock-dedi opcode cross-reference
- [docs/subsystem-trace-analysis.md](docs/subsystem-trace-analysis.md) - Ship subsystem creation pipeline (from stock trace)
- [docs/empty-stateupdate-root-cause.md](docs/empty-stateupdate-root-cause.md) - Why flags=0x00 happened (RESOLVED)
- [docs/black-screen-investigation.md](docs/black-screen-investigation.md) - Client disconnect investigation (RESOLVED)
- [docs/veh-cascade-triage.md](docs/veh-cascade-triage.md) - Why VEH was removed (historical)
- [docs/lessons-learned.md](docs/lessons-learned.md) - Debugging techniques, pitfalls, protocol discoveries
- [docs/troubleshooting.md](docs/troubleshooting.md) - Symptom-to-cause quick reference
- [docs/swig-api.md](docs/swig-api.md) - SWIG function reference
- [docs/decompiled-functions.md](docs/decompiled-functions.md) - Key function analysis
- [docs/function-map.md](docs/function-map.md) - 18K-function organized map
- [docs/damage-system.md](docs/damage-system.md) - Complete damage pipeline: collision, weapon, explosion paths, gate checks, subsystem distribution
- [docs/rtti-class-catalog.md](docs/rtti-class-catalog.md) - Complete class catalog: 129 NI, 124 TG, ~420 game classes (RTTI extraction)
- [docs/gamebryo-cross-reference.md](docs/gamebryo-cross-reference.md) - 129 NI classes cross-referenced against Gb 1.2, MWSE, and nif.xml (87 Gb match, 21/42 NI 3.1-only have nif.xml field defs)
- [docs/nirtti-factory-catalog.md](docs/nirtti-factory-catalog.md) - All 117 NiRTTI factory registrations with addresses
- [docs/netimmerse-vtables.md](docs/netimmerse-vtables.md) - Vtable maps for 6 core NI classes (NiObject through NiTriShape)
- [docs/function-mapping-report.md](docs/function-mapping-report.md) - Function naming coverage: ~6,031 of 18K functions named (33%), script suite docs
- [docs/gamespy-discovery.md](docs/gamespy-discovery.md) - GameSpy LAN/internet discovery, master server protocol (UDP heartbeat + TCP browsing), QR1 challenge-response crypto
- [docs/cut-content-analysis.md](docs/cut-content-analysis.md) - Cut/hidden features: ghost missions (Borg Hunt, Enterprise Assault), fleet command AI, tractor docking, self-destruct, dev tools, restoration priorities
- [docs/disconnect-flow.md](docs/disconnect-flow.md) - Player disconnect flow: 3 detection paths (timeout/graceful/kick), peer deletion convergence, event cascade, cleanup opcodes (0x14/0x17/0x18), Python layer
- [docs/collision-detection-system.md](docs/collision-detection-system.md) - Collision detection: 3-tier (sweep-and-prune -> bounding sphere -> per-type narrow), ProximityManager class, energy formula, call graph
- [docs/collision-effect-protocol.md](docs/collision-effect-protocol.md) - CollisionEffect (opcode 0x15) RE: wire format (22+N*4 bytes), CompressedVec4_Byte contacts, handler validation chain, CollisionEvent class (0x44 bytes), event registration, vtable maps
- [docs/objcreate-unknown-species-analysis.md](docs/objcreate-unknown-species-analysis.md) - ObjCreate handler behavior with unknown species: relay-after-create, empty hull ships, three failure modes, crash risks
- [docs/combat-mechanics-re.md](docs/combat-mechanics-re.md) - Consolidated combat RE: shields (facing/absorption/recharge), cloak (4-state machine), weapons (phaser charge/torpedo reload), repair (queue/rate formula), tractor (multiplicative drag, no damage), Sovereign HP values, OpenBC corrections
- [docs/shield-system.md](docs/shield-system.md) - Shield system: 6-facing ellipsoid, max-component facing determination, area vs directed absorption, power-budget recharge, cloak interaction
- [docs/cloaking-state-machine.md](docs/cloaking-state-machine.md) - Cloak device: states 0/2/3/5 (ghost 1/4), transition timer, shield disable (HP preserved), weapon gating via PoweredSubsystem, energy failure auto-decloak
- [docs/weapon-firing-mechanics.md](docs/weapon-firing-mechanics.md) - Weapons: phaser charge/discharge/intensity, torpedo reload/type-switch, CanFire gates, WeaponSystem update loop, wire formats
- [docs/repair-tractor-analysis.md](docs/repair-tractor-analysis.md) - Repair: simultaneous teams, no queue limit, rate formula with RepairComplexity. Tractor: 6 modes (HOLD/TOW/PULL/PUSH/DOCK), multiplicative speed drag, no direct damage
- [docs/cf16-explosion-encoding.md](docs/cf16-explosion-encoding.md) - CF16 format: BASE=0.001, MULT=10.0, 8 scales, 4096 mantissa steps. Explosion sender/receiver. Precision analysis for mod weapon-type IDs (15/25/273/2063). Scale 7 loses integer precision above 1000.
- [docs/tgmessage-routing.md](docs/tgmessage-routing.md) - TGMessage routing RE: relay-all (no whitelist), opaque payload, star topology, no max type check, mod compatibility (KM/BCR custom types). Two-layer type system (transport vs game opcode)
- [docs/tgmessage-routing-cleanroom.md](docs/tgmessage-routing-cleanroom.md) - Clean-room behavioral spec for TGMessage routing: no addresses, suitable for reimplementation. Behavioral guarantees, available opcode ranges, known mod allocations
- [docs/stateupdate-subsystem-wire-format.md](docs/stateupdate-subsystem-wire-format.md) - Subsystem health wire format: linked list order (not fixed table), hierarchical WriteState (3 formats), round-robin serializer, CT_ type constants, Sovereign example

## Ghidra Annotation Scripts
Bulk annotation scripts in `tools/`. Run from Ghidra Script Manager with stbc.exe loaded.
Run order: globals → nirtti → swig → python_capi → pymodules → vtables → swig_targets → discover_strings
- `tools/ghidra_annotate_globals.py` - Labels 13 globals, 62 key RE'd functions, 22 Python module tables (97 total)
- `tools/ghidra_annotate_nirtti.py` - Labels 117 NiRTTI factory + 117 registration functions (234 total)
- `tools/ghidra_annotate_swig.py` - Names 3,990 SWIG wrapper functions from PyMethodDef table
- `tools/ghidra_annotate_python_capi.py` - Names 113 Python C API functions, 10 module inits, type objects, globals (137 total)
- `tools/ghidra_annotate_pymodules.py` - Walks 21 Python module method tables, names 266 C implementations
- `tools/ghidra_annotate_vtables.py` - Auto-discovers 97 vtables from NiRTTI factories: 1,090 virtuals + 96 ctors + 84 dtors (1,270 total)
- `tools/ghidra_annotate_swig_targets.py` - Traces SWIG wrappers to C++ targets (4 named; 3,986 are inline field accessors)
- `tools/ghidra_discover_strings.py` - Names 33 functions from debug strings + adds 515 comments (runs last)
- See [docs/function-mapping-report.md](docs/function-mapping-report.md) for full coverage (~6,031 functions named, 33% of 18,247)

## Knowledge Preservation

After completing long-form reverse engineering analysis where findings are high-confidence (verified against live game traces or decompiled code), **always**:
1. Write or update a `docs/` markdown file with the findings (function addresses, call graphs, data layouts, gate conditions)
2. Update agent memory files with key discoveries for cross-session continuity
3. Add new docs to the Documentation Index above

This ensures hard-won RE knowledge is never lost between sessions.

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
