# Star Trek: Bridge Commander - Dedicated Server

A headless dedicated server for Star Trek: Bridge Commander's multiplayer mode, implemented as a DirectDraw proxy DLL.

## How It Works

The game loads our `ddraw.dll` thinking it's the DirectDraw runtime. The DLL intercepts rendering calls (returning stubs for headless operation) while bootstrapping the game engine, embedded Python 1.5 scripting, and the multiplayer networking stack. The result is a fully functional game server with no GPU required.

14 binary patches fix crash sites and skip renderer-dependent code paths at the x86 instruction level. A crash dump handler (`SetUnhandledExceptionFilter`) logs full diagnostics if anything unexpected occurs.

## Requirements

- **Star Trek: Bridge Commander** (GOG edition tested) installed in `game/server/` and `game/client/`
- **WSL2** with `i686-w64-mingw32-gcc` cross-compiler (`apt install gcc-mingw-w64-i686`)
- **Ghidra** with [GhidraMCP](https://github.com/LaurieWired/GhidraMCP) for reverse engineering (optional, for development)

## Quick Start

```bash
# Build the proxy DLL
make build

# Deploy to server game dir and launch
make run-server

# In another terminal, deploy client scripts and launch client
make run-client

# View server logs
make logs-server
```

## Build Targets

| Target | Description |
|--------|-------------|
| `make build` | Cross-compile server `ddraw.dll` |
| `make build-observe` | Cross-compile passive observer `ddraw.dll` |
| `make deploy` | Deploy to both server and client game dirs |
| `make deploy-server` | Deploy proxy DLL + server scripts to `game/server/` |
| `make deploy-client` | Deploy observer DLL + client scripts to `game/client/` |
| `make deploy-stockdedi` | Deploy observer DLL to stock dedicated server |
| `make run-server` | Deploy + launch server |
| `make run-client` | Deploy + launch client |
| `make run-stockdedi` | Deploy + launch stock dedicated server (baseline comparison) |
| `make logs-server` | Tail server logs (proxy, packet trace, dedicated init) |
| `make logs-client` | Tail client debug log |
| `make logs-stockdedi` | Tail stock dedicated server logs |
| `make kill` | Kill all running `stbc.exe` processes |
| `make clean` | Remove build artifacts |

## Project Structure

```
src/proxy/              DDraw proxy DLL (C source)
  ddraw_main.c          Main file: patches, game loop, crash handler (~4800 lines)
  ddraw_ddraw7.c        IDirectDraw7 proxy (display modes, surface creation)
  ddraw_d3d7.c          IDirect3D7 + IDirect3DDevice7 proxy
  ddraw_surface7.c      IDirectDrawSurface7 proxy (Lock/Blt stubs)
  ddraw_proxy.h         Shared structures and declarations
  ddraw.def             DLL export definitions
src/scripts/            Python scripts deployed to game
  Custom/               Checksum-exempt server scripts
    DedicatedServer.py  Server config and bootstrap (network, systems, settings)
    ClientLogger.py     Client-side diagnostic hooks
    Observer.py         Passive event counter (for stock-dedi analysis)
    StateDumper.py      F12 state dump to file
  Local.py              Server-side hook (checksum exempt)
  ClientLocal.py        Client-side hook (deployed as Local.py on client)
config/                 Server configuration files
  dedicated.cfg         Trigger file (presence enables dedicated mode)
docs/                   Reverse engineering notes and protocol documentation
reference/              Decompiled game code for analysis
  decompiled/           Ghidra C output (19 organized files, ~15MB)
  scripts/              Decompiled Python scripts (~1228 files)
game/                   Live game installs (gitignored)
  server/               Server game directory
  client/               Client game directory
  stock-dedi/           Stock dedicated server (baseline comparison)
```

## Current Status

**Client disconnects ~3 seconds after ship selection.**

The server boots headless through all 4 phases, clients discover via LAN, checksums pass, and the client reaches ship selection with the player visible on the scoreboard. However, the client disconnects shortly after because the server sends empty StateUpdate packets (flags=0x00 instead of 0x20 with subsystem data). Root cause: NIF ship models can't load without a renderer, so the subsystem list at ship+0x284 is NULL.

See [docs/black-screen-investigation.md](docs/black-screen-investigation.md) for the current investigation and [docs/empty-stateupdate-root-cause.md](docs/empty-stateupdate-root-cause.md) for the technical root cause analysis.

## Technical Details

- **Engine**: NetImmerse 3.1 (predecessor to Gamebryo)
- **Graphics**: DirectDraw 7 / Direct3D 7 (all stubbed for headless operation)
- **Networking**: Winsock UDP (`TGWinsockNetwork`), GameSpy LAN discovery
- **Scripting**: Embedded Python 1.5 with SWIG 1.x bindings
- **Executable**: 32-bit Windows (`stbc.exe`, ~5.9MB, base 0x400000)

## Documentation

| Document | Description |
|----------|-------------|
| [black-screen-investigation.md](docs/black-screen-investigation.md) | Current issue: client disconnect after ship selection |
| [dedicated-server.md](docs/dedicated-server.md) | Bootstrap sequence, active patches, crash handling |
| [wire-format-spec.md](docs/wire-format-spec.md) | UDP wire format, opcodes, fragmentation |
| [network-protocol.md](docs/network-protocol.md) | Protocol architecture, event system, handler tables |
| [multiplayer-flow.md](docs/multiplayer-flow.md) | Client/server join flow from discovery to gameplay |
| [empty-stateupdate-root-cause.md](docs/empty-stateupdate-root-cause.md) | Why server sends empty state updates |
| [veh-cascade-triage.md](docs/veh-cascade-triage.md) | Why VEH crash recovery was removed |
| [swig-api.md](docs/swig-api.md) | SWIG Python binding reference |
| [decompiled-functions.md](docs/decompiled-functions.md) | Key function analysis from Ghidra |
| [function-map.md](docs/function-map.md) | Organized map of ~18K game functions |
| [lessons-learned.md](docs/lessons-learned.md) | Python 1.5 quirks, debugging pitfalls |
| [message-trace-vs-packet-trace.md](docs/message-trace-vs-packet-trace.md) | Stock-dedi opcode cross-reference |

## Diagnostic Logs

| Log File | Location | Content |
|----------|----------|---------|
| `ddraw_proxy.log` | Server game dir | Main proxy log (boot, patches, game loop events) |
| `packet_trace.log` | Server game dir | Full packet hex dumps with opcode decoding |
| `tick_trace.log` | Server game dir | Per-tick CSV (players, packets, timers, memory) |
| `dedicated_init.log` | Server game dir | Python-side boot and runtime log |
| `crash_dump.log` | Server game dir | Full crash diagnostics (registers, stack, code bytes) |
| `client_debug.log` | Client game dir | Client-side handler tracing |

See [CLAUDE.md](CLAUDE.md) for full development context including key globals, address references, and agent workflow.
