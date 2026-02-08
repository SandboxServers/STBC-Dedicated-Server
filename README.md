# Star Trek: Bridge Commander - Dedicated Server

A headless dedicated server for Star Trek: Bridge Commander's multiplayer mode, implemented as a DirectDraw proxy DLL.

## How It Works

The game loads our `ddraw.dll` thinking it's the DirectDraw runtime. The DLL intercepts rendering calls (returning stubs for headless operation) while bootstrapping the game engine, embedded Python 1.5 scripting, and the multiplayer networking stack. The result is a fully functional game server with no GPU required.

## Requirements

- **Star Trek: Bridge Commander** (GOG edition tested) installed on Windows
- **WSL2** with `i686-w64-mingw32-gcc` cross-compiler (`apt install gcc-mingw-w64-i686`)
- **Ghidra** with [GhidraMCP](https://github.com/LaurieWired/GhidraMCP) for reverse engineering (optional, for development)

## Quick Start

```bash
# Build the proxy DLL
make build

# Deploy to game directory and launch
make run

# View server logs
make logs
```

The `GAME_DIR` variable defaults to `/mnt/c/GOG Games/Star Trek Bridge Commander`. Override with:
```bash
make GAME_DIR="/path/to/game" deploy
```

## Project Structure

```
src/proxy/          - DDraw proxy DLL (C source, the main codebase)
src/scripts/        - Python scripts deployed to game (Custom/ is checksum-exempt)
config/             - Server configuration files
tools/              - Development helper scripts
docs/               - Reverse engineering notes and protocol documentation
reference/          - Decompiled game code for analysis (not our work)
  decompiled/       - Ghidra C output (19 organized files)
  scripts/          - Decompiled Python scripts (~1228 files)
```

## Current Status

Server boots headless, clients discover via LAN, checksums pass, and packets exchange. Currently investigating a client black screen issue after connection. See [docs/black-screen-investigation.md](docs/black-screen-investigation.md) for details.

## Technical Details

- **Engine**: NetImmerse 3.1 (predecessor to Gamebryo)
- **Rendering**: DirectDraw 7 / Direct3D 7 (all stubbed in headless mode)
- **Networking**: Winsock UDP (TGWinsockNetwork), GameSpy LAN discovery
- **Scripting**: Embedded Python 1.5 with SWIG 1.x bindings
- **Executable**: 32-bit Windows (`stbc.exe`, ~5.9MB, base 0x400000)

See [CLAUDE.md](CLAUDE.md) for full development context and [docs/](docs/) for detailed documentation.
