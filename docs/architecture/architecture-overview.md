> [docs](../README.md) / [architecture](README.md) / architecture-overview.md

# Architecture Overview

How the dedicated server works, from DLL loading to game loop.

## The Proxy DLL Concept

Windows applications load DLLs by searching a series of directories. The **application directory** is searched before the system directory. By placing our own `ddraw.dll` in the game folder, the game loads it instead of the real `C:\Windows\System32\ddraw.dll`.

Bridge Commander calls `DirectDrawCreateEx()` during startup to initialize its renderer. Our DLL exports this function (and all other ddraw.dll exports). When the game calls it, we decide what to do:

- **Dedicated server mode** (`dedicated.cfg` exists): Return stub COM objects that satisfy the interface but do no rendering. The game thinks it has a working GPU.
- **Normal mode** (no `dedicated.cfg`): Forward the call to the real ddraw.dll. The game runs normally with our packet logging active.

This is called a **proxy DLL** because it sits between the application and the real DLL, intercepting calls.

## The COM Interface Chain

The game expects a hierarchy of COM objects:

```
IDirectDraw7         (display adapter - creates surfaces and D3D)
  IDirectDrawSurface7  (render target - the "screen")
  IDirect3D7           (3D subsystem - creates devices)
    IDirect3DDevice7   (GPU device - draws triangles)
```

Each of these is a C struct with a vtable pointer. Our proxy creates fake versions of each:

| File | What It Provides |
|------|-----------------|
| `ddraw_ddraw7.c` | `IDirectDraw7` — display modes, surface creation, cooperative level |
| `ddraw_surface7.c` | `IDirectDrawSurface7` — Lock/Unlock, Blt, Flip (all stubs) |
| `ddraw_d3d7.c` | `IDirect3D7` + `IDirect3DDevice7` — device caps, render state |
| `ddraw_proxy.h` | Struct definitions for all proxy objects |

The game's NetImmerse 3.1 engine reads 236 bytes (59 DWORDs) directly from the Device7 object for hardware caps. Our `ProxyDevice7` struct has padding bytes (`_niPadding[236]`) to satisfy this read without crashing.

## DllMain: What Happens at Load Time

When the game process starts and loads our DLL:

```
DllMain(DLL_PROCESS_ATTACH)
  |
  +-- Resolve base path (game directory)
  +-- Open ddraw_proxy.log
  +-- Open packet_trace.log
  +-- Set CWD to game directory
  |
  +-- Is OBSERVE_ONLY build?
  |     YES: Log passively, hook IAT for packet tracing, done
  |     NO:  Continue to server setup...
  |
  +-- Install CrashDumpHandler (SetUnhandledExceptionFilter)
  +-- Check for dedicated.cfg
  |     NOT FOUND: Forward mode (normal game), done
  |     FOUND:     Stub mode (dedicated server), continue...
  |
  +-- Redirect stdout/stderr to dedicated_console.log
  +-- Suppress CRT abort dialogs
  +-- Apply all 14+ binary patches (see below)
  +-- Start heartbeat thread
  +-- Load real ddraw.dll from System32 (for forward-mode exports)
```

## Binary Patches

The game executable was not designed to run headless. It assumes a GPU, a window, texture memory, and a scene graph full of loaded 3D models. To make it work without those, we modify the game's code at runtime.

Each **patch** is a function in `ddraw_main.c` that uses `VirtualProtect` + `WriteProcessMemory` (or direct memory writes) to change specific bytes in `stbc.exe`'s code at known addresses. Three types:

1. **NOP patches** — Replace instructions with `0x90` (NOP) to skip problematic code
2. **JMP patches** — Change a conditional jump to unconditional (e.g., `JNZ` to `JMP`) to force a code path
3. **Code caves** — Allocate new executable memory with `VirtualAlloc`, write new x86 instructions into it, then redirect the original code to jump there. The cave runs our logic and jumps back.

See [binary-patching-primer.md](../guides/binary-patching-primer.md) for a detailed explanation with examples.

## Bootstrap Phases

After DllMain finishes, the game initializes normally. It calls `DirectDrawCreateEx()` (which we intercept), creates its window, loads Python, and starts the engine. Our code sets up the multiplayer server in 4 phases, driven from a periodic timer:

### Phase 0: Flag Setting
Direct memory writes to set the game into host/multiplayer mode:
- `IsClient` (0x0097FA88) = 0
- `IsHost` (0x0097FA89) = 1
- `IsMultiplayer` (0x0097FA8A) = 1

### Phase 1: Network Initialization
Calls the game's own `FUN_00445d90` (UtopiaModule initialization) which creates the `TGWinsockNetwork` object, binds the UDP socket, and sets up the packet send/receive infrastructure.

### Phase 2: MultiplayerGame Creation
Calls `FUN_00504f10` (TopWindow_SetupMultiplayerGame) which creates the multiplayer game session object and registers it at `0x0097E238`.

### Phase 3: Automation
Invokes `DedicatedServer.py`'s `TopWindowInitialized()` via Python, which:
- Sets server name, captain name, max players
- Creates GameSpy for LAN discovery
- Enables new player handling
- Starts the game session

### Phase 4: Game Loop
A 33ms Windows timer (~30 fps) runs `GameLoopTimerProc`:
1. Call `UtopiaApp_MainTick` — event processing, simulation updates
2. Call `TGNetwork::Update` — send/receive packets
3. Run GameSpy query router — handle LAN discovery packets
4. Peer detection — scan WSN peer array for new connections
5. InitNetwork scheduling — call `Mission1.InitNetwork(peerID)` 30 ticks after peer appears
6. DeferredInitObject — poll for new ship objects, call Python to load NIF model + create subsystems
7. Monitoring and diagnostics

## The Two Worlds: C and Python

The server operates in two layers:

### C layer (`ddraw_main.c` → 7 split `.inc.c` files, ~6260 lines total)
- DLL lifecycle, binary patches, crash handling (`core_runtime_and_exports.inc.c`, `binary_patches_and_python_bridge.inc.c`)
- Game loop timer driving the engine (`game_loop_and_bootstrap.inc.c`)
- Peer detection and InitNetwork scheduling (`game_loop_and_bootstrap.inc.c`)
- DeferredInitObject ship creation polling (`game_loop_and_bootstrap.inc.c`)
- Packet trace system: decrypt, decode, log all UDP traffic (`packet_trace_and_decode.inc.c`)
- Direct memory manipulation of game engine globals
- IAT hooks for sendto/recvfrom interception (`runtime_hooks_and_iat.inc.c`, `socket_and_input_hooks.inc.c`)
- TGMessage factory hooks (`message_factory_hooks.inc.c`)

The C source is split into 7 logical `.inc.c` files that are `#include`d into `ddraw_main.c`
as a single translation unit. This preserves symbol visibility and link order while keeping
each file focused on one concern.

### Python layer (`scripts/Custom/DedicatedServer.py`)
- Server configuration (name, map, player count, game rules)
- SWIG API calls to game engine (`App.TopWindow_Method(obj, args)`)
- Import hooks to wrap mission scripts with error handling
- Scoring dictionary registration for player tracking
- DeferredInitObject: loads NIF models and creates subsystems for client ships

Python 1.5 scripts run inside the game's embedded interpreter. They use the SWIG-generated `App` module to call C++ engine functions. The C layer sets up the engine state that Python then configures and drives.

## Dual Build System

The same source files produce two different DLLs:

| Build | DLL | Purpose |
|-------|-----|---------|
| `make build` | `ddraw.dll` | Full server: patches, game loop, crash handler |
| `make build-observe` | `ddraw_observe.dll` | Passive observer: packet/event logging only, zero patches |

The observer build is compiled with `-DOBSERVE_ONLY`. All server-specific code is wrapped in `#ifndef OBSERVE_ONLY` guards. The observer DLL is deployed to the client and stock-dedi directories for diagnostic logging without modifying game behavior.

## Packet Flow

All game network traffic passes through Winsock UDP on a single socket. The traffic includes:

1. **GameSpy queries** — LAN discovery (plaintext, start with `\`)
2. **TGNetwork packets** — Game traffic (encrypted with AlbyRules! cipher)

Our IAT hooks on `sendto` and `recvfrom` capture every packet. Game packets are decrypted and decoded into `packet_trace.log`. GameSpy packets are logged as plaintext.

See [alby-rules-cipher-analysis.md](../networking/alby-rules-cipher-analysis.md) for the encryption details and [wire-format-spec.md](../protocol/wire-format-spec.md) for the packet format.

## Key Engine Globals

The game engine stores important state at fixed memory addresses in `stbc.exe`:

| Address | What | Used For |
|---------|------|----------|
| 0x0097FA00 | UtopiaModule base | Root of engine object hierarchy |
| 0x0097FA78 | TGWinsockNetwork* | Network subsystem (send/receive packets) |
| 0x0097FA7C | GameSpy ptr | LAN discovery (+0xDC = qr_t query/response) |
| 0x0097FA80 | NetFile/ChecksumMgr | File integrity checking |
| 0x0097E238 | TopWindow/MultiplayerGame | Active game session |
| 0x009A09D0 | Clock object | Game time (+0x90) and frame time (+0x54) |

These addresses are hardcoded constants found through Ghidra reverse engineering. They do not change between runs (the executable is not ASLR-enabled).
