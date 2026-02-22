> [docs](../README.md) / [guides](README.md) / developer-workflow.md

# Developer Workflow Guide

How to set up, build, test, and debug the dedicated server.

## Initial Setup

### Prerequisites
1. **WSL2** on Windows 10/11
2. **Cross-compiler**: `sudo apt install gcc-mingw-w64-i686`
3. **Star Trek: Bridge Commander** (GOG edition tested)

### Populating Game Directories

The repo expects three game installs under `game/` (all gitignored):

```
game/server/      Your dedicated server (uses stbc.exe)
game/client/      A client to test against (uses bridgecommander.exe)
game/stock-dedi/  Vanilla BC install for baseline comparison
```

To set up:
1. Install BC from GOG to any location
2. Copy the full install three times into `game/server/`, `game/client/`, `game/stock-dedi/`
3. The server directory needs `stbc.exe` (the headless-capable executable) — this is already in the GOG install
4. The client directories use `bridgecommander.exe` (the standard launcher)

### First Build

```bash
make clean && make build
```

This cross-compiles `ddraw.dll` using `i686-w64-mingw32-gcc`. Expected: 2 warnings about functions only used in the OBSERVE_ONLY build.

## The Inner Loop

The typical edit-build-test cycle:

### 1. Make your change
Edit `src/proxy/ddraw_main.c` (C) or `src/scripts/Custom/*.py` (Python).

### 2. Build
```bash
make build
```
Takes ~2 seconds. Fix any compiler errors.

### 3. Deploy and run
```bash
make run-server    # Kills existing stbc.exe, deploys, launches server
```
In a second terminal:
```bash
make run-client    # Deploys client scripts, launches client
```

### 4. Test
- In the client, go to **Multiplayer > LAN** — you should see the server listed
- Click to join, wait for checksum exchange, select a ship
- Watch the server logs for what happens

### 5. Check logs
```bash
make logs-server   # Dumps all server logs to terminal
```

### Python Changes: Delete .pyc Files

**Critical**: After editing any `.py` file, you must delete the corresponding `.pyc` file or the game will use the cached bytecode. The `make deploy-server` target does this automatically via `rm -f *.pyc`, but if you're manually copying files, remember to clean up.

## Log Files and What They Tell You

### Server-side logs (in `game/server/`)

| Log | What It Contains | Check When... |
|-----|-----------------|---------------|
| `ddraw_proxy.log` | DLL lifecycle, patches applied, phase transitions, game loop events | Server won't boot, patches fail, phases don't complete |
| `packet_trace.log` | Every UDP packet (decrypted, decoded, hex-dumped) | Client can't connect, checksums fail, packets malformed |
| `tick_trace.log` | Per-tick CSV: players, packets, timers, memory usage | Performance issues, timing problems, memory leaks |
| `pydebug.log` | `OutputDebugStringA` capture (includes `App.CPyDebug` output) | Python/engine debug prints, CPyDebug milestones |
| `dedicated_init.log` | Python-side logging from DedicatedServer.py | Python crashes, configuration issues, SWIG call failures |
| `crash_dump.log` | Full crash diagnostics (registers, stack, code bytes) | Server crashes or silently exits |
| `dedicated_console.log` | Redirected stdout/stderr from the game engine | Python print output, engine warnings |
| `state_dump.log` | Debug console output redirected to file | F12 state dumps, Python exceptions |

### Client-side logs (in `game/client/`)

| Log | What It Contains | Check When... |
|-----|-----------------|---------------|
| `ddraw_proxy.log` | Observer DLL lifecycle, IAT hooks | Client DLL loading issues |
| `pydebug.log` | `OutputDebugStringA` capture (includes `App.CPyDebug` output) | CPyDebug output and engine debug lines |
| `packet_trace.log` | Client's view of all packets | Compare with server trace to find divergence |
| `client_debug.log` | Handler tracing from ClientLogger.py | Client-side handler errors |
| `message_trace.log` | Deserialized message types (receive path only) | What messages the client actually processes |

### Reading Order for Common Issues

**Server won't boot:**
1. `ddraw_proxy.log` — Did patches apply? Did phases complete?
2. `dedicated_init.log` — Did Python code error?
3. `crash_dump.log` — Did it crash?

**Client can't find server:**
1. Server `ddraw_proxy.log` — Is GameSpy heartbeat running?
2. Server `packet_trace.log` — Are GameSpy queries arriving?

**Client connects but disconnects:**
1. Server `packet_trace.log` — Find the client's packets, check opcode flow
2. Client `packet_trace.log` — What was the last packet the client received?
3. Compare both traces at the same timestamp

**Server crashes:**
1. `crash_dump.log` — Registers, stack walk, code bytes around crash point
2. `ddraw_proxy.log` — Last few log entries before crash

## Correlating Packet Traces

Both server and client produce `packet_trace.log`. To compare them:

1. Look for the same packet sequence number (`#seq`) in both files
2. Server shows `S->C` (sent to client) and `C->S` (received from client)
3. Client shows the reverse perspective
4. Timestamps are wall-clock, so they won't match exactly — use sequence numbers

The `message_trace.log` (client only, from Observer.py) shows the **receive path** — what the engine's message factory actually deserializes. Every `C->S` opcode in `packet_trace.log` should have a matching entry in `message_trace.log`. `S->C` messages won't appear (they're not deserialized on the server).

## Stock-Dedi Comparison

The stock dedicated server (a normal BC instance hosting a game) is our ground truth. To capture a baseline:

```bash
# Terminal 1: Launch stock server with observer DLL
make run-stockdedi

# Terminal 2: Launch client to connect
make run-client

# After testing, check stock-dedi logs:
make logs-stockdedi
```

Compare `game/stock-dedi/packet_trace.log` against `game/server/packet_trace.log` to find where our server's behavior diverges from stock.

## Build Variants

| Command | Output | Use Case |
|---------|--------|----------|
| `make build` | `ddraw.dll` | Server: full patches, game loop, crash handler |
| `make build-observe` | `ddraw_observe.dll` | Observer: passive logging, zero patches |

The observer DLL is automatically built by `deploy-client` and `deploy-stockdedi`. You only need `make build` for the server.

## Killing Stuck Processes

BC sometimes hangs on exit. Use:
```bash
make kill    # taskkill /f /im stbc.exe
```

The `deploy-server` and `deploy-stockdedi` targets also kill existing processes before deploying.

## Common Gotchas

- **CWD matters**: The game expects its working directory to be the game folder. The proxy DLL sets this in DllMain, but if you launch `stbc.exe` from an unusual location, paths may break.
- **One server at a time**: Both server and stock-dedi use `stbc.exe`, so `make kill` will kill both.
- **Port 22101**: The game binds UDP port 22101. Only one server can use it at a time.
- **First connection timeout**: The first client connection always times out. The client must reconnect. This is a known issue we haven't fixed yet.
- **Antivirus warnings**: A DLL named `ddraw.dll` in a game directory triggers some antivirus heuristics. You may need to add an exclusion.
