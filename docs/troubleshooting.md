# Troubleshooting Guide

Known issues, their symptoms, and how to diagnose them.

## Quick Reference: Symptom to Cause

| Symptom | Log Signature | Root Cause | Status |
|---------|--------------|------------|--------|
| Server doesn't boot | `ddraw_proxy.log` stops mid-phase | Python error or crash during bootstrap | Check `dedicated_init.log` and `crash_dump.log` |
| Client can't find server on LAN | No GameSpy queries in `packet_trace.log` | GameSpy heartbeat not started, or UDP port 22101 blocked | Check Phase 3 in `ddraw_proxy.log` |
| Client connects then immediately disconnects | Checksum exchange starts but doesn't complete | Checksum mismatch (modified scripts in non-exempt directory) | Check `packet_trace.log` for opcode 0x20/0x21 flow |
| First connection always times out | Client must reconnect once | Unknown — stock-dedi does NOT have this issue | **Not fixed** |
| Client reaches ship select, disconnects ~3 sec later | `packet_trace.log` shows flags=0x00 in StateUpdate | Empty StateUpdates: ship subsystem list was NULL | **FIXED** — DeferredInitObject + InitNetwork timing |
| `scoring dict fix rc=-1` in log | `dedicated_init.log` | Python exception in score dictionary registration | Deferred — non-blocking |
| Crash at specific address | `crash_dump.log` with register dump | Unpatched crash site in headless mode | Add a new binary patch for the address |
| `ObjNotFound for 0x3FFFFFFF` in packet trace | Opcode 0x1D in decoded packets | **Normal** — stock server does this too. It's a sentinel query. | Not a bug |
| `Py_FatalError` or abort dialog | `ddraw_proxy.log` shows SIGABRT handler | Python fatal error (usually corrupt state or import failure) | Check what Python was doing in `dedicated_init.log` |

## Detailed Issue Descriptions

### Empty StateUpdates (FIXED)

**What happened**: Server sent StateUpdate packets with `flags=0x00` (empty) instead of `flags=0x20` (subsystem health data). Client interpreted this as connection failure after ~3 seconds.

**Root cause**: NIF ship models didn't load in headless mode, leaving the subsystem linked list at `ship+0x284` NULL. PatchNetworkUpdateNullLists correctly cleared flags to prevent malformed packets, but the result was empty state updates.

**Fix**: DeferredInitObject (Python-driven ship creation) now loads NIF models after the client selects a ship. The full subsystem creation pipeline runs, populating ship+0x284 with 33 subsystems. Combined with the InitNetwork timing fix (see below), the server now sends flags=0x20 with real health data.

See [empty-stateupdate-root-cause.md](empty-stateupdate-root-cause.md) for the full 5-step causal chain and resolution.

### InitNetwork Timing (FIXED)

**What happened**: MISSION_INIT_MESSAGE arrived 13+ seconds after client connect instead of ~2 seconds (stock timing). By then, the client had already stopped responding.

**Root cause**: The `bc` flag at `peer+0xBC` in the TGWinsockNetwork peer structure was used to detect checksum completion. This flag takes 200+ ticks to transition from 0→1, or in some cases never flips at all. The actual checksum exchange completes within 1-2 ticks.

**Fix**: Detect new peers by scanning the WSN peer array directly. When a new peer ID appears, schedule InitNetwork for 30 ticks later. This fires at connect time (~1.4s), matching stock timing (~2s).

### PatchNetworkUpdateNullLists Safety Cave (DO NOT DISABLE)

**Trap**: Creating a `legacy-null-list-safety-disable.cfg` file disables the safety cave at 0x005B1D57. This causes a **fatal crash** at 0x005B1EDB when the state update loop iterates the server's own ship (player 0) which has NULL subsystem lists. The crash is unrecoverable — MOV EAX,[ECX] → CALL [EAX+0x70] chains through a zeroed vtable. The safety cave MUST remain enabled even with DeferredInitObject, because the server's own ship (player 0) still has NULL subsystems.

### First Connection Timeout

**What happens**: The first client to connect always times out and must reconnect. Second attempt works.

**Why**: Not fully diagnosed. Stock dedicated server does NOT have this issue — the stock checksum exchange completes in ~1.1 seconds and the client stays connected on the first attempt. This is our bug, not an inherent game limitation.

**Known data**: Stock packet trace shows client connects at 19:44:56, checksums done by 19:44:58 (1.1s), no timeout. Our server likely has a timing issue in the initial connection establishment, possibly related to the peek-based UDP router or GameSpy initialization timing.

**Workaround**: Connect, wait for timeout, reconnect.

### VEH Zombie Objects (Historical — Fixed)

**What happened**: The original crash handler used Vectored Exception Handlers to redirect NULL dereference crashes to dummy memory buffers. This created "zombie objects" — pointers that passed NULL checks but contained zeroed/garbage data. These zombies were consumed by downstream code, causing cascade crashes at ~100/sec.

**Fix**: VEH was completely removed. Replaced with targeted binary patches that prevent crashes at source, plus a crash dump handler that logs diagnostics and lets the process terminate.

**Lesson**: Don't recover from crashes by faking valid state. Fix the root cause instead.

See [veh-cascade-triage.md](veh-cascade-triage.md) for the full analysis.

### PatchChecksumAlwaysPass (Historical — Fixed)

**What happened**: A patch at `0x006a1b75` forced the checksum result flag from 0 to 1, thinking 0 meant "fail" and 1 meant "pass".

**Reality**: Flag=0 means "no mismatches" (correct for the first player, who has no peers to compare against). Flag=1 means "mismatches detected" and triggers `FUN_006f3f30` which appends mismatch correction data to the Settings packet — corrupting it.

**Lesson**: Always verify what 0 and 1 mean in context. "Pass" and "fail" are assumptions.

### Crash at 0x005054C7 (MultiplayerGame vtable call)

**What happens**: Fatal crash with `ECX=0x00000000`, `EIP=0x005054C7`. The instruction is
`MOV EAX,[ECX]; CALL [EAX+0x11C]` — a vtable call on a NULL object pointer.

**When**: During MultiplayerGame creation or early game setup. The function reads the global
at `0x009878CC` and makes a vtable call. If the global is NULL at that point, it crashes.

**Impact**: The CrashDumpHandler logs the crash to `crash_dump.log` and the process terminates.
The server must be restarted.

**Status**: Observed but not consistently reproducible. May be a race condition during bootstrap.
The server usually starts fine — this crash is intermittent.

## How to Diagnose a New Crash

1. **Check `crash_dump.log`** — look for the exception code and faulting EIP
2. **Map the EIP to a function** — use the function map or Ghidra to identify what was executing
3. **Check registers** — NULL in EAX/ECX usually means a failed object lookup; the register dump shows what the code was trying to access
4. **Check the stack walk** — the EBP chain shows the call path that led to the crash
5. **Check code bytes** — the dump shows 32 bytes before and after the crash, so you can see the instruction context
6. **Decide on a fix**:
   - If the function is called with NULL `this`: add a NULL check code cave
   - If the function should never be called headless: NOP the call site or return early
   - If a conditional branch goes the wrong way: change JNZ to JMP (or vice versa)

## How to Diagnose a Protocol Issue

1. **Capture traces from both sides** — run server and client, reproduce the issue
2. **Find the divergence point** — compare packet traces (use sequence numbers, not timestamps)
3. **Check opcode flow** — is the server sending what the client expects? Compare against stock-dedi.
4. **Decode the packet** — `packet_trace.log` includes full decrypted hex dumps and opcode labels
5. **Check the handler** — trace the opcode through the game's message dispatch (see [wire-format-spec.md](wire-format-spec.md))

## Environment Issues

### WSL2 Path Translation
The Makefile uses `wslpath -w` to convert Linux paths to Windows paths when launching executables. If you get path errors, ensure your game directories are under `/mnt/c/` (or wherever your Windows drives are mounted).

### Port Conflicts
The game uses UDP port 22101. Check with `netstat -an | grep 22101` (on Windows) if you suspect a port conflict. Only one server instance can bind this port.

### Windows Defender
A file named `ddraw.dll` in a game directory may trigger antivirus heuristics (it looks like DLL sideloading, which it technically is). Add an exclusion for your game directories if builds get quarantined.
