# Troubleshooting Guide

Known issues, their symptoms, and how to diagnose them.

## Quick Reference: Symptom to Cause

| Symptom | Log Signature | Root Cause | Status |
|---------|--------------|------------|--------|
| Server doesn't boot | `ddraw_proxy.log` stops mid-phase | Python error or crash during bootstrap | Check `dedicated_init.log` and `crash_dump.log` |
| Client can't find server on LAN | No GameSpy queries in `packet_trace.log` | GameSpy heartbeat not started, or UDP port 22101 blocked | Check Phase 3 in `ddraw_proxy.log` |
| Client connects then immediately disconnects | Checksum exchange starts but doesn't complete | Checksum mismatch (modified scripts in non-exempt directory) | Check `packet_trace.log` for opcode 0x20/0x21 flow |
| First connection always times out | Client must reconnect once | Unknown — pre-existing issue | **Not fixed** |
| Client reaches ship select, disconnects ~3 sec later | `packet_trace.log` shows flags=0x00 in StateUpdate | Empty StateUpdates: ship subsystem list is NULL because NIF models don't load headlessly | **Current investigation** — see [black-screen-investigation.md](black-screen-investigation.md) |
| `scoring dict fix rc=-1` in log | `dedicated_init.log` | Python exception in score dictionary registration | Deferred — non-blocking |
| Crash at specific address | `crash_dump.log` with register dump | Unpatched crash site in headless mode | Add a new binary patch for the address |
| `ObjNotFound for 0x3FFFFFFF` in packet trace | Opcode 0x1D in decoded packets | **Normal** — stock server does this too. It's a sentinel query. | Not a bug |
| `Py_FatalError` or abort dialog | `ddraw_proxy.log` shows SIGABRT handler | Python fatal error (usually corrupt state or import failure) | Check what Python was doing in `dedicated_init.log` |

## Detailed Issue Descriptions

### Empty StateUpdates (Current Issue)

**What happens**: Server sends StateUpdate packets with `flags=0x00` (empty) instead of `flags=0x20` (subsystem health data). Client interprets this as connection failure after ~3 seconds.

**Why**: NIF ship models require the D3D7 renderer pipeline to load textures and geometry. Our stub renderer satisfies the COM interface but doesn't actually load model data. Without loaded models, the subsystem property list at `ship+0x284` is NULL. Our `PatchNetworkUpdateNullLists` correctly prevents sending garbage by clearing the flags, but the result is that no subsystem data reaches the client.

**Evidence**: Stock server sends `flags=0x20` with `startIdx` cycling through `0, 2, 6, 8, 10` every ~100ms. Our server sends `flags=0x00` every tick.

**Fix approaches**: See [empty-stateupdate-root-cause.md](empty-stateupdate-root-cause.md).

### First Connection Timeout

**What happens**: The first client to connect always times out and must reconnect. Second attempt works.

**Why**: Not fully diagnosed. Likely related to timing of the NewPlayerHandler callback and initial packet exchange.

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
