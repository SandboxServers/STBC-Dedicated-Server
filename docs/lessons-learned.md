# Lessons Learned

## Debugging Techniques That Work
- **MSG_PEEK routing**: Perfect for shared socket demuxing. Check first byte without consuming.
- **Ghidra MCP integration**: Decompile functions on demand during development. Invaluable.
- **ProxyLog diagnostics**: Adding detailed logging at each phase of bootstrap catches issues early.
- **Packet tracing**: Full hex dumps to packet_trace.log with opcode decoding. Cross-reference
  with message_trace.log (receive path) for complete picture.
- **Stock-dedi comparison**: Running the stock dedicated server with an OBSERVE_ONLY proxy DLL
  captures the correct packet flow. Compare stock traces against our traces to identify divergence.
- **CrashDumpHandler**: SetUnhandledExceptionFilter with full register/stack dumps to crash_dump.log.
  Process terminates cleanly on any unhandled exception. Each crash site is then fixed with a
  targeted binary patch (code cave or instruction patch).

## Critical Timing Discovery: bc Flag is Unreliable
The `bc` flag at `peer+0xBC` in the TGWinsockNetwork peer structure was used to detect when
a peer's checksum exchange completed. **This flag is unreliable**:
- Takes 200+ ticks (~7 seconds) to transition from 0 to 1
- In some test runs, **never flips at all** (remained 0 after 1000+ ticks)
- Is set deep in the checksum pipeline, NOT at actual completion time
- The actual checksum exchange completes within 1-2 ticks of connection

**Correct approach**: Detect new peers by scanning the WSN peer array directly (`WSN+0x2C` =
array pointer, `WSN+0x30` = count, each peer at `pp+0x18` = peer ID). This fires at connect
time and matches stock server timing.

## DeferredInitObject: How Headless NIF Loading Works
NIF model loading is **not renderer-dependent** — it's file I/O via NiStream::Load. The problem
was that the game only creates ship objects in response to network deserialization (ObjCreateTeam),
and the initial object has no NIF model loaded. The solution:

1. C-side GameLoopTimerProc detects new ship objects (polls after InitNetwork fires)
2. Python `DeferredInitObject(playerID)` determines ship class from species index
3. Calls `ship.LoadModel(nifPath)` on the ship object
4. Engine's AddToSet/SetupProperties pipeline creates 33 subsystem objects
5. ship+0x284 linked list is now populated, StateUpdate sends real health data

This is called "deferred" because it happens after the ship already exists on the network.

## PatchNetworkUpdateNullLists MUST Stay Enabled
Even with DeferredInitObject creating subsystems for client ships, the server's own player-0
ship still has NULL subsystems (it's a dummy ship that never gets a NIF model). The safety cave
at 0x005B1D57 clears SUB/WPN flags for objects with NULL ship+0x284. **Disabling this causes a
fatal crash** at 0x005B1EDB. Tested and confirmed.

## MISSION_INIT_MESSAGE Timing is Critical
Stock server sends MISSION_INIT_MESSAGE ~2 seconds after client connects. If it arrives too
late (our broken path: ~13 seconds), the client has already stopped responding to packets.
The timing fix (peer-array detection instead of bc-flag) brought this down to ~1.4 seconds,
which is within the stock's expected window.

## Common Pitfalls
- **WSN+0x30 is NOT player count**: It's a monotonically increasing counter (packet/connection counter). Don't use it to track active players.
- **connState naming is inverted**: State 2 = HOST (not client), State 3 = CLIENT (not host).
- **SWIG type checking is strict**: Can't recast `_p_TGNetwork` to `_p_TGWinsockNetwork` by string manipulation. SWIG validates the type suffix.
- **procPkts (+0x10D) is NOT "process packets"**: It's a force-disconnect flag. Only matters for client path. Host ignores it.
- **GameSpy recvfrom steals game packets**: Without the peek router, GameSpy's recvfrom loop in qr_process_incoming consumes ALL packets from the shared socket. Set qr_t+0xE4=0 and handle queries ourselves.
- **Don't rely on wsprintfA for long strings**: Truncates at 1024 bytes silently.
- **VEH crash recovery creates zombie objects**: Vectored Exception Handlers that redirect
  registers to dummy buffers create objects that pass NULL checks but contain garbage data.
  These zombies cause worse cascade crashes (100/sec) than the original failures. The correct
  approach is preventing the crash at source with targeted binary patches, not recovering from it.
  See [docs/veh-cascade-triage.md](veh-cascade-triage.md) for full analysis.
- **PatchChecksumAlwaysPass was WRONG**: Forcing checksum flag from 0 to 1 at 0x006a1b75
  corrupted the Settings packet. Flag=0 means "no mismatches" which is correct for the first
  player connecting to an empty server (no peers to compare against). Flag=1 triggers
  FUN_006f3f30 which appends bogus mismatch correction data.

## Architecture Insights
- The game's event system is the backbone: TGNetwork generates events -> EventManager dispatches -> handlers process. Without proper event generation, nothing works.
- Setting flags and pointers manually is not sufficient. The internal state machines have initialization sequences that set up callbacks, queues, and plumbing that raw memory writes don't replicate.
- The normal game flow uses Python scripts to drive the UI, which triggers C++ functions in the right sequence. Our C-level bootstrap skips some of these steps.

## Network Protocol Discoveries
- **StateUpdate flags are direction-dependent**: C->S always uses 0x80 (WPN), S->C always uses
  0x20 (SUB). These are mutually exclusive by direction. The decompiled code at FUN_005b17f0
  checks `DAT_0097fa8a` (IsMultiplayer) which may have different values on client vs host side.
  See [docs/message-trace-vs-packet-trace.md](message-trace-vs-packet-trace.md).
- **Empty StateUpdates caused disconnect (FIXED)**: Server was sending flags=0x00 because
  ship+0x284 was NULL. Fixed by DeferredInitObject (loads NIF model → creates subsystems).
  Combined with InitNetwork timing fix, client now stays connected with working damage.
  See [docs/empty-stateupdate-root-cause.md](empty-stateupdate-root-cause.md).
- **message_trace.log captures RECEIVE path only**: It hooks the TGMessage factory at
  deserialization. Every C->S opcode in packet_trace matches message_trace exactly.
  All S->C messages are absent from message_trace.
- **Fragmented reliable messages**: Large packets (>MTU) use flag bits 0x80 (reliable) +
  0x20 (fragmented) in the 0x32 transport wrapper. Fragment index byte is misread by the
  packet trace decoder as a game opcode, producing garbage entries.
- **ObjNotFound (0x1D) for 0x3FFFFFFF is normal**: Stock server does this too. It's a
  query for the "all objects" sentinel, not an error.
- **Double FUN_006a1e70 call**: The engine internally handles opcode 0x2A (NewPlayerInGame).
  Our GameLoopTimerProc also calls it, producing a duplicate. The engine handles it gracefully
  but it's unnecessary work.
