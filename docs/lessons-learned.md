# Lessons Learned

## Debugging Techniques That Work
- **Software breakpoints via VEH**: INT3 at function entry + single-step for re-arm. Very effective for confirming whether functions are called. CAVEAT: game may have anti-debug that catches unhandled INT3 and calls ExitProcess.
- **MSG_PEEK routing**: Perfect for shared socket demuxing. Check first byte without consuming.
- **Ghidra MCP integration**: Decompile functions on demand during development. Invaluable.
- **ProxyLog diagnostics**: Adding detailed logging at each phase of bootstrap catches issues early.

## Common Pitfalls
- **WSN+0x30 is NOT player count**: It's a monotonically increasing counter (packet/connection counter). Don't use it to track active players.
- **connState naming is inverted**: State 2 = HOST (not client), State 3 = CLIENT (not host).
- **SWIG type checking is strict**: Can't recast `_p_TGNetwork` to `_p_TGWinsockNetwork` by string manipulation. SWIG validates the type suffix.
- **VEH exceptions in Phase 2 are normal**: MultiplayerGame creation triggers NULL derefs that our VEH handler fixes. Non-deterministic but usually works.
- **procPkts (+0x10D) is NOT "process packets"**: It's a force-disconnect flag. Only matters for client path. Host ignores it.
- **GameSpy recvfrom steals game packets**: Without the peek router, GameSpy's recvfrom loop in qr_process_incoming consumes ALL packets from the shared socket. Set qr_t+0xE4=0 and handle queries ourselves.
- **Don't rely on wsprintfA for long strings**: Truncates at 1024 bytes silently.

## Architecture Insights
- The game's event system is the backbone: TGNetwork generates events -> EventManager dispatches -> handlers process. Without proper event generation, nothing works.
- Setting flags and pointers manually is not sufficient. The internal state machines have initialization sequences that set up callbacks, queues, and plumbing that raw memory writes don't replicate.
- The normal game flow uses Python scripts to drive the UI, which triggers C++ functions in the right sequence. Our C-level bootstrap skips some of these steps.

## What Needs Investigation
- **TGNetwork_HostOrJoin (0x006b3ec0)**: This is probably the key missing piece. It's what the normal game calls to start hosting, and likely sets up the internal send/recv/event pipeline.
- **Normal hosting flow**: Trace what happens from the Multiplayer menu through "Host Game" to "Waiting for Players" to understand the complete initialization sequence.
