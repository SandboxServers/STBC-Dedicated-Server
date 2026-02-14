# Network Protocol Analyst - Memory

## Key Findings

### State-Only Baseline (2026-02-12)
- Session had no custom-dedi client connection; packet correlation intentionally skipped.
- Useful pre-protocol baseline from state dumps:
  - Stock-dedi transitions `CurrentGame: None -> <C Game instance> -> None`
  - Custom-dedi starts with non-NULL `CurrentGame` but as raw pointer string
    (`_<addr>_p_Game`) rather than SWIG object wrapper.

### ENCRYPTION FULLY IMPLEMENTED AND VERIFIED (2026-02-09)
- See [encryption-analysis.md](encryption-analysis.md) for algorithm details
- See [cipher-implementation.md](cipher-implementation.md) for C reimplementation spec
- Cipher: Custom stream cipher with fixed key "AlbyRules!" (10 bytes at 0x0095abb4)
- **BYTE 0 OF UDP PAYLOAD IS NOT ENCRYPTED** - direction flag (0x01=server, 0x02=client, 0xFF=first contact)
- Encryption applies to bytes 1..N only

### TGNetwork Message Framing (VERIFIED from stock-dedi trace)
- See [tgnetwork-message-types.md](tgnetwork-message-types.md) for full opcode table
- byte[0] = direction (NOT encrypted): 0x01=server, 0x02=client, 0xFF=initial
- byte[1] = message count (number of TGNetwork messages that follow)
- byte[2+] = concatenated TGNetwork messages
- Messages are variable-length, self-describing by type
- Type 0x01 = ACK/Status (4 bytes: [01][seq][00][flags])
- Type 0x00 = Keepalive/Settings (variable)
- Type 0x32 = Reliable message wrapper

### 0x32 Reliable Message Format
- [0x32][total_msg_len][flags][seq_hi][seq_lo][payload...]
- total_msg_len includes the 0x32 type byte
- flags & 0x80 = reliable delivery required
- Sequence number = (seq_hi << 8) | seq_lo
- Inner payload contains the ACTUAL game opcode

### Opcodes 0x35 and 0x37 (IDENTIFIED 2026-02-10)
- See [post-join-opcodes.md](post-join-opcodes.md) for detailed analysis
- **0x35** (4B): Game state notification after NewPlayerInGame
  - Format: [maxPlayers:1][totalSlots:1][0xFF][0xFF]
  - Stock sends totalSlots=0x09 (8+1), proxy sends 0x01 (bug)
- **0x37** (16B): Player roster update, sent when 2nd+ player joins
  - Format: [numPlayers:1][15 zero bytes]
  - Only sent for 2nd player onward (not for first join in stock trace)

### Post-ObjCreate StateUpdate Behavior (CRITICAL FINDING 2026-02-10)
- Stock server sends flags=0x20 (SUB) with subsystem health data after ObjCreateTeam
- Cycles through subsystem groups: startIdx 0, 2, 6, 8, 10 with real health values
- Our proxy sends flags=0x00 (EMPTY) - headless engine has no subsystem data
- This is a root cause of client dysfunction: client expects subsystem state from server
- ObjNotFound (0x1D) is NORMAL - stock server sends one per peer for new objects
- Our proxy sends TWO ObjNotFound for same obj (one per incoming StateUpdate)

### DOUBLE NewPlayerInGame = ROOT CAUSE OF CURRENT BUGS (2026-02-10)
- Client DOES send 0x2A (NewPlayerInGame) correctly after receiving Settings+GameInit
- Engine dispatcher at 0x0069f2a0 routes 0x2A to LAB_006a1590 -> FUN_006a1e70
- Our GameLoopTimerProc ALSO calls FUN_006a1e70 after NEWPLAYER_DELAY_TICKS=90
- Result: FUN_006a1e70 fires TWICE = duplicate 0x35, 0x37, 0x17, ObjNotFound
- **FIX: Remove manual FUN_006a1e70 call from GameLoopTimerProc**
- Keep scoring dict fix as deferred action, verify InitNetwork runs via engine path
- See [session-comparison-20260210.md](session-comparison-20260210.md) for full stock-vs-proxy comparison

### Crash at 0x006CF1DC (2026-02-10, RESOLVED)
- FUN_006cf1c0: message buffer cleanup, double-clear of stack buffer
- If +0x1C already NULL, reads vtable from +0x04, writes 0xFFFFFFFE to .rdata
- Caller: FUN_006a1b10 (Settings send) clears buffer then destructor clears again
- Trigger: Second NewPlayerInGame call during active state update exchange
- Fix: Removing the double FUN_006a1e70 call eliminates the trigger

### Server Clock vs Client Clock
- Server clock always AHEAD of client by 0.8-2.0 seconds (NORMAL)
- Stock: client=47.70, server=49.58 (delta=1.88s)
- Proxy: client=42.08, server=42.88 (delta=0.80s)
- Clocks are independent; server started running before client connected

### ObjCreateTeam (0x03) Format (VERIFIED from stock-dedi trace)
- See [objcreate-team-format.md](objcreate-team-format.md) for full structure
- See [subsystem-ids.md](subsystem-ids.md) for weapon/subsystem object ID mapping
- Header: opcode(1) + owner(1) + team(1) + classType(4=0x00008008) + objID(4) = 11 bytes
- Body: spawnIdx(1) + pos(12) + quat(16) + speed(4) + pad(3) + nameLen(1) + name + setLen(1) + set + subsysHealth(var)

### Object ID Owner Encoding
- Bits 31-14 = owner prefix: 0x4000=Peer#0, 0x4004=Peer#3
- 0x3FFF = Peer#0 initial (first spawn), 0x0000 = global objects
- Weapon subsystem offsets from ship: +5,+6 (beams), +8 (torpedo), +14..+19 (torpedo array)

### Serialization Functions
- FUN_006cf670: ReadDword (4-byte LE), FUN_006cf6b0: ReadFloat (4-byte LE)
- FUN_006cf1c0: Buffer cleanup (clears +0x1C..+0x2C if data exists, else writes 0xFFFFFFFE to vtable)
- FUN_006cf120: Buffer destructor (sets vtable, calls cleanup, calls FUN_006d2050)
- FUN_006a1b10: Settings message builder (has double-clear bug path)
- FUN_005a1f50: Object factory (reads classType+objID, creates via FUN_006f13e0)
- FUN_005a2060: Deserializer (quat, pos, names, set lookup, subsys health)

### Stock Dedicated Server Slot Assignment (VERIFIED)
- Slot 0 = first player (Sep), Slot 1 = second player (Cady)
- Dedicated host does NOT take a slot (ghost host)
- So our proxy assigning slot=0 to first client is CORRECT
- Object ID 0x3FFFFFFF = player 0's initial spawn (correct for slot=0)

### Stock Post-Join Sequence (Single Burst, No Delay)
- C->S: 0x2A NewPlayerInGame
- S->C: 0x35 [08 09 FF FF] (immediate, ~2ms later)
- S->C: 0x17 DeletePlayerUI [... last_byte=slot+2]
- For 2nd+ player: also S->C(new): 0x37 [02 00...], S->C(all): 0x17
- Then idle until client sends ObjCreateTeam

### Stock Post-Spawn Sequence
- C->S: ObjCreateTeam + StateUpdate flags=0x9D
- S->C(other peer): ObjCreateTeam (relay)
- S->C(sender): 1x ObjNotFound
- S->C(sender): StateUpdate flags=0x20 [SUB] with subsystem health
  - Cycles through startIdx: 0, 2, 6, 8, 10 with real health values
  - This is the server's copy reflecting ship state back to owner

### Stock Subsystem Health Data Format (flags=0x20)
- StateUpdate: [0x1C][objID:4][gameTime:4][flags=0x20][startIdx:1][subsysData:N]
- startIdx cycles: 0, 2, 6, 8, 10 (each ~100ms apart, full cycle ~500ms)
- Health bytes: 0xFF = full, values decrease as damaged
- The "20" in subsys data at certain positions = partial health (e.g., 0x20 = 32/255)
- Server continuously cycles SUB updates even when ship is stationary
- These start IMMEDIATELY after ObjCreateTeam is received from client

### Disconnect Mechanism (INFERRED)
- Client expects SUB data from server after spawning
- If server only sends flags=0x00, client never sees its ship "acknowledged" by server
- Client likely has a timeout: "if no meaningful state from server within N seconds, disconnect"
- The stock server starts SUB cycling within 88ms of ObjCreateTeam receipt
- Our proxy NEVER sends SUB data, so the client hits its timeout

## Files Reference
- `game/stock-dedi/packet_trace.log` - Stock dedicated server trace (decrypted, ~1800 lines)
- `game/server/packet_trace.log` - Our proxy server trace (1051 lines, crashed session)
- `game/client/packet_trace.log` - Client-side trace (7592 lines)
- [post-join-opcodes.md](post-join-opcodes.md) - Analysis of 0x35, 0x37, 0x17 post-join
- [session-comparison-20260210.md](session-comparison-20260210.md) - Full stock-vs-proxy comparison

## Dump-Driven Network Init Signal (2026-02-12)
- In this state-dump pass, stock path evidence includes full Multiplayer menu -> mission start chain before scoreboard idle.
- Custom server path evidence contains only `PatchLoadedMissionModules` path, not full menu/network init chain.
- Interpretation: custom dedicated runtime likely enters post-start state through patch/bootstrap path rather than stock host-start message flow; this can affect lobby/session metadata and downstream packet behavior even when `CurrentGame` exists.

## Startup State vs Protocol Readiness (2026-02-12)
- Stock reaches protocol-relevant mission state in two steps after host screen:
  1) lobby prep (`CurrentGame` exists, no starting set yet),
  2) mission start (`CreateSystemFromSpecies`, `InitializeAllSets`, starting set non-null).
- Treat lobby-level `CurrentGame` as insufficient evidence of full game-state readiness.
