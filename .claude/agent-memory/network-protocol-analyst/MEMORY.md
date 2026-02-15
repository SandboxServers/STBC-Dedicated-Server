# Network Protocol Analyst - Memory

## Comprehensive Gap Analysis (2026-02-15)
- See [gap-analysis-20260215.md](gap-analysis-20260215.md) for full report
- 5 gaps: 1 High (DamageEventHandler missing), 2 Medium (time limit timer, 0x35 byte), 2 Low

### Settings Packet (0x00) Bytes RESOLVED
- **DAT_008e5f59** = collision damage toggle (WriteBit)
- **DAT_0097faa2** = friendly fire toggle (WriteBit)

### Event Handler Gaps
- DamageEventHandler (ET_WEAPON_HIT) NOT registered = damage scoring always zero
- DeletePlayerHandler/ProcessNameChangeHandler not registered = cosmetic only

### Stock Disconnect Flow
- Engine handles C++ side (0x17, 0x18 opcodes sent automatically)
- Python DeletePlayerHandler only rebuilds UI list; scores preserved for reconnect

## Key Protocol Facts (Verified)

### ENCRYPTION FULLY IMPLEMENTED AND VERIFIED (2026-02-09)
- Cipher: Custom stream cipher with fixed key "AlbyRules!" (10 bytes at 0x0095abb4)
- BYTE 0 NOT ENCRYPTED (direction flag: 0x01=server, 0x02=client, 0xFF=init)
- See [encryption-analysis.md](encryption-analysis.md)

### TGNetwork Message Framing (VERIFIED)
- See [tgnetwork-message-types.md](tgnetwork-message-types.md)
- byte[0]=direction, byte[1]=msg_count, byte[2+]=messages
- Type 0x01=ACK(4B), Type 0x32=Reliable wrapper

### Opcodes 0x35 and 0x37 (IDENTIFIED)
- **0x35**: Game state after NewPlayerInGame: [maxPlayers][totalSlots][FF][FF]
  - Stock sends totalSlots=0x09, we send 0x01 (still a bug)
- **0x37**: Player roster update for 2nd+ player joins

### StateUpdate Flag Split (VERIFIED from 30K+ packets)
- C->S: always 0x80 (WPN), never 0x20 (SUB)
- S->C: always 0x20 (SUB), never 0x80 (WPN)
- Mutually exclusive by direction in MP

### Stock Post-Join: 0x2A -> 0x35 -> 0x17 -> idle -> ObjCreateTeam
### Stock Post-Spawn: ObjCreateTeam -> ObjNotFound -> SUB cycling (100ms intervals)

## Files Reference
- `docs/wire-format-spec.md` - Complete opcode table + wire formats
- `docs/message-trace-vs-packet-trace.md` - Stock packet cross-reference
- `src/scripts/Custom/DSNetHandlers.py` - EndGame, RestartGame, scoring
- `src/scripts/Custom/DSHandlers.py` - ChatRelay, DeferredInitObject
- [post-join-opcodes.md](post-join-opcodes.md) - 0x35/0x37 analysis
- [session-comparison-20260210.md](session-comparison-20260210.md) - Full comparison
