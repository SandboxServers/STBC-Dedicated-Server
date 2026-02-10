# Session Comparison: Proxy vs Stock-Dedi (2026-02-10)

## Key Traces Compared
- `game/server/packet_trace.log` (proxy, 1051 lines, crashed session)
- `game/stock-dedi/packet_trace.log` (stock, ~1800 lines, working 2-player session)
- `game/stock-dedi/message_trace.log` (stock app-layer messages)

## Critical Divergences Found

### 1. Double FUN_006a1e70 (ROOT CAUSE)
- Engine handles 0x2A internally -> sends 0x35+0x17 within 32ms (correct)
- Our GameLoopTimerProc calls FUN_006a1e70 again 90 ticks later (WRONG)
- Results: duplicate 0x35, spurious 0x37, duplicate 0x17, ACK storm, double ObjNotFound
- Stock: exactly ONE call triggered by client's 0x2A, no manual call

### 2. Empty StateUpdates (flags=0x00 vs 0x20)
- Stock: flags=0x20 [SUB] with real subsystem health, cycling startIdx 0,2,6,8,10
- Proxy: flags=0x00 [] always (headless = no subsystem lists)
- PatchNetworkUpdateNullLists clears SUB/WPN flags when lists are NULL
- Client expects to receive subsystem data from server; never gets it

### 3. 0x35 totalSlots Wrong (0x01 vs 0x09)
- Stock: [08 09 FF FF] = 8 maxPlayers, 9 total slots (8 + ghost host)
- Proxy: [08 01 FF FF] = 8 maxPlayers, 1 total slot (just the connecting peer)

### 4. Client ACK Storm After Duplicate Burst
- Proxy packets #63,#65,#67: client retransmits 16 ACKs covering ALL old seqs
- Stock: clean ACK pattern, no retransmissions

### 5. DeletePlayerUI Time Bytes
- Stock: bytes 11-12 = F2 05 (0x05F2=1522)
- Proxy: bytes 11-12 = 45 00 (0x0045=69)
- Different game clock state at time of generation

## Stock Post-Spawn Subsystem Cycling Pattern (VERIFIED)
After server receives ObjCreateTeam + first StateUpdate(flags=0x9D):
```
S->C: ObjNotFound(0x3FFFFFFF)  -- exactly 1x
S->C: StateUpdate flags=0x20 startIdx=0  [FF FF 20 FF FF FF FF FF FF]
S->C: StateUpdate flags=0x20 startIdx=2  [FF 60 FF FF FF FF FF FF FF FF FF FF FF FF FF]
S->C: StateUpdate flags=0x20 startIdx=6  [FF 40 FF FF FF FF FF FF FF FF FF]
S->C: StateUpdate flags=0x20 startIdx=8  [FF FF FF FF FF 40 FF FF FF]
S->C: StateUpdate flags=0x20 startIdx=10 [FF FF FF 20 FF FF FF FF FF FF]
S->C: StateUpdate flags=0x20 startIdx=2  (cycle repeats)
```
Cycle period: ~100ms per update, full cycle ~500ms
All subsystems at 0xFF (full health) initially

## Timing Comparison
| Event | Stock (Sep) | Proxy (Cady) |
|-------|------------|--------------|
| Connect -> ChecksumReq | 15.1 sec | 0.06 sec |
| 0x2A -> 0x35 response | 2ms | 32ms (engine) + 3.5s (duplicate) |
| 0x2A -> ObjCreateTeam | 26.5 sec | 11.7 sec |
| ObjCreate -> StateUpdate SUB | 88ms | NEVER (flags=0x00) |

## Fix Priority
1. Remove manual FUN_006a1e70 from GameLoopTimerProc
2. Synthesize SUB state updates (flags=0x20) with default health
3. Fix totalSlots in 0x35 (lower priority)
