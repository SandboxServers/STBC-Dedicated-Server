# Post-Join Opcodes: 0x35, 0x37, 0x17

## Sequence After NewPlayerInGame (0x2A)

### First Player Join (stock trace, Peer#0 Sep)
```
C->S  0x2A NewPlayerInGame
S->C  0x35 [08 09 FF FF]         -- game state
S->C  0x17 [17 bytes]            -- DeletePlayerUI (last byte=0x02)
```

### Second Player Join (stock trace, Peer#3 Cady)
```
C->S  0x2A NewPlayerInGame
S->C  0x35 [08 09 FF FF]         -- game state
S->C  0x37 [02 00...x14_zeros]   -- player roster (sent to 2nd+ player only)
S->C  0x17 [17 bytes]            -- DeletePlayerUI (last byte=0x03)
S->C(Peer#0) 0x17                -- also sent to first player about new joiner
```

## Opcode 0x35 Format (4 bytes)
```
Offset  Size  Field
0       1     maxPlayers (always 0x08 for 8-player game)
1       1     totalSlots (stock=0x09, proxy=0x01 BUG)
2       1     0xFF sentinel
3       1     0xFF sentinel
```

### totalSlots values:
- Stock: 0x09 = 8 player slots + 1 host = 9 total
- Proxy: 0x01 = probably just counting 1 connected peer (WRONG)
- This likely comes from the player array size in MultiplayerGame

## Opcode 0x37 Format (16 bytes)
```
Offset  Size  Field
0       1     numConnectedPlayers (0x02 when 2nd player joins)
1-15    15    Zero padding (reserved for future player data?)
```

### Behavior:
- NOT sent for first player join
- Sent starting with 2nd player
- Sent to the NEW player only (not broadcast to existing)
- May initialize the client's player list/scoreboard

## Opcode 0x17 (DeletePlayerUI) Format (17 bytes payload after opcode)
```
Offset  Size  Field
0       1     0x66 (sub-opcode? always same)
1       1     0x08 (UI type?)
2       2     0x00 0x00
4       1     0xF1 (stock) / 0xE1 (proxy) -- UI element ID?
5       1     0x00
6       1     0x80
7-10    4     0x00 0x00 0x00 0x00
11      1     0xF2 (stock) / 0xE1 (proxy) -- game time related?
12      1     0x05 (stock) / 0x00 (proxy) -- high byte of above
13-14   2     0x00 0x00
15      1     Player slot index (0x02=slot0, 0x03=slot1)
```

### Key difference: bytes 4-5 and 11-12
- Stock: F1 00 ... F2 05 = these look like gameTime-derived values
- Proxy: E1 00 ... E1 00 = smaller values, possibly because proxy has different clock state

### Last byte encoding:
- 0x02 = first player (slot 0)
- 0x03 = second player (slot 1)
- Pattern: slot_index + 2

## Proxy Bugs Identified (2026-02-10 Session)
1. **DOUBLE FUN_006a1e70** = Root cause. Engine handles client 0x2A, then our manual
   call fires 90 ticks later. FIX: Remove manual call from GameLoopTimerProc.
2. 0x35 byte[1] = 0x01 instead of 0x09 (engine generates this; investigate MPG slot count)
3. DeletePlayerUI time-related bytes are wrong (45 00 vs F2 05) -- different game clock state
4. Double 0x35 send (first burst has 0x35+0x17, second burst 4s later has 0x35+0x37+0x17+0x17)
5. The second burst should NOT happen -- stock server sends everything in one burst
6. TWO ObjNotFound for same obj (caused by double FUN_006a1e70)
7. Empty StateUpdates flags=0x00 (headless engine has no subsystem data)

## Stock Behavior (VERIFIED 2026-02-10)
### First Player (Sep, Peer#0)
- Slot=0 in Settings, 0x35=[08 09 FF FF], ONE 0x17 with last_byte=0x02
- NO 0x37 (only sent for 2nd+ player)
- Post-spawn: relay ObjCreate to other peer, 1x ObjNotFound, StateUpdate flags=0x20 [SUB]

### Second Player (Cady, Peer#3)
- Slot=1 in Settings, 0x35=[08 09 FF FF], 0x37=[02 00...], ONE 0x17 with last_byte=0x03
- Also sends 0x17 to Peer#0 about the new player (last_byte=0x03)
