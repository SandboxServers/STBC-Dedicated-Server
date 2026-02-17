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

### CollisionEffect (0x15) FULLY DECODED (2026-02-17)
- Wraps TGEvent with factory ID 0x00008124, event code 0x00800050
- Format: [opcode:1][typeClassId:i32][eventCode:i32][srcObjId:i32v][tgtObjId:i32v][count:u8][count * CompressedVec4Byte:4B][force:f32]
- CompressedVec4Byte = [dirX:s8][dirY:s8][dirZ:s8][magnitude:u8] (ship-relative, bounding-sphere-normalized)
- Write at 0x005871a0: parent TGEvent Write + WriteByte(count) + per-contact vtable+0x98 + WriteFloat(force)
- Read at 0x00587300: parent TGEvent Read + ReadByte(count) + per-contact vtable+0x9C + ReadFloat(force)
- Compression: vtable+0xA0 (0x006d29a0) normalizes Vec3 to 3 dir bytes; vtable+0xAC (0x006d2d10) adds magnitude byte
- Handler validates sender owns a collision object, checks bounding proximity, re-posts as 0x008000fc
- See [collision-effect-analysis.md](collision-effect-analysis.md) for full decode

### TGEvent Serialization Pattern (VERIFIED)
- Base TGEvent Write (FUN_006d6130, vtable+0x34): [typeClassId:i32][eventCode:i32][srcObjId:i32v][tgtObjId:i32v]
- Base TGEvent Read (FUN_006d61c0, vtable+0x38): reads 3 fields (code, src, tgt); typeClassId read separately by FUN_006d6200
- Event factory: FUN_006d6200 reads typeClassId, creates event via FUN_006f13e0, calls event->Read(stream)
- Event sender: FUN_006a17c0 writes [opcode_byte][event->Write(stream)], sends reliable to all peers
- Subclasses override Write/Read at vtable+0x34/+0x38 to add class-specific fields after calling parent

### Stream Vtable Map (TGBufferStream at PTR_LAB_00895c58)
- +0x50: ReadByte   | +0x54: WriteByte
- +0x58: ReadShort  | +0x5C: WriteShort
- +0x60: ReadInt32  | +0x64: WriteInt32 (variant)
- +0x68: ReadInt32  | +0x6C: WriteInt32 (FUN_006cf870)
- +0x70: ReadFloat  | +0x74: WriteFloat
- +0x80: ReadInt32v | +0x84: WriteInt32v (thunk to +0x6C)
- +0x98: WriteCompressedVec4Byte (4B: 3 dir + 1 mag)
- +0x9C: ReadCompressedVec4Byte
- +0xA0: CompressVec3ToDirBytes (normalize + 3 signed bytes + magnitude)
- +0xA8: CompressVec3 (3 dir bytes + CF16 magnitude = 5B standard)
- +0xAC: CompressVec4Byte (calls +0xA0, adds magnitude byte)
- +0xBC: DecompressVec4Byte (4 bytes -> Vec3 + magnitude)

## Files Reference
- `docs/wire-format-spec.md` - Complete opcode table + wire formats
- `docs/message-trace-vs-packet-trace.md` - Stock packet cross-reference
- `src/scripts/Custom/DSNetHandlers.py` - EndGame, RestartGame, scoring
- `src/scripts/Custom/DSHandlers.py` - ChatRelay, DeferredInitObject
- [post-join-opcodes.md](post-join-opcodes.md) - 0x35/0x37 analysis
- [session-comparison-20260210.md](session-comparison-20260210.md) - Full comparison
