> [docs](../README.md) / [protocol](README.md) / wire-format-spec.md

# Star Trek: Bridge Commander - Multiplayer Wire Format Specification

Produced by systematic decompilation of stbc.exe (base 0x400000, ~5.9MB) using Ghidra.
Validated against stock dedicated server packet traces (30,000+ packets).
See also: [message-trace-vs-packet-trace.md](message-trace-vs-packet-trace.md) for packet trace cross-reference.

## Detailed Sub-Documents

| Document | Contents |
|----------|----------|
| [transport-layer.md](transport-layer.md) | Raw UDP packet, 7 transport types, TGMessage layout/vtable, fragment reassembly, reliable delivery |
| [stream-primitives.md](stream-primitives.md) | TGBufferStream read/write functions, bit packing, CF16 encoding/decoding, CompressedVector3/4 |
| [checksum-opcodes.md](checksum-opcodes.md) | Opcodes 0x20-0x28: checksum request/response, file transfer, 5 checksum rounds |
| [game-opcodes.md](game-opcodes.md) | Opcodes 0x00-0x2A: Settings, GameInit, ObjCreate, PythonEvent, EventForward, CollisionEffect, TorpedoFire, BeamFire, Explosion, etc. |
| [stateupdate.md](stateupdate.md) | Opcode 0x1C: dirty flags, 8 field formats, round-robin subsystem/weapon serialization, force-update timing |
| [object-replication.md](object-replication.md) | FUN_0069f620 object create/update, serialization chain |
| [python-messages.md](python-messages.md) | Opcodes 0x2C+: TGMessage script messages, SendTGMessage API, wire examples, receive dispatch |

## Related Protocol Documents

| Document | Contents |
|----------|----------|
| [pythonevent-wire-format.md](pythonevent-wire-format.md) | PythonEvent (0x06) polymorphic event transport, 4 factory types |
| [tgobjptrevent-class.md](tgobjptrevent-class.md) | TGObjPtrEvent (factory 0x010C): class layout, wire format, 5 C++ producers |
| [set-phaser-level-protocol.md](set-phaser-level-protocol.md) | SetPhaserLevel (opcode 0x12): TGCharEvent wire format |
| [collision-effect-protocol.md](collision-effect-protocol.md) | CollisionEffect (opcode 0x15): contact point compression, handler validation |
| [stateupdate-subsystem-wire-format.md](stateupdate-subsystem-wire-format.md) | Subsystem health wire format: linked list order, WriteState formats |
| [subsystem-integrity-hash.md](subsystem-integrity-hash.md) | Subsystem hash (anti-cheat): dead code in MP |
| [cf16-precision-analysis.md](cf16-precision-analysis.md) | CF16 precision tables and mod compatibility |
| [cf16-explosion-encoding.md](cf16-explosion-encoding.md) | CF16 explosion encoding analysis |
| [delete-player-ui-wire-format.md](delete-player-ui-wire-format.md) | DeletePlayerUI (0x17): TGEvent transport for join/disconnect player list updates |
| [tgmessage-routing.md](tgmessage-routing.md) | TGMessage routing: relay-all, no whitelist, star topology |

---

## Summary: Opcode Table

### MultiplayerWindow Dispatcher (FUN_00504c10, handles 0x00/0x01/0x16)

| Opcode | Name | Direction | Handler | Payload Summary |
|--------|------|-----------|---------|-----------------|
| 0x00 | Settings | S->C | FUN_00504d30 | gameTime, settings, playerSlot, mapName, checksumFlag |
| 0x01 | GameInit | S->C | FUN_00504f10 | (empty - just the opcode byte) |
| 0x16 | UICollisionSetting | S->C | FUN_00504c70 | collisionDamageFlag(bit) |

### Game Opcodes (MultiplayerGame Dispatcher at 0x0069F2A0, jump table at 0x0069F534, opcodes 0x02-0x2A)

| Opcode | Name | Direction | Handler | Payload Summary |
|--------|------|-----------|---------|-----------------|
| 0x02 | ObjectCreate | S->C | FUN_0069f620 | type=2, ownerSlot, serializedObject |
| 0x03 | ObjectCreateTeam | S->C | FUN_0069f620 | type=3, ownerSlot, teamId, serializedObject |
| 0x04 | (dead) | -- | DEFAULT | Jump table default; boot handled at transport layer |
| 0x05 | (dead) | -- | DEFAULT | Jump table default |
| 0x06 | PythonEvent | any | FUN_0069f880 | eventCode, eventPayload |
| 0x07 | StartFiring | any | FUN_0069fda0 | objectId, event data (-> event 0x008000D7) |
| 0x08 | StopFiring | any | FUN_0069fda0 | objectId, event data (-> event 0x008000D9) |
| 0x09 | StopFiringAtTarget | any | FUN_0069fda0 | objectId, event data (-> event 0x008000DB) |
| 0x0A | SubsysStatus | any | FUN_0069fda0 | objectId, event data (-> event 0x0080006C) |
| 0x0B | AddToRepairList | any | FUN_0069fda0 | objectId, event data (-> event 0x008000DF) |
| 0x0C | ClientEvent | any | FUN_0069fda0 | objectId, event data (from stream, preserve=0) |
| 0x0D | PythonEvent2 | any | FUN_0069f880 | eventCode, eventPayload (same as 0x06) |
| 0x0E | StartCloaking | any | FUN_0069fda0 | objectId, event data (-> event 0x008000E3) |
| 0x0F | StopCloaking | any | FUN_0069fda0 | objectId, event data (-> event 0x008000E5) |
| 0x10 | StartWarp | any | FUN_0069fda0 | objectId, event data (-> event 0x008000ED) |
| 0x11 | RepairListPriority | any | FUN_0069fda0 | objectId, event data (-> event 0x00800076) |
| 0x12 | SetPhaserLevel | any | FUN_0069fda0 | objectId, event data (-> event 0x008000E0) |
| 0x13 | HostMsg | C->S | FUN_006A01B0 | host-specific dispatch (self-destruct etc.) |
| 0x14 | DestroyObject | S->C | FUN_006a01e0 | objectId. **Not observed in stock MP ship deaths** -- ships die via 0x29+0x03 |
| 0x15 | CollisionEffect | C->S | FUN_006a2470 | typeClassId(0x8124), eventCode(0x800050), srcObjId, tgtObjId, count, count*cv4_byte(dir+mag), force(f32). **C->S only, server never relays** |
| 0x16 | (default) | -- | DEFAULT | Handled by MultiplayerWindow dispatcher, not game jump table |
| 0x17 | DeletePlayerUI | S->C | FUN_006a1360 | Serialized TGEvent (factory 0x866): join=ET_NEW_PLAYER_IN_GAME (0x8000F1), disconnect=ET_NETWORK_DELETE_PLAYER (0x60005). 18 bytes: classID(4), eventCode(4), srcObj(4), tgtObj(4), peerID(1). See [delete-player-ui-wire-format.md](delete-player-ui-wire-format.md) |
| 0x18 | DeletePlayerAnim | S->C | FUN_006a1420 | player deletion animation |
| 0x19 | TorpedoFire | owner->all | FUN_0069f930 | objId, flags, velocity(cv3), [targetId, impact(cv4)] |
| 0x1A | BeamFire | owner->all | FUN_0069fbb0 | objId, flags, targetDir(cv3), moreFlags, [targetId] |
| 0x1B | TorpTypeChange | any | FUN_0069fda0 | objectId, event data (-> event 0x008000FD) |
| 0x1C | StateUpdate | owner->all | FUN_0069FF50 | objectId, gameTime, dirtyFlags, [fields...] |
| 0x1D | ObjNotFound | S->C | FUN_006a0490 | objectId (0x3FFFFFFF queries are normal) |
| 0x1E | RequestObject | C->S | FUN_006a02a0 | objectId (server responds with 0x02/0x03) |
| 0x1F | EnterSet | S->C | FUN_006a05e0 | objectId, setData |
| 0x20-0x28 | (default) | -- | DEFAULT | Handled by NetFile dispatcher, not game jump table |
| 0x29 | Explosion | S->C | FUN_006a0080 | objectId, impact(cv4), damage(cf16), radius(cf16) |
| 0x2A | NewPlayerInGame | C->S | FUN_006a1e70 | Client sends to server after ship selection. **Direction verified C->S from stock traces** |

### Python-Level Messages (via SendTGMessage, bypass C++ dispatcher)

| Byte | Name | Direction | Handler | Payload Summary |
|------|------|-----------|---------|-----------------|
| 0x2C | CHAT_MESSAGE | relayed | Python ReceiveMessage | senderSlot, padding, msgLen, ASCII text |
| 0x2D | TEAM_CHAT_MESSAGE | relayed | Python ReceiveMessage | same format as 0x2C |
| 0x35 | MISSION_INIT_MESSAGE | S->C | Python ReceiveMessage | game config, sent after ObjCreateTeam |
| 0x36 | SCORE_CHANGE_MESSAGE | S->C | Python ReceiveMessage | score deltas |
| 0x37 | SCORE_MESSAGE | S->C | Python ReceiveMessage | full score sync, sent once during join |
| 0x38 | END_GAME_MESSAGE | S->C | Python ReceiveMessage | game over signal |
| 0x39 | RESTART_GAME_MESSAGE | S->C | Python ReceiveMessage | game restart signal |

### Checksum/NetFile Opcodes

| Opcode | Name | Direction | Handler | Payload Summary |
|--------|------|-----------|---------|-----------------|
| 0x20 | ChecksumRequest | S->C | FUN_006a5df0 | index, directory, filter, recursive |
| 0x21 | ChecksumResponse | C->S | FUN_006a4260 | index, hashes |
| 0x22 | VersionMismatch | S->C | FUN_006a4c10 | filename |
| 0x23 | SystemChecksumFail | S->C | FUN_006a4c10 | filename |
| 0x25 | FileTransfer | S->C | FUN_006a3ea0 | filename, filedata |
| 0x27 | FileTransferACK | C->S | FUN_006a4250 | (empty) |

### Event Handler Registration (from FUN_0069efe0)

| Address | Name |
|---------|------|
| 0x0069f2a0 | ReceiveMessageHandler (main dispatch) |
| 0x006a0a20 | DisconnectHandler |
| 0x006a0a30 | NewPlayerHandler |
| 0x006a0c60 | SystemChecksumPassHandler |
| 0x006a0c90 | SystemChecksumFailHandler |
| 0x006a0ca0 | DeletePlayerHandler |
| 0x006a0f90 | ObjectCreatedHandler |
| 0x006a1150 | HostEventHandler |
| 0x006a1590 | NewPlayerInGameHandler |
| 0x006a1790 | StartFiringHandler |
| 0x006a17a0 | StartWarpHandler |
| 0x006a17b0 | TorpedoTypeChangeHandler |
| 0x006a18d0 | StopFiringHandler |
| 0x006a18e0 | StopFiringAtTargetHandler |
| 0x006a18f0 | StartCloakingHandler |
| 0x006a1900 | StopCloakingHandler |
| 0x006a1910 | SubsystemStatusHandler |
| 0x006a1920 | AddToRepairListHandler |
| 0x006a1930 | ClientEventHandler |
| 0x006a1940 | RepairListPriorityHandler |
| 0x006a1970 | SetPhaserLevelHandler |
| 0x006a1a60 | DeleteObjectHandler |
| 0x006a1a70 | ChangedTargetHandler |
| 0x006a1b10 | ChecksumCompleteHandler |
| 0x006a2640 | KillGameHandler |
| 0x006a2a40 | RetryConnectHandler |
| 0x006a1240 | ObjectExplodingHandler |
| 0x006a07d0 | EnterSetHandler |
| 0x006a0a10 | ExitedWarpHandler |

---

## Ship Subsystem Type Catalog

**Validated by JMP detour trace** (2026-02-10, stock dedicated server, 223K lines).
See [../analysis/subsystem-trace-analysis.md](../analysis/subsystem-trace-analysis.md) for full trace data.

### Vtable-to-Type Map

| vtable | Type | Named Slot | Offset | Instances (Sovereign) |
|--------|------|-----------|--------|----------------------|
| 0x0088A1F0 | PoweredSubsystem | Powered | +2B0 | 1 |
| 0x00892C98 | PowerReactor | Power | +2C4 | 1 (+1 secondary in list) |
| 0x00892D10 | LifeSupport | Unk_C | +2CC | 1 |
| 0x00892E24 | WarpDrive | Unk_E | +2D8 | 1 |
| 0x00892EAC | CloakingDevice | Cloak | +2C8 | 1 |
| 0x00892F34 | RepairSubsystem | Repair | +2C0 | 1 |
| 0x00892FC4 | ImpulseEngine | -- | -- | 4 |
| 0x00893040 | SensorArray | Unk_B | +2D0 | 1 |
| 0x00893194 | PhaserEmitter | -- | -- | 8 |
| 0x00893240 | PhaserController | Phaser | +2B8 | 1 |
| 0x00893598 | ShieldGenerator | Shield | +2B4 | 1 |
| 0x00893630 | TorpedoTube | -- | -- | 6 (4 fwd, 2 aft) |
| 0x008936F0 | TractorBeam | -- | -- | 4 |
| 0x00893794 | PulseWeapon | Pulse | +2D4 | 1 |
| 0x00895340 | ShipRefNiNode | ShipRef | +2E0 | 1 (set separately) |

### Named Slot Layout (ship+0x2B0 to ship+0x2E4)

```
+2B0  Powered      0x0088A1F0   Master powered subsystem
+2B4  Shield       0x00893598   Shield generator
+2B8  Phaser       0x00893240   Phaser controller
+2BC  (unused)     NULL         Always NULL
+2C0  Repair       0x00892F34   Auto-repair
+2C4  Power        0x00892C98   Power reactor
+2C8  Cloak        0x00892EAC   Cloaking device (present on all ships)
+2CC  LifeSupport  0x00892D10   Structural/life support
+2D0  SensorArray  0x00893040   Sensors
+2D4  Pulse        0x00893794   Pulse weapons (present on all ships)
+2D8  WarpDrive    0x00892E24   Warp drive
+2DC  (unused)     NULL         Always NULL
+2E0  ShipRef      0x00895340   NiNode scene graph backpointer
```

### Anti-Cheat Hash Field Offsets (from ship+0x27C)

These offsets are used by FUN_005b5eb0 to locate subsystem pointers for hash computation.
Hashed in this exact order (each slot is NULL-checked; NULL slots are skipped):

| Hash Order | Offset from +0x27C | Ship Offset | Subsystem | Hash Method | Extra Fields |
|---|---------------------|-------------|-----------|-------------|--------------|
| 1 | +0x48 | +0x2C4 | Power Reactor | base_subsystem_hash | none |
| 2 | +0x44 | +0x2C0 | Shield Generator | base + type-specific | 12 floats: 6 maxShield + 6 chargePerSecond facings |
| 3 | +0x34 | +0x2B0 | Powered Master | base + type-specific | 5 property floats |
| 4 | +0x4C | +0x2C8 | Cloak Device | base + type-specific | 1 property float |
| 5 | +0x50 | +0x2CC | Impulse Engine | base + type-specific | 4 property floats |
| 6 | +0x54 | +0x2D0 | Sensor Array | base_subsystem_hash | none |
| 7 | +0x5C | +0x2D8 | Warp Drive | base + type-specific | 1 property float |
| 8 | +0x60 | +0x2DC | Crew / Unknown-A | base_subsystem_hash | side-effect getter |
| 9 | +0x38 | +0x2B4 | Torpedo System | weapon_system_hash | children + torpedo types |
| 10 | +0x3C | +0x2B8 | Phaser System | weapon_system_hash | children |
| 11 | +0x40 | +0x2BC | Pulse Weapon System | weapon_system_hash | children |
| 12 | +0x58 | +0x2D4 | Tractor Beam System | weapon_system_hash | children |

**Note**: The Repair subsystem does NOT appear in the hash. See [subsystem-integrity-hash.md](subsystem-integrity-hash.md) for complete analysis.
