# STBC Event Types (from MultiplayerGame constructor FUN_0069e590)

## Network Events (0x6000x)
| Type | Handler Name | Handler Address | Notes |
|------|-------------|-----------------|-------|
| 0x60001 | ReceiveMessageHandler | 0x0069f2a0 | All game opcodes 0x00-0x0F |
| 0x60003 | DisconnectHandler | 0x006a0a20 | Player disconnected |
| 0x60004 | NewPlayerHandler | 0x006a0a30 | New connection, assigns slot |
| 0x60005 | DeletePlayerHandler | 0x006a0ca0 | Player removed |

## Game Events (0x8000xx) - HOST ONLY (registered inside `if DAT_0097fa8a != 0` block)
| Type | Handler Name | Handler Address | Notes |
|------|-------------|-----------------|-------|
| 0x8000df | HostEventHandler | 0x006a1150 | |
| 0x800074 | HostEventHandler | 0x006a1150 | Shared handler |
| 0x800075 | HostEventHandler | 0x006a1150 | Shared handler |
| 0x8000e8 | SystemChecksumPassedHandler | 0x006a0c60 | All checksums pass |
| 0x8000e7 | SystemChecksumFailedHandler | 0x006a0c90 | Checksum mismatch |
| 0x8000e6 | ChecksumCompleteHandler | 0x006a1b10 | Per-player checksum done |
| 0x80005d | EnterSetHandler | 0x006a07d0 | |
| 0x8000c5 | ExitedWarpHandler | (near 0x006a17a0) | |

## Game Events - ALWAYS registered (both host and client)
| Type | Handler Name | Handler Address | Notes |
|------|-------------|-----------------|-------|
| 0x80004e | ObjectExplodingHandler | 0x006a1240 | |
| 0x8000f1 | NewPlayerInGameHandler | 0x006a1e70 | Calls Python InitNetwork! |
| 0x8000d8 | StartFiringHandler | 0x006a1790 | |
| 0x8000da | StopFiringHandler | (near 0x006a1930) | |
| 0x8000dc | StopFiringAtTargetHandler | (near 0x006a1930) | |
| 0x8000dd | SubsystemStatusHandler | (near 0x006a1930) | |
| 0x800076 | RepairListPriorityHandler | (near 0x006a1940) | |
| 0x8000e0 | SetPhaserLevelHandler | 0x006a1970 | |
| 0x8000e2 | StartCloakingHandler | 0x006a18f0 | |
| 0x8000e4 | StopCloakingHandler | 0x006a1900 | |
| 0x8000ec | StartWarpHandler | 0x006a17a0 | |
| 0x8000fe | TorpedoTypeChangeHandler | 0x006a17b0 | |

## Event Flow: New Player Connection
1. TGNetwork fires `0x60004` (ET_NETWORK_NEW_PLAYER)
2. NewPlayerHandler (0x006a0a30) assigns slot, calls FUN_006a3820 (checksum start)
3. Checksum exchange (opcodes 0x20/0x21, 4 rounds)
4. NetFile fires `0x8000e6` per-player when done (from FUN_006a4560 line 3977)
5. ChecksumCompleteHandler (0x006a1b10) sends opcode 0x00 + 0x01
6. NetFile fires `0x8000e8` from FUN_006a4bb0 when ALL pass
7. SystemChecksumPassedHandler (0x006a0c60) handles 0x8000e8
8. At some point `0x8000f1` fires -> NewPlayerInGameHandler (0x006a1e70)
9. FUN_006a1e70 calls Python InitNetwork(playerID) via FUN_006f8ab0
10. InitNetwork sends MISSION_INIT_MESSAGE -> client shows ship selection

## CRITICAL: 0x8000f1 (NewPlayerInGame) fires FROM:
- Constructor at line 5509-5524: fires for HOST immediately with its own ID
- FUN_006a1e70 at line 975: fires during NewPlayerInGameHandler itself (re-posts)
- Need to trace WHERE 0x8000f1 originates for non-host players after checksums
