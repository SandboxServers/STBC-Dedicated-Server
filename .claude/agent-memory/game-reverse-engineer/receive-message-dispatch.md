# MultiplayerGame::ReceiveMessageHandler Dispatch Table

## Location
- Handler entry: LAB_0069f2a0 (undefined function in Ghidra)
- Registered for: Event 0x60001 (ET_NETWORK_MESSAGE_EVENT)
- Spans: 0x0069f27c to 0x0069f61f (gap between FUN_0069f250 and FUN_0069f620)
- Registration: FUN_006da130(&LAB_0069f2a0, "MultiplayerGame :: ReceiveMessageHandler")

## Dispatch Table (calls from within the handler)
| Call Address | Target | Description |
|---|---|---|
| 0x0069f30d | FUN_006a1e70 | InitNetwork + replicate objects to new player |
| 0x0069f323 | FUN_0069f620 | Game object create/update (no team byte) |
| 0x0069f339 | FUN_0069f620 | Game object create/update (with team byte) |
| 0x0069f352 | FUN_0069fda0 | Event forward/dispatch |
| 0x0069f36b | FUN_0069fda0 | Event forward/dispatch |
| 0x0069f384 | FUN_0069fda0 | Event forward/dispatch |
| 0x0069f39d | FUN_0069fda0 | Event forward/dispatch |
| 0x0069f3b6 | FUN_0069fda0 | Event forward/dispatch |
| 0x0069f3cc | FUN_0069fda0 | Event forward/dispatch |
| 0x0069f3e0 | FUN_0069ff50 | Generic handler |
| 0x0069f3f4 | FUN_0069f880 | Event post |
| 0x0069f40d | FUN_0069fda0 | Event forward/dispatch |
| 0x0069f426 | FUN_0069fda0 | Event forward/dispatch |
| 0x0069f43f | FUN_0069fda0 | Event forward/dispatch |
| 0x0069f458 | FUN_0069fda0 | Event forward/dispatch |
| 0x0069f46c | FUN_006a0080 | Torpedo/projectile create |
| 0x0069f480 | FUN_006a01e0 | Object delete |
| 0x0069f4d0 | FUN_0069f930 | Ship state update (pos/orient/velocity) |
| 0x0069f4e4 | FUN_0069fbb0 | Ship weapons state update |
| 0x0069f520 | FUN_006a02a0 | Object state request/reply |

## Key Insight
FUN_006a1e70 is the FIRST dispatch case (0x0069f30d), strongly suggesting it handles
the lowest numbered game opcode in the MultiplayerGame dispatcher.

## Cannot Be Decompiled
This area is not recognized as a function in Ghidra. The MCP bridge cannot create
functions. To decompile, manually create function at 0x0069f2a0 in Ghidra GUI.

## Game Opcode 0x1c
FUN_005b17f0 (ship state writer) writes 0x1c as its opcode byte. This is the
periodic ship state update. The dispatcher maps it to FUN_0069f930 or FUN_005b21c0
(receiver side, called via vtable).
