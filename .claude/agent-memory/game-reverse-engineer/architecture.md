# Architecture Notes

## Client-Side Message Processing Chain
1. TGNetwork::Update receives packet, fires ET_NETWORK_MESSAGE_EVENT (0x60001)
2. EventManager dispatches to ALL registered handlers for 0x60001:
   - NetFile::ReceiveMessageHandler (FUN_006a3cd0) - opcodes 0x20-0x27
   - MultiplayerGame::ReceiveMessageHandler (LAB_0069f2a0) - opcodes 0x00-0x0F
   - MultiplayerWindow::ReceiveMessageHandler (FUN_00504c10) - opcodes 0x00, 0x01, 0x16
   - ChatObjectClass::ReceiveMessageHandler - chat messages
3. Each handler checks the message class and opcode independently

## Message Class IDs
- Messages created via FUN_006b82a0 have vtable PTR_LAB_008958d0
- FUN_00504c10 checks `(**(code **)*this_00)() == 0x32` (vtable[0] returns class ID)
- If the server creates a message with the WRONG class, the client's 0x32 check fails
- The server-side ChecksumCompleteHandler uses FUN_006b82a0 for basic messages

## MultiplayerWindow+0xb0 Flag
- Set to 0 during FUN_00504890 (StartGameHandler) at line 2183
- Set from stream in deserialize (FUN_00505500 line 2572)
- ConnectHandler (LAB_00505040) likely sets it - but decompilation incomplete
- Guards FUN_00504c10 - if 0, ALL received messages are silently dropped

## Server-Side ChecksumCompleteHandler (FUN_006a1b10) Flow
1. Gets player slot index from peer ID
2. Looks up peer in WSN peer array
3. Cross-checks checksums against ALL other players (iterates slots 0-15)
4. If any mismatch found: sets local_45c = 1 (checksum fail flag)
5. Builds opcode 0x00 packet: [0x00][gameTime:f32][DAT_008e5f59:u8][DAT_0097faa2:u8][slot:u8][mapNameLen:u16][mapName][passFail:u8]
6. If passFail != 0: calls FUN_006f3f30 to append mismatch data
7. Sends opcode 0x00 (reliable)
8. Sends opcode 0x01 (reliable) - just [0x01]

## DAT_008e5f59 and DAT_0097faa2
- DAT_008e5f59 is read from the settings packet by client FUN_00504d30
  - Client stores it back to DAT_008e5f59 (line 2326)
  - Also read by opcode 0x16 handler (line 2281)
  - Appears to be a game mode/settings byte
- DAT_0097faa2 is read by client as `this+0xb4` on MultiplayerWindow (line 2328)
  - Used in serialization at FUN_00505500 line 2531
  - Likely a secondary settings/mode flag

## Critical Flow: Opcode 0x01 Handler (FUN_00504f10)
This is the KEY function for the client transition:
1. Calls FUN_006f8ab0 with "AI_Setup", "GameInit" - initializes AI system
2. Creates MultiplayerGame via FUN_0069e590 with "Multiplayer.MultiplayerGame"
3. If IsMultiplayer: reads g_iPlayerLimit from MissionMenusShared
4. Sets maxPlayers on MultiplayerGame (puVar3[0x7f])
5. Loads TGL "data/TGL/Multiplayer.tgl", finds "Connection Completed" text
6. Shows status text via FUN_006f4ee0, calls FUN_005054b0 (UI transition)
7. FUN_005054b0 navigates the UI pane tree to show the game setup/lobby screen
