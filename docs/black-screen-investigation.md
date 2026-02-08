# Black Screen Investigation

## Symptom
Client connects to dedicated server, checksums pass, keepalive works, in-session music plays,
but screen is black with no cursor, no scoreboard, no ship selection.

## What We've Tried (all FAILED to fix)
1. **Patched checksum flag 0→1** (PatchChecksumAlwaysPass at 0x006a1b75)
   - Without this patch, FUN_006f3f30 was never called (no game state data appended)
   - With patch, FUN_006f3f30 runs and appends data, but still black screen
2. **Removed ET_START and Mission1.Initialize** (lobby mode)
   - Server stays g_bGameStarted=0
   - Thought client was skipping lobby because game was "in progress" - WRONG
3. **Patched FUN_0055c810 crash** (PatchHeadlessCrashSites)
   - Fixed VEH crash #6 during client connection, but unrelated to black screen

## Current Server State (sent in opcode 0x00)
- DAT_008e5f59 = 0x01 (game settings byte - need to understand what this controls)
- DAT_0097faa2 = 0x00 (game settings byte - need to understand what this controls)
- Map name = 'Multiplayer.Episode.Mission1.Mission1' (correct)
- gameTime = ~10-20 seconds (normal - user confirmed non-zero is OK)
- checksum flag = 0x01 (PASS, after our patch)

## Packet Flow (from log)
1. Client connects → PLAYERS CHANGED: 0→1 (or 1→2 if host counted)
2. Checksum exchange: 4 rounds of request/response (opcodes 0x20/0x21)
3. Server sends settings packet (opcode 0x00) - 29 bytes
4. Server sends status packet (opcode 0x01) - single byte
5. Keepalive ping/pong continues (3-byte packets every ~5 seconds)
6. Client stays connected but shows black screen

## Key Unknowns
1. **What does the client-side handler for opcode 0x00 actually do?**
   - The MultiplayerGame ReceiveMessageHandler at LAB_0069f2a0 dispatches game opcodes
   - This address is NOT a function in Ghidra → cannot decompile
   - Calls FUN_0069f930 from 0x0069f4d0, FUN_0069f880 from 0x0069f3f4
   - MUST create function at 0x0069f2a0 in Ghidra for proper analysis

2. **What triggers the ship selection screen on the client?**
   - Is it the opcode 0x00 packet?
   - Is it a Python event fired after settings are received?
   - Is there a specific UI transition function?

3. **What do DAT_008e5f59 and DAT_0097faa2 control?**
   - DAT_008e5f59 = DAT_008e5f58 (set in MultiplayerGame constructor)
   - DAT_0097faa2 is written to piVar5 + 0x2d in some init function
   - Could these indicate "lobby" vs "in-game"?

4. **Is the opcode 0x00 packet data correct/complete?**
   - FUN_006f3f30 appends checksum match data, but since no other players exist
     to match against, the data might be empty/wrong format
   - The client might expect specific data from FUN_006f3f30 to proceed

5. **Does the server need to be in ProcessingPackets=1 mode BEFORE client connects?**
   - Currently set in TopWindowInitialized, should be early enough

## Two Dispatch Paths (IMPORTANT)
- **NetFile/ChecksumManager (FUN_006a3cd0)**: opcodes 0x20-0x27 (checksums, files)
- **MultiplayerGame (LAB_0069f2a0)**: opcodes 0x00-0x0F (game messages)
These are SEPARATE dispatchers on SEPARATE objects.

## Next Steps to Try
1. **Create function at 0x0069f2a0 in Ghidra** → decompile the dispatch table
2. **Compare packet captures** between normal server and our server
3. **Check if FUN_006f3f30 data is valid** when no checksum matches exist
4. **Trace what the CLIENT does** after receiving opcode 0x00
5. **Check DAT_008e5f58** value at runtime (source of DAT_008e5f59)
6. **Look at FUN_0069f620 (param_2 variant)** - handles object creation, might be
   the function that processes opcode 0x00 on the client side
