# Client Disconnect Investigation

## Current Status: CLIENT DISCONNECTS ~3 SEC AFTER SHIP SELECTION

Client connects to dedicated server, checksums pass (4 rounds), reaches ship selection screen,
player appears on scoreboard, ship model is visible. Then ~3 seconds later:
**"You have been disconnected from the host computer"**

### Previously Solved: Black Screen (no longer occurs)
The original black screen issue was caused by missing NewPlayerInGame handshake.
Fixed by GameLoopTimerProc calling FUN_006a1e70 (opcode 0x2A handler) when player count
increases. Client now receives Settings (0x00), GameInit (0x01), ObjCreateTeam (0x03),
and transitions to ship selection UI.

## Root Cause Analysis

The disconnect is caused by **empty StateUpdate packets** from the server.

### The Causal Chain (verified against stock-dedi comparison)

1. **NIF models don't load headlessly** - the proxy DLL stubs the D3D7 renderer, so
   NIF model loading (which depends on renderer pipeline for texture/geometry) produces
   objects without valid scene graph nodes.

2. **AddToSet("Scene Root", prop) fails** - SubsystemProperty objects can't link to
   NiNode "Scene Root" in the NIF model because the node doesn't exist.

3. **Subsystem linked list at ship+0x284 is NULL** - no properties linked means
   FUN_005b3fb0 finds nothing to create, so the runtime subsystem list stays empty.

4. **PatchNetworkUpdateNullLists clears the 0x20 flag** - our binary patch at 0x005b1d57
   correctly prevents sending malformed subsystem data by clearing flags when +0x284 is NULL.
   Result: flags byte = 0x00 (empty) instead of 0x20 (SUB).

5. **Client expects regular subsystem health updates** - stock server sends flags=0x20
   (SUB) with real health values ~10x per second per object, cycling through subsystem
   groups at startIdx 0, 2, 6, 8, 10. Our server sends flags=0x00 (nothing).

### Evidence: Stock Server vs Our Server

| Aspect | Stock Server | Our Server |
|--------|-------------|------------|
| NIF model loading | Works (real D3D7) | Fails (stubbed renderer) |
| Ship subsystem list (+0x284) | Populated (10+ subsystems) | NULL |
| StateUpdate flags sent (S->C) | 0x20 (SUB) or 0x3E (full) | 0x00 (empty) |
| Subsystem cycling | startIdx 0,2,6,8,10 at ~100ms | None |
| Client behavior | Stays connected | Disconnects after ~3 sec |

See: [docs/empty-stateupdate-root-cause.md](empty-stateupdate-root-cause.md) for full 5-step analysis.

## What Works (Confirmed)

- Headless boot through all 4 phases, Python DedicatedServer.TopWindowInitialized() runs
- MultiplayerGame: ReadyForNewPlayers=1, MaxPlayers=8, ProcessingPackets=1
- GameSpy LAN discovery, peek-based UDP router
- Checksum exchange (4 rounds) completes successfully
- Settings packet (opcode 0x00) sent with correct map name and player slot
- GameInit (0x01) triggers client-side setup
- ObjCreateTeam (0x03) creates player ship on client
- Client reaches ship selection, player on scoreboard, ship model visible
- First connection timeout issue exists (client must reconnect once)

## Packet Flow (from stock-dedi comparison)

### Working flow (stock server):
1. Client connects -> NewPlayerHandler fires
2. Checksum exchange: 4 rounds of 0x20/0x21
3. Server sends Settings (0x00) + GameInit (0x01)
4. Client sends NewPlayerInGame (0x2A)
5. Server sends ObjCreateTeam (0x03) + GameState (0x35) + PlayerRoster (0x37)
6. Server begins StateUpdate cycling: flags=0x20, startIdx rotating
7. Client stays connected, game session active

### Our flow (disconnects):
1-5: Same as stock (all working)
6. Server sends StateUpdate with flags=0x00 (empty) - no subsystem data
7. Client disconnects after ~3 sec

## Fix Approaches (from root cause analysis)

### 1. Enable NIF model loading on headless server (RECOMMENDED)
NIF loading (NiStream::Load) is file I/O, not renderer-dependent. If the renderer
pipeline can be restored enough to not crash during NIF loading, the entire subsystem
chain works automatically. This would produce flags=0x20 with real subsystem data.

### 2. Synthesize subsystem data in StateUpdate packet
Binary patch to intercept flags byte write and inject synthetic subsystem data
(all 0xFF = full health). Requires understanding exact wire format for subsystem updates.

### 3. Accept flags=0x00 and fix client-side consequences
If client can tolerate missing SUB data, session may function.
But client likely treats prolonged absence of subsystem updates as connection failure.

## Key Addresses

| Address | Function | Role |
|---------|----------|------|
| 0x005b17f0 | FUN_005b17f0 | StateUpdate serializer (per-ship per-tick) |
| 0x005b21c0 | FUN_005b21c0 | StateUpdate receiver/deserializer |
| 0x005b1d57 | (patch site) | PatchNetworkUpdateNullLists - clears flags when +0x284 NULL |
| 0x006a1e70 | FUN_006a1e70 | NewPlayerInGame handler (opcode 0x2A) |
| 0x006a1b10 | FUN_006a1b10 | ChecksumCompleteHandler (sends 0x00 + 0x01) |
