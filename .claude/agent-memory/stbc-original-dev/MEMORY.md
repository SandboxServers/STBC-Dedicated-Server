# STBC Original Developer Agent Memory

## Key Design Intent Conclusions

### Scene Graph is Load-Bearing for Networking
FUN_005b17f0 (network state update) calls NiAVObject vtable methods (0x94=GetWorldTranslation, 0xac=GetWorldRotation, 0xb0=GetWorldScale) with ZERO null checks. Objects in the simulation MUST have valid scene graphs. This was an invariant, not a checked condition. See [design-intent.md](design-intent.md).

### Stock Dedicated Server = Full Engine + Different UI
The stock "Dedicated Server" toggle (MultiplayerMenus.py:2996) only sets IsClient=0. Full renderer, NIF loading, scene graph, simulation all run normally. The dedicated host sees the options menu pane, not the tactical view. GPU still renders every frame.

### Ship Subsystem/Weapon Population Chain
CreateShip -> SetupModel(NIF load) -> LoadPropertySet(hardpoints) -> SetupProperties(C++ engine creates subsystem objects from hardpoints + scene graph nodes) -> UpdateNodeOnly. SetupProperties requires named NiNode children in the scene graph matching hardpoint names.

### The Correct Headless Approach
Stub D3D draw calls (DrawPrimitive, Present/Flip) at the lowest level. Let renderer pipeline build fully. The NIF loader and scene graph construction depend on renderer internal state. PatchDeviceCapsRawCopy prevents the raw memcpy crash, PatchRendererMethods stubs specific vtable methods. See [design-intent.md](design-intent.md) for full analysis.

### NiDX7Renderer Pipeline (FUN_007c3480) Analysis
FUN_007cb2c0 (NiD3DGeometryGroupManager ctor) takes 3 stack params, not 1 as Ghidra shows:
IDirect3D7*, IDirect3DDevice7*, bool. RET 0xC confirms. Both D3D pointers get AddRef'd via
vtable[1]. T&L flag determines SYSTEMMEMORY vs WRITEONLY VB path. Adapter creation (FUN_007c7f80)
calls DirectDrawCreateEx internally via GetProcAddress("DDRAW.DLL") which hits the proxy DLL.
Full analysis in [design-intent.md](design-intent.md).

### Multiplayer Architecture: Server-Authoritative with Delta Compression
NOT lockstep, NOT peer-to-peer. Host runs full simulation for all ships. Sends delta
state updates via FUN_005b17f0 (flag byte + changed fields). Clients send inputs.
Host applies inputs and pushes resulting state.

### Full Network Protocol Architecture (NEW)
Two dispatch layers: C++ engine messages (binary, compact) and Python TGMessages
(via TGBufferStream). State updates use dirty-flag delta compression with round-robin
subsystem/weapon budgets (10 bytes/6 bytes per frame). Combat events (fire, cloak,
warp, explode) are separate reliable messages. Python messages use first-byte type
discriminator with App.MAX_MESSAGE_TYPES as base offset. Full protocol breakdown
in design-intent.md under "Multiplayer Network Protocol - Full Architecture".

### Python vs C++ Split
C++ handles ~90% of simulation (physics, collision, weapons, shields, AI, network
serialization). Python handles ~10% (mission setup, game mode rules, UI flow, event
handlers, scoring, chat). Cannot run server on Python alone.

### Stock Dedicated Server Implementation
MultiplayerMenus.py line 2996: `g_pHostDedicatedButton.IsChosen()` -> `SetIsClient(0)`.
Line 909-917: `IsHost() and (not IsClient())` -> show options pane instead of tactical.
Full renderer runs. No headless capability. This was a scope/priority decision, not
a technical impossibility.

## File Index
- [design-intent.md](design-intent.md) - Detailed architecture analysis and design intent
- [load-bearing-bugs.md](load-bearing-bugs.md) - Bugs/behaviors that other code depends on
- [alternative-approaches.md](alternative-approaches.md) - Analysis of headless server strategies
