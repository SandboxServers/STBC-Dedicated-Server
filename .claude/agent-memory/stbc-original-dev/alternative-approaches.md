# Alternative Approaches to Headless Dedicated Server

## Analysis Date: 2026-02-09 (updated 2026-02-10)
## Context: DDraw proxy approach with targeted binary patches

## Approach Ranking (Least Effort to Most)

### 1. Stub Only Final Draw Calls (Current Approach)
- Renderer initializes fully (pipeline objects build via proxy COM)
- PatchDeviceCapsRawCopy prevents raw memcpy crash in FUN_007d1ff0
- PatchRendererMethods stubs 3 specific vtable methods
- D3D7 proxy stubs DrawPrimitive, DrawIndexedPrimitive, Flip, Blt-for-present
- PatchRenderTick skips render work (no GPU cost)
- PatchTGLFindEntry handles missing TGL UI data
- CrashDumpHandler logs diagnostics on any unhandled crash

### 3. Small Hidden Window + Real D3D (Simplest Possible)
- Create real window (64x64 or minimum), hide/minimize immediately
- Real DirectDraw7, real D3D7, real device, real surfaces (system memory)
- Only stub Present/Flip (return S_OK, never display)
- Everything else runs completely stock
- Higher CPU/GPU cost but zero risk of cascade failures
- Good as a validation step: "does the game work headless if rendering is a no-op?"

### 4. Full Reimplementation of Network Protocol (Nuclear Option)
- Write a standalone server from scratch
- Implement TGWinsockNetwork UDP protocol
- Implement checksum exchange
- Implement game state management
- Implement simulation (or skip it and relay client state)
- MASSIVE effort, months of work, likely more than fixing current approach
- Only makes sense if BC's engine is truly unfixable (it is not)

## Why Subsystem Lists Are Still NULL
Root cause chain:
1. Renderer pipeline builds successfully (PatchSkipRendererSetup removed)
2. NIF loader runs but ship models need GPU texture backing for full loading
3. Without loaded NIF models, scene graph nodes are incomplete
4. Incomplete scene graphs -> NULL subsystem/weapon linked lists at ship+0x284
5. PatchNetworkUpdateNullLists correctly clears flags to prevent garbage packets
6. Result: server sends empty StateUpdates (flags=0x00), client disconnects

## Key Architectural Facts
- NetImmerse 3.1: scene graph = render graph, no separation possible
- Ship hardpoints are NiNode children found by name in the geometry tree
- NiBound (collision volumes) computed from child geometry vertices
- NIF loader requires renderer+0xC8 (geometry group mgr) for vertex buffer allocation
- Simulation reads from scene graph (positions, rotations, bounds) but never writes pixels
- The "dedicated server" has always been "full engine minus one player ship"
