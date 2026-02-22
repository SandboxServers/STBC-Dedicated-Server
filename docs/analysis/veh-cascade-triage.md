> [docs](../README.md) / [analysis](README.md) / veh-cascade-triage.md

# VEH Cascade Triage: Why VEH Was Removed

Date: 2026-02-10
Source: win32-crash-analyst + game-reverse-engineer + stbc-original-dev agent analysis

## Verdict: VEH is 100% a corruption cascade, not a real game bug

### Evidence
1. **Stock dedicated server has ZERO VEH crashes** (vehR=0, vehW=0 in every tick)
2. **ESI=0x21 is not a game value** - stale register from pre-cascade, never updated because VEH jumped past function prologue
3. **EDX=0xC000000D is NTSTATUS** leaked from Windows exception dispatch internals
4. **EAX=0x01290000 is g_pNullDummy** - VEH-injected value, not game code
5. **Return address was 0x00000000** - stack corruption from 100/sec VEH noise

## The 100/sec Crash Pattern (Root Cause)

### 0x00419963 (AsteroidField constructor, FUN_004196d0)
- Deep in initialization chain, needs scene graph objects
- Base class constructor (FUN_00435030) fails to create NiNode objects (no renderer)
- VEH patches NULL, constructor "completes" -> creates **zombie object**
- Zombie has valid vtable (0x00888B84) and passes NULL checks, but internal data is garbage
- Game iterates all AsteroidField objects each frame -> each zombie triggers more crashes

### 0x004360CB (GetBoundingBox, FUN_004360c0)
```c
pfVar6 = (float *)(**(code **)(*this + 0xe4))();  // GetWorldBound()
fVar1 = pfVar6[3];                                  // CRASH: returns NULL/garbage
```
- vtable+0xe4 = GetWorldBound() on NiAVObject
- Zombie objects -> GetWorldBound() returns NULL -> pfVar6[3] crashes
- VEH redirects to dummy -> zero-size bounding box -> ALL spatial queries meaningless

### The Cascade Mechanism
1. AsteroidField ctor crashes at 0x00419963 (60-100/sec)
2. VEH patches -> zombie AsteroidField objects
3. Game iterates zombies -> GetBoundingBox at 0x004360CB (100/sec)
4. VEH patches those too -> zero-size bounds
5. VEH recoveries happen on SAME thread during re-entrant event dispatch
6. Each recovery adjusts ESP -> corrupts stack frames of outer functions
7. FUN_006a1b10 (ChecksumCompleteHandler) has corrupted stack-local TGNetworkStreamWriter
8. FUN_006cf1c0 writes dead marker through corrupt pointer -> .rdata AV
9. RET pops corrupted return address -> cascade through ReceiveMessageHandler -> event dispatcher

## 4-Stage Crash Chain (Specific Instance)

### Stage 1: FlatBufferStream dead-marker (SAFE skip)
- EIP=0x006CF1DC: `MOV [EAX], 0xFFFFFFFE` writing to .rdata 0x00895C58
- VEH skips to RET at 0x006CF1E2 -- correct, dead marker is diagnostic only
- But: RET pops 0x00000000 (corrupted return address)

### Stage 2: Bad EIP=0x0 (DANGEROUS)
- Stack-scan finds 0x0069F3E5 at ESP+48 (ReceiveMessageHandler)
- Jumps there with wrong register context
- Destroys all callee-saved registers from intermediate frames

### Stage 3: Bad EIP=0x5 (DANGEROUS)
- Code at 0x0069F3E5 dereferences EAX=0 -> vtable+5 = 0x5
- Stack-scan finds 0x006E2249 at ESP+10 (event dispatcher mid-loop)

### Stage 4: UNRECOVERABLE
- EIP=0x006E2249: `MOV EAX, [ESI+0x0C]` where ESI=0x21 (stale)
- Function prologue never ran -> this+0x30 recursion counter never incremented
- Any recovery would leave event system recursion counter corrupted permanently

## Resolution: VEH Removed

VEH was removed entirely on 2026-02-10. Replaced with:
- `SetUnhandledExceptionFilter(CrashDumpHandler)` - logs full diagnostics to crash_dump.log
- Process terminates cleanly on any unhandled exception
- Each crash site will be fixed with targeted code cave patches (prevent crash at source)
- All proactive binary patches (PatchTGLFindEntry, PatchNetworkUpdateNullLists, etc.) retained

## What Would Happen Without VEH

Process crashes immediately on FIRST access violation at root sites:
- 0x00419963: First AsteroidField construction after client connects
- 0x004360CB: Any GetBoundingBox on scene-graph-dependent object
- 0x006D1E10: TGL::FindEntry NULL sentinel

The fundamental issue: headless server has no DDraw/D3D renderer, so ANY code path
touching NetImmerse scene graph (NiNode, NiAVObject, NiBound) hits NULL pointers.
This includes object construction, bounding box queries, visibility, animation, collision.

**The correct fix is not VEH recovery but preventing these code paths from executing.**
