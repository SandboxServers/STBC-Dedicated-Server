# VEH Sustainability Analysis

## Core Finding: VEH mid-function recovery is fundamentally unsafe for complex object construction

### The Cascade Problem
1. VEH register redirect makes instruction succeed but function's INTENDED SIDE EFFECTS never happen
2. Object gets partially initialized - some fields set, others left as-is
3. Downstream code reads those fields expecting valid data
4. More crashes, more VEH recovery, more partial initialization
5. Stack frame alignment can drift if VEH skips instructions that modify ESP

### Evidence
- 0x00419963 (AsteroidField ctor): fires 60-100/sec - constructor partially completing
- 0x004360CB (GetBoundingBox): vtable+0xe4 call returns garbage because object not properly constructed
- 0x006CF1DC: this+0x04 contains vtable address instead of sub-object ptr - likely from stack corruption where `this` shifted by -4 bytes
- Each targeted VEH fix reveals 2-3 more crash sites downstream

### Why the Dummy Buffer Approach Has Limits
- g_pNullDummy is 64KB zeroed memory with fake vtable pointing to `xor eax,eax; ret`
- Works for: simple NULL deref reads (returns 0), vtable calls on NULL objects (returns 0)
- FAILS for: complex multi-step object construction, bounding box calculations (returns zero-size bounds), any code that checks for specific non-zero values

### GetBoundingBox (0x004360c0) Analysis
```
004360c0: SUB ESP,0x18
004360c3: MOV EAX,[ECX]       ; load vtable
004360c5: CALL [EAX+0xe4]     ; call virtual method (index 0x39)
004360cb: FLD [EAX+0xc]       ; EAX is return value, use as NiBound ptr
```
- vtable+0xe4 is "GetWorldBound()" on NiAVObject
- If ECX is null/dummy, call returns 0 (from stub), then FLD [0x0C] crashes
- Even if we redirect EAX to dummy, result is zero-size bounding box at origin
- All spatial queries (collision, proximity, culling) become meaningless

### AsteroidField Constructor (FUN_004196d0) at 0x00419963
- Function is in 0x004196d0-0x00419a2f range (gap in Ghidra's function database)
- Constructor sets up proximity manager, collision sets, allocates sub-objects
- Crash mid-constructor = partially constructed AsteroidField with NULL sub-objects
- Every frame: game iterates AsteroidField list, each tries to use NULL sub-objects

## Assessment: Current approach cannot be made stable
- Too many crash sites in object construction paths
- VEH recovery produces zombie objects (not NULL, not valid)
- Zombie objects are worse than NULL because they pass NULL checks
- The TGL::FindEntry returning 0x1C pattern is the canonical example of this

## Viable alternatives (ranked by crash-elimination potential)
1. **System-memory render backend** - provide real DDraw/D3D that renders to RAM
   - Eliminates ALL renderer-related NULL pointers at source
   - Objects fully constructed with valid scene graph data
   - CPU cost: moderate (software rasterization is cheap at 1x1 resolution)

2. **Stub NiRenderer + NiAVObject** - provide valid NetImmerse objects
   - Harder than option 1 because NI objects are deeply interconnected
   - Would need to understand full NiNode/NiGeometry/NiRenderer hierarchy

3. **Function-level interception** - replace entire functions that crash
   - Instead of VEH recovery, replace the function entry points
   - AsteroidField ctor: replace to set all fields to safe defaults
   - GetBoundingBox: replace to return a 1-unit bounding box
   - More targeted than VEH, but need to find ALL crash-prone functions
