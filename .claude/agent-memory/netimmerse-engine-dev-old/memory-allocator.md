# NetImmerse/Python Memory Allocator Analysis

## Custom Allocator Singleton at 0x0099C478
The region 0x0099C478-0x0099C4B0 is the **custom small-block memory allocator** used by
the embedded Python 1.5.2 interpreter (and possibly shared with some engine subsystems).

### Structure Layout (0x0099C478 base)
| Offset | Address    | Purpose |
|--------|-----------|---------|
| +0x00  | 0x0099C478 | Allocator base/this ptr (used as ECX for thiscall) |
| +0x08  | 0x0099C480 | Pool bucket count (used in binary search) |
| +0x0C  | 0x0099C484 | Pool bucket array pointer (0x24-byte entries, sorted by size) |
| +0x10  | 0x0099C488 | Small alloc count |
| +0x14  | 0x0099C48C | Small alloc total bytes |
| +0x20  | 0x0099C498 | Large alloc count (>0x80 bytes) |
| +0x24  | 0x0099C49C | Large alloc total bytes |
| +0x28  | 0x0099C4A0 | Current memory usage (large blocks) |
| +0x2C  | 0x0099C4A4 | Peak memory usage |
| +0x30  | 0x0099C4A8 | Last warning threshold |
| +0x34  | 0x0099C4AC | Warning limit (0=disabled) |

### Key Functions
- `FUN_00717840(size)` = **pymalloc** - small block (<= 0x80) or CRT malloc (> 0x80)
- `FUN_00717960(ptr)` = **pyfree** - return to pool or CRT free
- `FUN_007179c0(ptr, newsize)` = **pyrealloc** - resize with pool awareness
- `FUN_00717b20(size)` = pool bucket lookup (binary search by size)
- `FUN_00717b70(size)` = pool bucket lookup-or-create
- `FUN_00718180(this, block)` = return block to free list (thiscall, ECX = pool bucket)
- `FUN_00718d60(size)` = cdecl wrapper for pymalloc
- `FUN_00718da0(ptr, size)` = cdecl wrapper for pyrealloc
- `FUN_00717ed0()` = memory warning callback (currently empty/NOP)

### Small Block Pool Design
- Blocks <= 0x80 (128) bytes use pool allocator
- Blocks > 0x80 bytes use CRT malloc directly
- Pool buckets are 0x24 (36) bytes, stored in sorted array at DAT_0099c484
- Each bucket has a free list at offset +0x1C
- Binary search by allocation size for O(log n) lookup

### Thread Safety: **NONE**
All allocator globals are read-modify-written without any synchronization:
- No CriticalSection, no Interlocked*, no mutex
- `DAT_0099c498 = DAT_0099c498 + 1` etc. are non-atomic
- Free list manipulation (`FUN_00718180`) is linked-list pointer swap, not atomic
- This is by design -- Python 1.5.2 with GIL assumes single-threaded C API access

## Crash Analysis
Crash at 0x007179FB (`MOV EDI, [EBX-4]`) in pyrealloc:
- EBX holds a buffer pointer, code reads the size header at [ptr-4]
- If another thread freed or reallocated that buffer, [ptr-4] contains garbage
- Fault address 0x003F003B = EBX was 0x003F003F, so [0x003F003F-4] = [0x003F003B]
- 0x003F003F looks like corrupted data (two 0x3F = '?' characters), not a valid heap pointer

Crash at 0x0071796B (`MOV EAX, [EAX-4]`) in pyfree:
- Same pattern: reading size header from a corrupted/freed pointer
- EAX=0x00000121, so fault at [0x00000121-4] = [0x0000011D] (near-NULL)
- This is a use-after-free: the pointer was already freed by the other thread
