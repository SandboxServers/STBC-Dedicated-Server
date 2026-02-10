# x86 Patch Engineer Memory

## Current Patch Inventory (ddraw_main.c, ~4788 lines)
See [patch-inventory.md](patch-inventory.md) for details.

## Architecture Assessment
See [architecture-assessment.md](architecture-assessment.md) for the full approach comparison.

## Key Findings
- 15+ distinct patches applied at runtime via VirtualProtect + memcpy
- VEH handler has generic NULL-redirect (read+write) plus targeted EIP skips
- VEH fires ~100/sec based on vehR/vehW counters in tick_trace.log
- Proxy DDraw7/D3D7/Device7/Surface7 stubs exist with full COM vtables
- NiDX7Renderer ctor at 0x007E7AF0 is patched to zero-init + set vtable + RET
- PatchSkipRendererSetup at 0x007C39CF jumps over pipeline construction
- The renderer object exists but is a hollow shell (zeroed fields, real vtable)
- Game objects (ships, asteroids) lack bounding volumes because scene graph skips rendering
- Root problem: NetImmerse scene graph traversal produces visual data; without it, object state is incomplete

## Verified Addresses
- 0x007E7AF0: NiDX7Renderer ctor (PUSH -1, PUSH SEH) - patched to zero+RET
- 0x007C39CF: Pipeline setup entry (PUSH 0x976b98) - patched to JMP skip
- 0x007C1346: Device lost check (JZ +0x49) - patched to JMP
- 0x006D1E10: TGL::FindEntry (MOV EAX,[ESP+4]) - redirected to cave
- 0x005b1d57: Network update flags (MOV ECX,[ESP+0x14]) - redirected to cave
- 0x0043ADB6: Renderer alloc check (JZ +0x0B) - patched to JMP (skip ctor)
- 0x004433EA: Render tick (JNZ +0x4A) - patched to JMP (skip render)
