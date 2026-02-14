# x86 Patch Engineer Memory

## Current Patch Inventory (ddraw_main.c, ~3800 lines)
See [patch-inventory.md](patch-inventory.md) for details.

## Architecture Assessment
See [architecture-assessment.md](architecture-assessment.md) for the full approach comparison.

## Key Findings
- 15 active binary patches applied at runtime via VirtualProtect + memcpy
- CrashDumpHandler via SetUnhandledExceptionFilter logs diagnostics on unhandled exceptions
- Proxy DDraw7/D3D7/Device7/Surface7 stubs exist with full COM vtables
- Renderer pipeline runs fully (PatchSkipRendererSetup removed, pipeline objects build)
- PatchDeviceCapsRawCopy zeros the 236-byte raw copy count in FUN_007d1ff0
- Scene graph construction works but NIF models still don't load (no GPU texture backing)
- Root issue: ship subsystem lists at +0x284 NULL because NIF models need GPU for full loading

## Verified Addresses
- 0x007C1346: Device lost check (JZ +0x49) - patched to JMP
- 0x006D1E10: TGL::FindEntry (MOV EAX,[ESP+4]) - redirected to cave
- 0x005b1d57: Network update flags (MOV ECX,[ESP+0x14]) - redirected to cave
- 0x005b22b5: Subsystem hash check - redirected to cave
- 0x006d2eb0/0x006d2fd0: Compressed vector read - vtable validation caves
- 0x004433EA: Render tick (JNZ -> JMP skip render)
- 0x0043ADB6: Renderer alloc check (JZ -> JMP skip ctor)
- 0x0043B1D2: Init abort (NOP out JMP)
- 0x00419960: Vtable thunk (8 bytes, MOV ECX,[ECX+1C]/MOV EAX,[ECX]/JMP [EAX+34]) - full replacement cave

## Lessons Learned
- JZ/JNZ rel8 displacement = target_offset - (jz_offset + 2), NOT target_offset - (jz_offset + 1). The +2 accounts for the full 2-byte JZ instruction (opcode + displacement byte). Initial draft had off-by-one on both JZ branches.
- When a code cave reproduces ALL original instructions (full function replacement), no JMP-back fixup is needed. This simplifies the cave and eliminates a rel32 calculation.

## App-Wrap/State-Dump Signal (2026-02-12)
- Stock dump shows `g_kUtopiaModule` consistently as instance.
- Custom server dump shows mixed representation in same dump (`g_kUtopiaModule` as instance and as string pointer), suggesting namespace/global contamination from compat wrapping.
- Custom server call-path capture is minimal (3 calls), so instrumentation currently cannot reconstruct canonical startup chain; treat this as observability gap before low-level patch conclusions.

## Instrumentation Caveat from New Dumps (2026-02-12)
- Stock stage progression shows high call-path variance (95 -> 528 -> 131) and meaningful transitions.
- Server repeated dumps are byte-for-byte shape-equivalent with constant 3-call path surface; use this as a signal that startup path is forced/static or wrapper tracing coverage is incomplete.
