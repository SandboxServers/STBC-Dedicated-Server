# x86 Patch Engineer Memory

## Current Patch Inventory (ddraw_main.c, ~3800 lines)
See [patch-inventory.md](patch-inventory.md) for details.

## Architecture Assessment
See [architecture-assessment.md](architecture-assessment.md) for the full approach comparison.

## Key Findings
- 14 active binary patches applied at runtime via VirtualProtect + memcpy
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
