# Patch Inventory

## Active Patches (applied in DllMain)
1. PatchRenderTick - 0x004433EA JNZ->JMP skip render work
2. PatchInitAbort - NOP JMP at 0x0043B1D2 (abort suppression)
3. PatchPyFatalError - make Py_FatalError return instead of abort
4. PatchSkipDeviceLost - 0x007C1346 JZ->JMP skip device-lost recreation
5. PatchRendererMethods - stub 3 renderer vtable methods (RET/RET N)
6. PatchDeviceCapsRawCopy - zero MOV ECX count at 0x007d2119
7. PatchHeadlessCrashSites - RET at entry of 2 UI functions
8. PatchTGLFindEntry - code cave at 0x006D1E10 (NULL this check)
9. PatchNetworkUpdateNullLists - code cave at 0x005b1d57 (clear SUB/WPN flags when lists NULL)
10. PatchSubsystemHashCheck - code cave at 0x005b22b5 (fix anti-cheat false positive)
11. PatchCompressedVectorRead - vtable validation at 0x006d2eb0/0x006d2fd0
12. PatchNullThunk_00419963 - code cave at 0x00419960 (NULL-check this+[this+0x1C] vtable thunk, AsteroidField tick)
13. PatchDebugConsoleToFile - redirect Python debug console output to log file
14. PatchDirectDrawCreateExCache - cache DirectDrawCreateEx result for engine reuse
15. SigAbrtHandler - SIGABRT signal handler (signal(), not binary patch)

## Removed Patches (no longer needed)
- PatchRendererCtorEntry - let real ctor run (was zeroing object)
- PatchSkipRendererSetup - let pipeline run (was skipping all setup)
- PatchChecksumAlwaysPass - flag=0 means "no mismatches" which is correct for first player
- PatchNullSurface - removed (no longer needed)
- HookAbort - removed (replaced by PatchInitAbort + SigAbrtHandler)
- PatchNullGlobals - split into PatchDirectDrawCreateExCache

## Crash Handling
- CrashDumpHandler registered via SetUnhandledExceptionFilter
- Logs full diagnostics to crash_dump.log (registers, stack walk, code bytes, memory)
- Returns EXCEPTION_CONTINUE_SEARCH (clean process termination)
