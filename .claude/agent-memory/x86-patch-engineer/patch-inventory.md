# Patch Inventory

## Active Patches (applied in DllMain)
1. HookGameIAT - IAT hooks for game functions
2. InlineHookMessageBoxA - suppress dialog popups
3. HookAbort - redirect abort() at 0x0085A108
4. PatchNullSurface - code cave at 0x007CB322 for mipmap NULL surface
5. PatchRenderTick - 0x004433EA JNZ->JMP skip render work
6. PatchInitAbort - NOP JMP at 0x0043B1D2 (abort suppression)
7. PatchPyFatalError - make Py_FatalError return
8. PatchCreateAppModule - create SWIG "App" module pre-init
9. PatchNullGlobals - pre-fill NULL globals with dummy buffer
10. PatchSkipDeviceLost - 0x007C1346 JZ->JMP skip device-lost
11. PatchRendererMethods - stub 3 renderer vtable methods (RET/RET N)
12. PatchDeviceCapsRawCopy - zero MOV ECX count at 0x007d2119
13. PatchHeadlessCrashSites - RET at entry of 2 UI functions
14. PatchTGLFindEntry - code cave at 0x006D1E10 (NULL this check)
15. PatchNetworkUpdateNullLists - code cave at 0x005b1d57 (clear flags)
16. PatchSubsystemHashCheck - fix anti-cheat false positive
17. PatchCompressedVectorRead - vtable validation
18. PatchDebugConsoleToFile - redirect Python exceptions to log

## Removed Patches (commented out)
- PatchRendererCtorEntry - let real ctor run (was zeroing object)
- PatchSkipRendererSetup - let pipeline run (was skipping all setup)
- PatchChecksumAlwaysPass - flag=0 is correct for first player

## VEH Handler (CrashHandler)
- Software breakpoint handling (INT3 + single-step for function tracing)
- Bad EIP recovery (scan stack for return address)
- Phase 2 longjmp recovery
- NULL write redirect (Pass 1: direct, Pass 2: base+offset)
- NULL read redirect with targeted EIP skips:
  - 0x005b1edb -> 0x005b1f1f (subsystem list loop skip)
  - 0x005b1f82 -> 0x005b2105 (weapon list loop skip)
  - 0x006F4DA1 -> 0x006F4ED5 (wstring assign EBP skip)
  - 0x006F4EEC: EBX redirect (wstring assign TGL)
  - 0x00731D43: EDI redirect (TGAnimAction::Init TGL)
- Generic NULL register redirect (ECX/EAX/EDX/ESI/EDI/EBX -> dummy)
