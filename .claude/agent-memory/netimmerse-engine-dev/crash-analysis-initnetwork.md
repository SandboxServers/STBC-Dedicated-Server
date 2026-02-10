# Server Crash During InitNetwork - Root Cause Analysis

## Summary
**Root cause: Python GIL violation from concurrent PyRun_String on two threads.**

## The Two Threads
1. **Main thread** (via `GameLoopTimerProc` SetTimer callback):
   - ESP ~ 0x001AF70C (low stack, typical for main thread)
   - Calls `RunPyCode()` -> `PyRun_String()` to execute `InitNetwork(2)`
   - Fires at tick 267 (INITNET_DELAY_TICKS after player joined)

2. **HeartbeatThread** (created via `CreateThread` in DllMain):
   - ESP ~ 0x02D3FE1C (high stack, typical for spawned thread)
   - At 15 seconds (i==30): calls `PyRun_String()` for diagnostics
   - Also calls `PyImport_AddModule()`, `PyModule_GetDict()`

## Timing Coincidence
- 15-second STATE CHECK = HeartbeatThread at i==30 calls PyRun_String
- Tick 267 at 33ms/tick = ~8.8s after game loop started
- Bootstrap takes ~6-7s, so tick 267 is ~15s after DLL load
- BOTH threads hit PyRun_String at the exact same moment

## Crash Chain
1. HeartbeatThread enters Python parser (FUN_007839d0 -> FUN_0078b530)
2. Parser calls FUN_007840f0 (shift/push) which calls FUN_00718d60 (pymalloc)
3. **Simultaneously**, main thread's InitNetwork Python code triggers pymalloc/pyfree
4. Allocator at 0x0099C478 has NO thread safety (no locks, no atomics)
5. Concurrent read-modify-write corrupts free lists and size headers
6. Crash 1 (ESP=0x02D3FE1C, heartbeat thread): pyrealloc reads corrupted [ptr-4]
7. Crash 2 (ESP=0x001AF70C, main thread): pyfree reads freed/corrupted pointer

## Three Crash Sites Explained
- **0x00784182** (VEH caught): Parser shift/push writing to NULL EAX
  - FUN_007840f0 line `*puVar3 = param_2` where puVar3=NULL
  - pymalloc returned NULL due to corruption -> parser got NULL buffer -> write to NULL
  - VEH redirected EAX to dummy, allowing "recovery" but damage was done

- **0x007179FB**: pyrealloc `MOV EDI, [EBX-4]` reading size header
  - EBX=0x003F003F (corrupted pointer, 0x3F = '?' = garbage)
  - Fault address 0x003F003B (EBX-4)

- **0x0071796B**: pyfree `MOV EAX, [EAX-4]` reading size header
  - EAX=0x00000121 (very low address, use-after-free)
  - Fault address 0x0000011D (EAX-4)

## Fix
Remove ALL Python API calls from HeartbeatThread. The HeartbeatThread should only:
- Call EnumThreadWindows for dialog dismissal (Win32 API, safe)
- Read memory addresses for logging (read-only, safe enough)
- SetTimer on game window (posts WM_TIMER to main thread's queue, safe)

Move the 15-second diagnostic to a flag checked by GameLoopTimerProc on the main thread.
