# Win32 Crash Analyst - Agent Memory

## Analyzed Crash Sites
- See [crash-sites.md](crash-sites.md) for detailed per-address analysis

## Key Structural Knowledge
- See [structures.md](structures.md) for decoded object layouts

## VEH Handler State
- Current handler: `CrashHandler` in `src/proxy/ddraw_main.c` line ~1602
- Write handler: faultAddr < 0x10000, redirects NULL base registers to g_pNullDummy
- Read handler: targeted EIP skips first, then generic NULL register redirect
- **CRITICAL**: Write handler only checks faultAddr < 0x10000 (NULL page). Crashes writing to .rdata (0x00888000-0x008BAFFF) are NOT caught.
- **NEW PATTERN NEEDED**: Targeted (eip, faultAddr) checks for .rdata writes, placed BEFORE NULL page guard
  - 0x006CF1DC writing 0x00895C58: EIP skip to 0x006CF1E2 (skip dead marker, proceed to RET)

## Function Name Corrections
- FUN_006cefe0 = TGNetworkStreamWriter ctor (NOT "Reader" as previously labeled in some notes)
- FUN_006a1b10 = ChecksumCompleteHandler / SendSettingsToPlayer
- FUN_006cf1c0 = TGNetworkStreamWriter::Cleanup (reset for reuse OR write dead marker)
- FUN_006cf180 = TGNetworkStreamWriter::Init (attach buffer)
- FUN_006cf9b0 = TGNetworkStreamWriter::GetBytesWritten (returns this+0x24)

## Memory Map (stbc.exe)
- .text: 0x00401000 - 0x00887FFF (code)
- .rdata: 0x00888000 - 0x008BAFFF (read-only data, vtables, strings)
- .data: 0x008BB000 - 0x009B5357 (read-write globals)
- Stack: ~0x001A0000 range (seen 0x001AF490)
- Heap: 0x04000000+ range (seen 0x046064BC in EBP)

## VEH Sustainability Analysis (2026-02-09)
- See [veh-sustainability-analysis.md](veh-sustainability-analysis.md)
- **Verdict**: Mid-function VEH recovery is fundamentally unsound for object construction
- VEH produces "zombie objects" that pass NULL checks but have invalid data
- 100/sec crash rate is symptom of cascade: partial init -> downstream crash -> more partial init
- Recommended alternative: system-memory render backend or function-level replacement

## AsteroidField Constructor
- FUN_004196d0 (range 0x004196d0-0x00419a2f) - gap in Ghidra's function DB
- Sets vtable to 0x00888b84, creates proximity manager, collision sets
- 0x00419963 crash is mid-constructor; VEH recovery = partially constructed object
- Destructor: FUN_00419a30 (calls FUN_00419a60)

## GetBoundingBox (FUN_004360c0)
- Calls vtable+0xe4 (GetWorldBound) then reads NiBound from return value
- If object has no scene graph data, vtable call returns 0, FLD [0x0C] crashes
- Even with VEH redirect, result is zero-size bounding box (functionally broken)
- Referenced by 20+ vtable entries in .rdata - shared across many object types

## VEH Cascade Pattern (2026-02-10)
- See [veh-cascade-analysis.md](veh-cascade-analysis.md) for full writeup
- **Pattern**: FlatBufferStream skip -> RET to 0x0 -> blind stack scan -> 2nd crash -> 3rd cascade
- **Root cause of cascade**: Bad-EIP recovery scans stack for HasCallBefore() addresses, jumps mid-function with wrong register context
- **Key insight**: ESI=0x21 at FUN_006e21d0 crash was stale register, not from game logic
- **EDX=0xC000000D** is NTSTATUS STATUS_INVALID_PARAMETER leaked from exception dispatch, not game code
- 0x0069F3E5 is inside MultiplayerGame::ReceiveMessageHandler (LAB_0069f2a0, gap in Ghidra DB)
- 0x006E2249 is mid-loop in FUN_006e21d0 (event handler dispatcher)
- **Conclusion**: Cannot safely add more VEH skips; need cascade depth limit or longjmp

## Event System Functions
- FUN_006e21d0 = event handler dispatcher (iterates registered handlers, calls FUN_006e0c30)
- FUN_006db620 = event dispatch lookup (calls FUN_006e21d0 at 0x006db660)
- FUN_006e0c30 = handler invocation (calls registered callback via function pointer)
- FUN_006e21d0 range: 0x006E21D0-0x006E230D, epilogue at 0x006E2308 (POP EDI/ESI/EBP/EBX/ECX; RET 4)
- this+0x0C = handler count, this+0x04 = handler array ptr, this+0x30 = recursion counter

## Ghidra Function DB Gaps (important for stack scan recovery)
- 0x0069F27C-0x0069F61F: MultiplayerGame::ReceiveMessageHandler (LAB_0069f2a0)
- 0x004196d0-0x00419a2f: AsteroidField constructor
- Jump table for ReceiveMessageHandler at 0x0069F534, first case at 0x0069F31E
