# Win32 Crash Analyst - Agent Memory

## Analyzed Crash Sites
- See [crash-sites.md](crash-sites.md) for detailed per-address analysis

## Key Structural Knowledge
- See [structures.md](structures.md) for decoded object layouts

## Crash Handling
- **CrashDumpHandler** via `SetUnhandledExceptionFilter` in DllMain
- Logs full diagnostics to `crash_dump.log`: registers, EBP chain walk, stack hex dump, code bytes, memory at register targets
- Returns `EXCEPTION_CONTINUE_SEARCH` (process terminates after logging)
- All crash sites are fixed proactively with targeted binary patches (code caves, NOPs, JMPs)

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

## AsteroidField Constructor
- FUN_004196d0 (range 0x004196d0-0x00419a2f) - gap in Ghidra's function DB
- Sets vtable to 0x00888b84, creates proximity manager, collision sets
- 0x00419963 crash was mid-constructor in headless mode (NiAVObject base not fully initialized)
- Addressed by renderer pipeline restoration (scene graphs now build fully)

## GetBoundingBox (FUN_004360c0)
- Calls vtable+0xe4 (GetWorldBound) then reads NiBound from return value
- If object has no scene graph data, vtable call returns 0, FLD [0x0C] crashes
- Referenced by 20+ vtable entries in .rdata - shared across many object types
- Addressed by renderer pipeline restoration (NIF loading produces valid bounds)

## Event System Functions
- FUN_006e21d0 = event handler dispatcher (iterates registered handlers, calls FUN_006e0c30)
- FUN_006db620 = event dispatch lookup (calls FUN_006e21d0 at 0x006db660)
- FUN_006e0c30 = handler invocation (calls registered callback via function pointer)
- FUN_006e21d0 range: 0x006E21D0-0x006E230D, epilogue at 0x006E2308 (POP EDI/ESI/EBP/EBX/ECX; RET 4)
- this+0x0C = handler count, this+0x04 = handler array ptr, this+0x30 = recursion counter

## Ghidra Function DB Gaps (important for disassembly)
- 0x0069F27C-0x0069F61F: MultiplayerGame::ReceiveMessageHandler (LAB_0069f2a0)
- 0x004196d0-0x00419a2f: AsteroidField constructor
- Jump table for ReceiveMessageHandler at 0x0069F534, first case at 0x0069F31E
