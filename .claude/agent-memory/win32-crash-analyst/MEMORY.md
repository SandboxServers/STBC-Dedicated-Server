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

## STATUS_INVALID_HANDLE (0xC0000008) Pattern
- Raised by ntdll during NtClose when FILE*/HANDLE is invalid (not just NULL)
- FUN_006d20e0 calls fclose(this+0x08) without validating FILE* is actually valid
- TGNetworkStream base class inherits FILE* field at +0x08 from NiStream base -- always NULL for network streams, but can be corrupted
- SEH cascade path: STATUS_INVALID_HANDLE -> unhandled -> SEH chain walk -> 0xFFFFFFFF sentinel -> AV -> nested exception -> stack overflow
- The RET patch at 0x006CF1DC (dead marker skip) does NOT cause this -- it only affects *(this+0x04), not this+0x08
- CRT addresses: FUN_0085a047 = fclose, FUN_0085a0f5 = fopen, FUN_0085ba65 = ftell-like

## Function Name Corrections
- FUN_006cefe0 = TGNetworkStream ctor (same class for read AND write)
- FUN_006a1b10 = ChecksumCompleteHandler / SendSettingsToPlayer
- FUN_006cf1c0 = TGNetworkStream::Cleanup (reset for reuse OR write dead marker)
- FUN_006cf180 = TGNetworkStream::Init (attach buffer)
- FUN_006cf9b0 = TGNetworkStream::GetPosition (returns this+0x24)
- FUN_006cf600 = TGNetworkStream::ReadUint16 (__fastcall, crash site 0x006CF628)
- FUN_006cf540 = TGNetworkStream::ReadByte
- FUN_006cf580 = TGNetworkStream::ReadBitBool
- FUN_006cf670 = TGNetworkStream::ReadDword
- FUN_006cf6b0 = TGNetworkStream::ReadFloat
- FUN_006b8530 = GetBufferData (returns buffer ptr + optional size out-param)
- FUN_006cf120 = TGNetworkStream::Destructor (derived, calls Cleanup then base dtor)
- FUN_006d1fc0 = NiStream base ctor (allocates sub-object, zeros FILE* at +0x08)
- FUN_006d2050 = NiStream base dtor (closes FILE*, frees sub-object)
- FUN_006d20e0 = NiStream::CloseFile (fclose this+0x08 if non-NULL)
- FUN_006d2080 = NiStream::OpenFile (fopen, stores FILE* at this+0x08)
- FUN_0085a047 = CRT fclose
- FUN_0085a0f5 = CRT fopen

## Stream Reader NULL Buffer Pattern
- All stream reader functions check size bounds but NOT buffer ptr NULL
- FUN_006b8530 can return NULL buffer with non-zero size
- Code cave fix needed at individual reader functions (or at Init site)

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

## Critical Lesson: Hybrid Mode != Full UI
- "Real renderer provides valid UI objects" is FALSE for dedicated servers
- Dedicated server skips menu flow that creates UI panes regardless of renderer mode
- FUN_0050e1b0(DAT_009878cc, N) returns NULL for pane types not created during boot
- PatchHeadlessCrashSites MUST be enabled for ALL dedicated server modes (headless AND hybrid)
- FUN_0055c890 was NEVER patched in any mode (missing from original patch list)

## UI Pane Lookup (FUN_0050e1b0)
- Iterates linked list at this+0x34, matches element+0x4C == type
- Type 4: general UI, Type 5: subtitle/notification, Type 8: MP chat
- DAT_009878cc = pane manager. Type 5 never created in dedi-server mode.
- FUN_00507f80 = AddSubtitleFromText, FUN_00508000 = AddSubtitleByHandle, FUN_00508120 = RemoveSubtitle

## Ghidra Function DB Gaps (important for disassembly)
- 0x0069F27C-0x0069F61F: MultiplayerGame::ReceiveMessageHandler (LAB_0069f2a0)
- 0x004196d0-0x00419a2f: AsteroidField constructor
- Jump table for ReceiveMessageHandler at 0x0069F534, first case at 0x0069F31E
