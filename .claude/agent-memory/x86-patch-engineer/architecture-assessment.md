# Architecture Assessment: Headless Dedicated Server Approaches

## Assessment Date: 2026-02-09 (updated 2026-02-10)
## Assessed by: x86 Patch Engineer

See MEMORY.md for summary. This file contains the full reasoning.

## Current State Summary
- 14 active binary patches applied at runtime
- CrashDumpHandler (SetUnhandledExceptionFilter) for unhandled exceptions
- Client connects, passes checksums, reaches ship select, disconnects ~3s later
- Root cause: NIF ship models don't load fully without GPU texture backing,
  so subsystem lists at ship+0x284 are NULL -> empty StateUpdate packets

## Approach Ratings

### 1. Targeted Binary Patches (current) - SOLID FOUNDATION
Feasibility: 9, Effort: 5, Stability: 8
Each crash site gets a specific fix (code cave, NOP, or JMP). No generic
exception recovery. Clean failure via CrashDumpHandler if something new hits.

### 2. NOP-sled top-level functions
Feasibility: 6, Effort: 6, Stability: 5

### 3. Static binary patch (stbc_dedicated.exe)
Feasibility: 8, Effort: 4, Stability: 6

### 4. Import table hooking
Feasibility: 7, Effort: 3, Stability: 4

### 5. Function-level stubbing (entry-point RET)
Feasibility: 8, Effort: 5, Stability: 7

### 6. "Let it render to nothing" (system memory DDraw)
Feasibility: 9, Effort: 6, Stability: 9

### 7. Extract game logic DLLs
Feasibility: 2, Effort: 10, Stability: 3

### 8. Memory-mapped pre-patch loader
Feasibility: 7, Effort: 5, Stability: 7

### 9. Minimal patches with real system-memory rendering
Feasibility: 9, Effort: 5, Stability: 9
