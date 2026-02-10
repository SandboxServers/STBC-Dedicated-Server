# Architecture Assessment: Headless Dedicated Server Approaches

## Assessment Date: 2026-02-09
## Assessed by: x86 Patch Engineer

See MEMORY.md for summary. This file contains the full reasoning.

## Current State Summary
- 18 active patches, VEH with 5 targeted skips + generic NULL redirect
- VEH fires ~100/sec (vehR + vehW counters)
- Client connects, passes checksums, reaches ship select, disconnects ~3s later
- Root cause: game objects lack visual data (bounding volumes, scene graph nodes)
  because renderer is a hollow shell

## Approach Ratings

### 1. VEH (current) - FUNDAMENTALLY FLAWED for high-frequency crashes
Feasibility: 7, Effort: 3 (already done), Stability: 2

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
