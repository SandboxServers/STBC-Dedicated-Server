# EBP Corruption Crash (0x0CCA8281) - SOLVED 2026-02-15

## Symptom
- VEH crash at EIP=0x0CCA8281 (WSN data at WSN+0x31, NOT code)
- Fires immediately after RunPyCode calls InitNetwork(2) at tick 325
- Repeats every tick; eventually fatal crash at EIP=0x006B569C

## Root Cause
- mingw GCC at -O2 uses EBP as general-purpose register (frame pointer omission)
- GCC caches IsBadReadPtr function pointer in EBP throughout GameLoopTimerProc
- PY_RunString -> Python -> SWIG -> stbc.exe C++ code corrupts EBP to 0
- Subsequent `call *%ebp` (IsBadReadPtr) jumps to address 0

## Evidence Chain
1. Proxy log: InitNetwork(2) at 48.161s, VEH[2] at 48.162s (same tick, 1ms later)
2. Stack has return address 0x58E18E21 = DLL RVA 0x8E21
3. Disasm at RVA 0x8E1F: `FF D5` (call *%ebp) with args matching IsBadReadPtr(0x009A09D0, 4)
4. IAT entry at RVA 0x2B278 = __imp__IsBadReadPtr@8
5. EBP loaded from IAT at 0x66CC81F0, but was 0 at crash time

## Fix (two layers)
1. **-fno-omit-frame-pointer** in Makefile CFLAGS: prevents GCC from using EBP as GPR
2. **RunPyString_Safe noinline wrapper**: isolates PY_RunString call in its own frame,
   so any callee-saved register corruption is contained by the wrapper's epilogue

## DLL Base Address
- PE preferred base: 0x66CC0000
- Runtime base was 0x58E10000 (but varies with ASLR)
- .text at RVA 0x1000 (size 0x165B4), .idata at RVA 0x2B000

## Key Lesson
When cross-calling into foreign DLL code (stbc.exe Python/SWIG chain), callee-saved
register preservation cannot be assumed. The noinline wrapper pattern creates a
compiler-managed isolation boundary that is safe and portable.
