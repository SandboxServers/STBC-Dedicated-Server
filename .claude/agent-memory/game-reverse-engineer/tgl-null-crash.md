# TGL NULL Pointer Crash Analysis (0x1C Bad Pointer)

## Summary
During Phase 2 boot (CreateMultiplayerGame), TGL data files fail to load in headless
mode because the rendering/UI subsystem is stubbed. FUN_006d1e10 (TGLFile::FindEntry)
has a design pattern where it returns `this + 0x1c` as the "default entry" when a named
entry isn't found. When the TGL file object itself is NULL (load failure), this returns
`0 + 0x1c = 0x1c`, which is non-zero and passes all downstream NULL checks, causing
cascading access violations.

## Root Cause Chain
1. FUN_006d03d0 calls FUN_006d11d0 to load "data/TGL/Multiplayer.tgl"
2. FUN_006d11d0 calls FUN_006d17e0 which calls fopen() on the TGL file
3. If file load/parse fails, FUN_006d11d0 returns NULL
4. FUN_006d1e10 is called with this=NULL, param="Connection_Completed"
5. Binary search (FUN_006d1ea0) is called on NULL this, returns 0xFFFFFFFF
6. Fallback: `return (int)this + 0x1c = 0 + 0x1c = 0x1c`
7. Value 0x1c propagated to FUN_00731d20, FUN_006f4d90, FUN_006f4ee0

## FUN_006d1e10 Disassembly (Critical Function)
```
006d1e10: MOV EAX,[ESP+4]      ; param_1 (entry name)
006d1e14: PUSH ESI
006d1e15: TEST EAX,EAX         ; NULL name check
006d1e17: MOV ESI,ECX          ; ESI = this (TGL object)
006d1e19: JNZ 0x006d1e22
006d1e1b: LEA EAX,[ESI+0x1c]   ; DEFAULT: return this+0x1c  <-- BUG when this=NULL
006d1e1e: POP ESI
006d1e1f: RET 0x4
006d1e22: PUSH EAX
006d1e23: MOV ECX,ESI
006d1e25: CALL 0x006d1ea0       ; Binary search for name
006d1e2a: CMP EAX,-0x1
006d1e2d: JNZ 0x006d1e36
006d1e2f: LEA EAX,[ESI+0x1c]   ; NOT FOUND: return this+0x1c  <-- BUG when this=NULL
006d1e32: POP ESI
006d1e33: RET 0x4
006d1e36: MOV ECX,[ESI+0x14]   ; FOUND: return entries[idx]
006d1e39: LEA EAX,[EAX+EAX*2]
006d1e3c: POP ESI
006d1e3d: LEA EAX,[ECX+EAX*8+4]
006d1e41: RET 0x4
```

## Crash Sites (all caused by 0x1C from above)
| Address | Instruction | Register | What |
|---------|------------|----------|------|
| 0x006F4DA1 | MOV ECX,[EBP+8] | EBP=0x1C | NiString::Assign reads src length |
| 0x00731D43 | MOV EAX,[EDI+8] | EDI=0x1C | NiTexture::Init reads entry data |
| 0x00718184 | (cascade) | ECX=0 | NiAlloc with bad size from above |
| 0x0043BB9A | (cascade) | ESI=-1 | Further corruption |

## Fix: Code Cave at FUN_006d1e10
Patch entry point to add `TEST ECX,ECX / JZ return_null` before original code.
All downstream callers already have NULL checks that will handle a proper NULL return.

## Affected Call Sites (all use same LoadTGL -> FindEntry pattern)
- FUN_00504f10: "data/TGL/Multiplayer.tgl" -> "Connection_Completed"
- FUN_004fe560: "data/TGL/Options.tgl" -> "Sensor_Interference"
- FUN_0050d550: "data/tgl/Options.tgl" -> "Bad_Connection"
- FUN_00502550: passes TGL entry to NiTexture constructor
- FUN_00507f80: passes param to NiTexture constructor
- Plus ~15 more callers through FUN_00731bb0/FUN_00731c50

## TGL Object Structure (inferred, 0x2c bytes)
```
+0x00: byte flags
+0x04: ptr  unknown1
+0x08: ptr  unknown2
+0x0c: ???
+0x10: uint entryCount
+0x14: ptr  entryArray (each entry = 0x18 bytes)
+0x18: ???
+0x1c: DEFAULT ENTRY (TGL entry struct, used as fallback)
```
