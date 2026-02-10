# Renderer Pipeline Trace: Full Ghidra Analysis (2026-02-09)

## Crash Context (historical, fixed by PatchDeviceCapsRawCopy)
- EIP=0x0, EAX=ECX=0x02F33A04, EBP=0x02F22ABC (renderer wrapper)
- Stack return candidate: 0x007C4879 (FUN_007c4850 = logging helper, NOT crash site)
- PatchRendererMethods ACTIVE, stubs: FUN_007e8780 (RET), FUN_007c2a10 (RET 4), FUN_007c16f0 (RET 0x18)
- PatchDeviceCapsRawCopy zeroes the REP MOVSD count at 0x007d2119 to prevent raw copy

## FUN_007c4850 (at 0x007C4879) = Logging Helper
- Just formats "NI_D3D_Renderer: <msg>" and outputs it
- 0x007C4879 is `ADD ESP,0x114; RET` (its epilogue)
- Called from dozens of places in pipeline code -- breadcrumb, not crash

## Execution Flow in FUN_007c3480 After FUN_007cb2c0

### Step 1: LAB_007c3a78 - Store GGM result
```asm
007c3a78: MOV [EBP + 0xc8], EAX    ; renderer->0xC8 = GGM ptr
007c3a88: MOV byte [EBP + 0x2a1],0  ; clear flag
```

### Step 2: Optional flag set (caps-dependent, may skip)

### Step 3: SetCameraData - PATCHED SAFE
```asm
007c3ad5: MOV EDX,[EBP]            ; vtable at 0x00898984
007c3b48: CALL [EDX + 0xa4]        ; vtable[41] = 0x007C16F0 -> RET 0x18
```
Confirmed: 0x00898984 + 0xa4 = 0x00898A28 -> 0x007C16F0 (patched)

### Step 4: Call FUN_007d4950 (Texture Caps Manager)
```asm
007c3b5d: MOV EAX,[EDX]            ; *(adapter_wrapper) = adapter_info
007c3b64: MOV EDX,[EAX + 0x194]    ; display bit depth
007c3b6a: MOV EAX,[EAX + 0xc]      ; DDraw7* (our ProxyDDraw7)
007c3b82: CALL 0x007d4950
007c3b8a: MOV [EBP + 0xc4],EAX     ; renderer->0xC4
```

### Step 5: Call FUN_007d2230 (Depth/Stencil Manager) - CORRUPTION SOURCE
```asm
007c3bba: CALL 0x007d2230
007c3bc2: MOV [EBP + 0xb8],EAX     ; renderer->0xB8
```
- Internally calls FUN_007d1ff0 which copies 59 DWORDs from Device7
- Copied data has our vtable ptr where NI expects D3DCAPS7 structure

### Step 6: Call FUN_007ccd10 (Render State Manager) - CRASH SITE
```asm
007c3be1: CALL 0x007ccd10
007c3be9: MOV [EBP + 0xbc],EAX     ; renderer->0xBC
```
- Uses corrupted caps data from step 5
- Calls FUN_007cb2c0 with extracted pointers -> AddRef on bad data -> EIP=0

## FUN_007cb2c0 Calling Convention (CORRECTED)
- `__thiscall` with ECX=this, `RET 0xC` (3 stack params)
- Ghidra decompiler shows 1 param (WRONG) - it's actually 3:
  - Param1 (first pushed): IDirect3D7* (or DDraw7*)
  - Param2: IDirect3DDevice7*
  - Param3: BOOL bUseTnL
- Both COM params get AddRef via vtable[1]
- Both work fine with our proxy objects in the initial call from FUN_007c3480
- CRASH is when FUN_007ccd10 calls it with corrupted pointers

## Adapter Info Object (FUN_007c7f80)
- Size: 0x1A4 (420 bytes)
- +0x0C: IDirectDraw7* (our ProxyDDraw7, from DirectDrawCreateEx)
- +0x194: display bit depth
- Created via `DirectDrawCreateEx` which calls our proxy
- `adapter_wrapper[0]` = adapter_info pointer (set by FUN_007c9e50)

## Renderer->0x14 (IDirect3D7*)
- Set by FUN_007c09c0: `DD7_QueryInterface(IID_IDirect3D7, &renderer[5])`
- Our ProxyD3D7 created by DD7_QueryInterface

## Renderer->0x18 (IDirect3DDevice7*)
- Set by FUN_007c3480 via `D3D7::CreateDevice` (vtable offset 0x10)
- Our ProxyDevice7 created by D3D7_CreateDevice

## Root Cause (FIXED)
FUN_007d1ff0 copies 59 DWORDs (236 bytes) from Device7 as raw memcpy (REP MOVSD).
Our ProxyDevice7 has vtable ptr at offset 0 which NI misinterprets as caps data.

## Fix Applied
PatchDeviceCapsRawCopy zeroes the MOV ECX count at 0x007d2119, preventing the
raw copy entirely. NI gets zeroed caps data which means "no features supported"
— safe for headless operation.
