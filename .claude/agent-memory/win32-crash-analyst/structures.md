# Decoded Object Structures

## TGNetworkStream (derived class, vtable 0x00895C58)
- NOTE: Same class used for both reading AND writing. Constructor FUN_006cefe0.
- Constructor: FUN_006cefe0 (calls base FUN_006d1fc0 first)
- Destructor: FUN_006cf120 (calls FUN_006cf1c0 then base FUN_006d2050)
- Cleanup/reset: FUN_006cf1c0 (also vtable entry at +0x04)
- Init (attach buffer): FUN_006cf180(this, buffer_ptr, buffer_capacity)
- Get written size: FUN_006cf9b0 (returns this+0x24)
- Size: 0x2D bytes (45 bytes, 12 DWORDs + 1 byte)

### Layout:
| Offset | Size | Field | Set By |
|--------|------|-------|--------|
| +0x00 | 4 | vtable ptr (0x00895C58 derived, 0x00895D60 base) | constructor |
| +0x04 | 4 | sub-object ptr (heap-allocated, 0x14 bytes via FUN_00718cb0) | FUN_006d1fc0 base ctor |
| +0x08 | 4 | FILE* (file handle) | base class |
| +0x0C | 4 | error/status code (zeroed by Init) | FUN_006cf180 |
| +0x10 | 4 | unknown (zeroed by base) | FUN_006d1fc0 |
| +0x14 | 4 | unknown (zeroed by base) | FUN_006d1fc0 |
| +0x18 | 4 | unknown (zeroed by base) | FUN_006d1fc0 |
| +0x1C | 4 | buffer ptr (non-zero = buffer attached) | FUN_006cf180 / zeroed by cleanup |
| +0x20 | 4 | buffer capacity | FUN_006cf180 / zeroed by cleanup |
| +0x24 | 4 | bytes written (current position) | FUN_006cf180 / zeroed by cleanup |
| +0x28 | 4 | unknown | zeroed by cleanup |
| +0x2C | 1 | flag byte | zeroed by cleanup |

### Vtable at 0x00895C58:
| Offset | Target | Function |
|--------|--------|----------|
| +0x00 | 0x006CF170 | unknown method |
| +0x04 | 0x006CF1C0 | FUN_006cf1c0 (cleanup/reset) |

### Sub-object at +0x04 (0x14 bytes, allocated by FUN_00718cb0):
- Constructed by FUN_006d3220(ptr, 0)
- Dead marker: 0xFFFFFFFE written to [+0x00] by FUN_006cf1c0 when no buffer attached
- Layout: [+0x00] = initial value 0 (or 0xFFFFFFFE when dead), [+0x04] = 0

### FUN_006cf1c0 "cleanup" function logic:
- if (this+0x1C != 0): zero out fields +0x1C through +0x2C, return (NORMAL PATH)
- if (this+0x1C == 0): write 0xFFFFFFFE to *(this+0x04), return (DEAD MARKER PATH)
  - Crash when this+0x04 is vtable address (0x00895C58 in .rdata) instead of heap ptr
  - Safe to skip: dead marker is diagnostic, sub-object freed by destructor anyway

### FUN_006cf180 "Init" (attach buffer) logic:
- if (this+0x1C != 0): already has buffer, write 0xFFFFFFFD error to *(this+0x04), return
- else: set this+0x0C=0, *(this+0x04)=0, this+0x1C=buffer, this+0x20=size, +0x24/+0x28/+0x2C=0

### Reader functions (all __fastcall, ECX=this):
| Address | Name | Reads | Advances By |
|---------|------|-------|-------------|
| 0x006CF540 | ReadByte | *(this+0x1C)[pos] | 1 |
| 0x006CF580 | ReadBitBool | bit from *(this+0x1C)[base] | 0-1 (lazy byte load) |
| 0x006CF600 | ReadUint16 | *(uint16*)(this+0x1C)[pos] | 2 |
| 0x006CF670 | ReadDword | *(uint32*)(this+0x1C)[pos] | 4 |
| 0x006CF6B0 | ReadFloat | *(float*)(this+0x1C)[pos] | 4 |
| 0x006CF9B0 | GetPosition | returns this+0x24 | 0 |

### All reader functions have same vulnerability:
- Bounds check uses this+0x20 (size) vs this+0x24 (position)
- If bounds check passes, reads through this+0x1C (buffer ptr)
- If this+0x1C is NULL but this+0x20 is non-zero, crash occurs
- FUN_006b8530 can return NULL buffer with non-zero size

## TGNetworkStream base class (vtable 0x00895D60)
- Constructor: FUN_006d1fc0
- Destructor: FUN_006d2050 (calls FUN_006d20e0 to close file, then frees sub-object at +0x04)
