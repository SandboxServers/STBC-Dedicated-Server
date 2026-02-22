> [docs](../README.md) / [guides](README.md) / binary-patching-primer.md

# Binary Patching Primer

How we modify the running game executable to make it work headless.

## Why Binary Patches

Bridge Commander was compiled in 2002 and we don't have the source code. The executable assumes a GPU, a window, loaded textures, and a scene graph full of 3D models. In headless mode, many of these assumptions are wrong and cause crashes.

We fix this by changing specific bytes in the executable's code at runtime, before the problematic code runs. Since `stbc.exe` is a 32-bit Windows executable without ASLR, all code addresses are fixed — the same function is always at the same address.

## The Three Patch Types

### 1. NOP Patch (simplest)
Replace instructions with `0x90` (NOP — "no operation") to skip them.

**When to use**: A function call or instruction should simply not execute.

**Example**: `PatchInitAbort` replaces a JMP that calls `abort()` on init failure:
```
Before: E9 XX XX XX XX    JMP <abort_wrapper>   (5 bytes)
After:  90 90 90 90 90    NOP NOP NOP NOP NOP   (5 bytes)
```

In C:
```c
VirtualProtect((void*)0x0043B1D2, 5, PAGE_EXECUTE_READWRITE, &oldProt);
memset((void*)0x0043B1D2, 0x90, 5);  // NOP out the JMP
VirtualProtect((void*)0x0043B1D2, 5, oldProt, &oldProt);
```

### 2. JMP Patch (change control flow)
Change a conditional jump to unconditional (or vice versa) to force a different code path.

**When to use**: A branch condition goes the wrong way in headless mode.

**Example**: `PatchRenderTick` changes a conditional skip to unconditional:
```
Before: 0F 85 XX XX XX XX    JNZ <skip_render>    (6 bytes)
After:  E9 XX XX XX XX 90    JMP <skip_render>    (5 bytes + NOP)
```
The condition checked whether rendering was needed. In headless mode, we always skip.

The JMP displacement needs recalculation because `JNZ rel32` is 6 bytes but `JMP rel32` is 5:
```c
// JNZ rel32 at 0x004433EA: 0F 85 [4-byte offset]
// JMP rel32 at same address: E9 [4-byte offset] 90
// New offset = old_offset + 1 (because JMP is 1 byte shorter before the offset)
```

### 3. Code Cave (most powerful)
Allocate new executable memory, write custom x86 instructions into it, then redirect the original code to jump there. The cave runs our logic and jumps back.

**When to use**: We need to add a check, modify a register, or run conditional logic that doesn't exist in the original code.

**Example**: `PatchTGLFindEntry` adds a NULL check to a function that assumed `this` was always valid.

Original function at `0x006D1E10`:
```asm
MOV EAX, [ESP+4]    ; load first parameter
PUSH ESI             ; save register
TEST EAX, EAX       ; continue at 0x006D1E15...
```

Our code cave:
```asm
TEST ECX, ECX        ; is 'this' NULL?
JNZ  .original       ; if not, proceed normally
XOR  EAX, EAX        ; return NULL
RET  4               ; clean up stack (stdcall)
.original:
MOV  EAX, [ESP+4]    ; original first instruction
PUSH ESI             ; original second instruction
JMP  0x006D1E15      ; jump back to original code (after what we copied)
```

## Anatomy of a Code Cave Patch

Every code cave patch in `ddraw_main.c` follows this structure:

```c
static void PatchSomething(void) {
    // 1. Define the cave bytes (x86 machine code)
    static BYTE cave[] = {
        0x85, 0xC9,                     // TEST ECX, ECX
        0x75, 0x05,                     // JNZ +5
        0x33, 0xC0,                     // XOR EAX, EAX
        0xC2, 0x04, 0x00,              // RET 4
        // .original:
        0x8B, 0x44, 0x24, 0x04,        // MOV EAX, [ESP+4]
        0x56,                           // PUSH ESI
        0xE9, 0x00, 0x00, 0x00, 0x00   // JMP <fixup needed>
    };

    // 2. Allocate executable memory
    BYTE* pCave = VirtualAlloc(NULL, sizeof(cave),
                               MEM_COMMIT | MEM_RESERVE,
                               PAGE_EXECUTE_READWRITE);

    // 3. Copy cave bytes into allocated memory
    memcpy(pCave, cave, sizeof(cave));

    // 4. Fix up the JMP back to original code
    //    offset = target - (address_after_JMP_instruction)
    DWORD jmpFrom = (DWORD)(pCave + 19);  // byte after the JMP
    DWORD jmpTo   = 0x006D1E15;           // where in original code to return
    *(DWORD*)(pCave + 15) = jmpTo - jmpFrom;

    // 5. Redirect original function entry to our cave
    DWORD oldProt;
    VirtualProtect((void*)0x006D1E10, 5, PAGE_EXECUTE_READWRITE, &oldProt);
    *(BYTE*)0x006D1E10 = 0xE9;  // JMP rel32
    *(DWORD*)0x006D1E11 = (DWORD)pCave - (0x006D1E10 + 5);
    VirtualProtect((void*)0x006D1E10, 5, oldProt, &oldProt);
}
```

### Key Concepts

**VirtualProtect**: Game code is in read-only/execute memory. We must change the protection to writable before modifying it, then restore it.

**JMP rel32 encoding**: The x86 `JMP` instruction (`0xE9`) takes a 4-byte signed offset. The offset is relative to the address of the **next** instruction (address after the JMP):
```
offset = target_address - (jmp_address + 5)
```

**Copied instructions**: The cave must include copies of any original instructions that were overwritten by the redirect JMP (since those bytes are now `E9 XX XX XX XX`). The cave then jumps back to the instruction *after* the overwritten ones.

**The 5-byte rule**: A `JMP rel32` is exactly 5 bytes (`E9` + 4-byte offset). You must overwrite at least 5 bytes at the patch site. If the original instructions don't align to exactly 5 bytes, pad with NOPs.

## x86 Quick Reference

Common instructions you'll see in patch code:

| Bytes | Instruction | Meaning |
|-------|------------|---------|
| `90` | NOP | Do nothing |
| `C3` | RET | Return from function |
| `C2 XX XX` | RET imm16 | Return and pop N bytes (stdcall cleanup) |
| `E9 XX XX XX XX` | JMP rel32 | Unconditional jump (relative) |
| `E8 XX XX XX XX` | CALL rel32 | Function call (relative) |
| `0F 85 XX XX XX XX` | JNZ rel32 | Jump if not zero (conditional) |
| `0F 84 XX XX XX XX` | JZ rel32 | Jump if zero (conditional) |
| `EB XX` | JMP rel8 | Short jump (1-byte offset) |
| `75 XX` | JNZ rel8 | Short conditional jump |
| `85 C9` | TEST ECX, ECX | Set flags based on ECX (zero check) |
| `85 C0` | TEST EAX, EAX | Set flags based on EAX (zero check) |
| `33 C0` | XOR EAX, EAX | Set EAX to 0 |
| `8B 44 24 XX` | MOV EAX, [ESP+XX] | Load stack argument |

## Calling Conventions

BC uses two main conventions:

**`__thiscall`** (most C++ methods): `this` pointer in ECX, other arguments on stack right-to-left. Callee cleans stack.

**`__cdecl`** (C functions, some engine functions): All arguments on stack right-to-left. Caller cleans stack.

When writing a code cave, you must preserve the convention. If the original function is `__thiscall`, ECX holds `this` when your cave executes.

## Reading Patch Functions

When you encounter a patch function in `ddraw_main.c`:

1. **Read the comment block** — it explains what the original code does and why we're patching it
2. **Look at the `cave[]` array** — this is the machine code that will execute. Decode it instruction by instruction.
3. **Find the fixup** — the `jmpFrom`/`jmpTo` calculation shows where the cave returns to
4. **Find the redirect** — the `*(BYTE*)0xXXXXXX = 0xE9` line shows what original code address is being patched

## Common Patterns

**NULL guard**: Check if a pointer (usually in ECX or EAX) is NULL, return a safe value if so, otherwise fall through to original code. Used when a function is called with NULL `this` that was valid in the normal game.

**Flag clearing**: Modify a flags byte or register to remove bits that would cause invalid data to be sent. Used when a feature depends on data structures that don't exist headlessly.

**Skip block**: Jump over a block of code that crashes or is unnecessary. Used for renderer-dependent operations.

## Active Patches Reference

See [dedicated-server.md](../architecture/dedicated-server.md) for the full table of 14+ active patches with addresses and effects.
