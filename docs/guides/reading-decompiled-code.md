> [docs](../README.md) / [guides](README.md) / reading-decompiled-code.md

# Reading Ghidra Decompiled Code

The `reference/decompiled/` directory contains 19 files of Ghidra C output from `stbc.exe`. This guide explains how to read it.

## File Organization

| File | Contents |
|------|----------|
| `01_core_engine.c` | Core engine, memory management, containers |
| `02_utopia_app.c` | UtopiaApp, game initialization, Python bridge |
| `03_game_objects.c` | Ships, weapons, systems, AI |
| `04_ui_windows.c` | UI panes, windows, menus |
| `05_game_mission.c` | Mission logic, scenarios |
| `09_multiplayer_game.c` | Multiplayer game logic, message handlers |
| `10_netfile_checksums.c` | Checksum exchange, file transfer |
| `11_tgnetwork.c` | TGWinsockNetwork, packet I/O |
| `12_data_serialization.c` | Data serialization, cipher |

These are organized thematically but the boundaries are approximate. A function might call across files.

## Function Naming

Ghidra names functions by their address:

```c
void __thiscall FUN_005b17f0(void *this, int param_1)
```

- `FUN_` prefix = Ghidra-generated name (no debug symbols)
- `005b17f0` = the function's address in `stbc.exe`
- `__thiscall` = calling convention (C++ method with `this` in ECX)

To find a function in the decompiled code, search for its address: `grep "005b17f0" reference/decompiled/*.c`

## Variable Naming

Ghidra generates variable names from their type and position:

| Pattern | Meaning |
|---------|---------|
| `iVar2` | Integer variable, 2nd in function |
| `uVar3` | Unsigned integer variable |
| `puVar4` | Pointer to unsigned, 4th variable |
| `pcVar1` | Pointer to char |
| `cVar1` | Char variable |
| `bVar1` | Byte (unsigned char) |
| `param_1` | First function parameter |
| `this` | The `this` pointer (for `__thiscall`) |
| `local_1c` | Local variable at stack offset 0x1C |
| `unaff_ESI` | Unaffected ESI (register preserved across calls) |

## Reading `this` Pointer Offsets

Most engine objects are accessed through `this` with hard-coded offsets:

```c
*(int *)((int)this + 0x284)
```

This reads a 4-byte integer at offset `0x284` from the object's base address. When you see this pattern:
- The object type is whatever `this` points to
- `0x284` is a struct field offset (we may or may not know its name)
- Cross-reference with known offsets in [dedicated-server.md](../architecture/dedicated-server.md)

Common example: `this + 0x78` on UtopiaModule is the TGWinsockNetwork pointer.

## Reading Vtable Calls

Virtual method calls appear as double-dereference patterns:

```c
(**(code **)(*param_1 + 8))(param_1, 0x8137);
```

Breaking this down:
1. `*param_1` — dereference the object to get its vtable pointer
2. `*param_1 + 8` — offset 8 into the vtable (3rd entry, since each is 4 bytes)
3. `*(code **)(...` — read the function pointer from the vtable
4. `(*...)(param_1, 0x8137)` — call it with `param_1` as `this` and `0x8137` as argument

In C++ terms, this is: `param_1->vtable[2](param_1, 0x8137)` or roughly `param_1->SomeVirtualMethod(0x8137)`.

To identify which function is being called, you need to know the vtable layout. Check the agent memory or [function-map.md](../engine/function-map.md) for known vtables.

## Reading Constants

### Float constants
Ghidra shows floats as hex integer literals:

| Hex | Float |
|-----|-------|
| `0x3f800000` | 1.0f |
| `0x447a0000` | 1000.0f |
| `0x3f000000` | 0.5f |
| `0x40000000` | 2.0f |
| `0x00000000` | 0.0f |

When you see `*(undefined4*)(this + 0x5c) = 0x3f800000;` that's storing `1.0f`.

### Pointer constants
```c
*(undefined ***)this = &PTR_FUN_008952fc;
```
This sets the vtable pointer. `PTR_FUN_008952fc` is a label in `.rdata` pointing to a vtable array. The address `0x008952fc` is the vtable's location.

### DAT_ globals
```c
DAT_0097fa88 = 0;
```
`DAT_` prefix means a global variable at that address. Cross-reference with the Key Globals table:

| Symbol | What |
|--------|------|
| `DAT_0097fa88` | IsClient flag |
| `DAT_0097fa89` | IsHost flag |
| `DAT_0097fa8a` | IsMultiplayer flag |
| `DAT_0097e238` | TopWindow pointer |
| `DAT_009a09d0` | Clock object pointer |

## Common Patterns

### Constructor
```c
undefined4 * __thiscall FUN_00690180(void *this, int param_1)
{
    FUN_0068a600(this, param_1);     // Call parent constructor
    *(undefined ***)this = &PTR_FUN_008952fc;  // Set vtable
    *(undefined4 *)((int)this + 0x5c) = 0x3f800000;  // Init field to 1.0f
    return (undefined4 *)this;       // Return this (common for ctors)
}
```

Tell-tale signs: calls a parent function first, sets vtable, initializes fields, returns `this`.

### Destructor
```c
void __thiscall FUN_006b9c50(void *this)
{
    // ... cleanup code ...
    FUN_006f3d30(this);  // Call parent destructor or free
}
```

Tell-tale signs: called through vtable slot 0, frees resources, calls a parent cleanup.

### NULL check + early return
```c
if (param_1 == (int *)0x0) {
    return (int *)0x0;
}
```

Ghidra writes NULL as `(int *)0x0` or `(void *)0x0`.

### Loop over linked list
```c
iVar2 = *(int *)((int)this + 0x284);  // head of list
while (iVar2 != 0) {
    // process node at iVar2
    iVar2 = *(int *)(iVar2 + 4);      // next pointer
}
```

### String comparison
```c
cVar1 = (**(code **)(*param_1 + 8))(0x8137);
```

The magic number `0x8137` is likely a hash or type ID. BC uses hash-based type checking (`IsKindOf` equivalent). These appear frequently in dynamic casts.

## Tips

1. **Start from known addresses** — if you know a function's address from a crash or patch, search for it directly
2. **Follow the call chain up** — use `grep` to find callers of a function (`grep "FUN_005b17f0" reference/decompiled/*.c`)
3. **Map constants to meaning** — keep the Key Globals table open while reading; `DAT_0097fa88` is much more meaningful as "IsClient"
4. **Trust the structure, not the variable names** — `iVar2` tells you nothing, but `*(int*)(this + 0x78)` tells you it's reading offset 0x78 from an object
5. **Cross-reference with runtime behavior** — when Ghidra's decompilation is ambiguous, check what the function actually does by looking at packet traces or log output at runtime
