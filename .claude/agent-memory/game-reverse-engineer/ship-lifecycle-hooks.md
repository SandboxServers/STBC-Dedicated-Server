# Ship Lifecycle Functions for Hooking (2026-02-14)

## Summary
Analyzed ship damage/destruction/cleanup chain for function tracing hooks.
All prologue bytes verified from stbc.exe binary.

## Damage Chain Call Flow
```
Collision:       FUN_005b0060 (CollisionDamageWrapper) -> FUN_005afd70 + FUN_00593650
Weapon:          FUN_005af420 (WeaponDoDamage) -> FUN_00594020
Position-based:  FUN_00593650 (DoDamage_FromPosition) -> FUN_00594020
Contact-based:   FUN_005952d0 (DoDamage_CollisionContacts) -> FUN_00594020 (per contact point)

FUN_00594020 (DoDamage):
  -> Creates DamageEvent (FUN_004bbde0)
  -> Calls FUN_00593e50 (ProcessDamage)

FUN_00593e50 (ProcessDamage):
  -> Applies damage/resistance multipliers (FUN_004bbe90, FUN_004bbeb0)
  -> Distributes to subsystems via FUN_004b1ff0 -> FUN_004b4b40 (proximity) / FUN_004bd9f0 (AABB)
  -> Forwards to hull damage tracker via FUN_00593ee0 -> FUN_004b2120
  -> Triggers notification via FUN_00593f30 (sets up callback at 0x005927e0)

0x005927e0 (DamageNotificationCallback - NOT in Ghidra func DB):
  -> Checks DAT_008e5c1c flag
  -> Calls FUN_00592960 (DamageTickUpdate)
  -> If damage tick returns true, gets NiNode and calls FUN_007dc5c0 with gameTime
```

## Destruction Chain
```
Network opcode 0x14 -> FUN_006a01e0 (DestroyObject_NetworkHandler):
  -> Reads objectID from stream
  -> FUN_00434e00: looks up object by ID in global tracker (type 0x8003)
  -> If obj+0x20 != NULL: calls vtable[0x5c](objectID) on obj+0x20's vtable
  -> If obj+0x20 == NULL:
     -> FUN_0059fd30: checks if object has type 0x8006 (ship type)
     -> If ship: calls vtable[0x138](1, 0) -- likely SetVisible(false) / MarkDead
     -> Then calls vtable[0] with arg 1 -- destructor with cleanup flag

Network opcode 0x29 -> FUN_006a0080 (Explosion_NetworkHandler):
  -> Reads objectID, position, damage values from stream
  -> FUN_00590a50: looks up object by ID (type 0x8007 - explosion target)
  -> Creates DamageEvent and calls FUN_00593e50 (ProcessDamage)
```

## Ship Death Detection
- No single "ship is dead" function found
- Hull HP depletion is tracked through the damage notification system
- FUN_00592960 (DamageTickUpdate) processes subsystem damage each tick
- The vtable[0x138](1,0) call in DestroyObject is the closest to "mark as dead"
- Ship removal: vtable[0](1) = destructor with delete flag
- Python side handles death events (ET_DESTROYED_OBJECT etc.)

## Hook-Ready Function Table

| Address | Name | Prologue (16 bytes) | relocLen | Notes |
|---------|------|---------------------|----------|-------|
| 0x005B0060 | CollisionDamageWrapper | 53 8B 5C 24 08 56 57 8B 7C 24 14 8B F1 6A 01 6A | 5 | __thiscall(this, collider, dmgAmount, dmgType) |
| 0x00593650 | DoDamage_FromPosition | 83 EC 24 56 8B F1 8B 46 18 85 C0 0F 84 84 00 00 | 6 | __thiscall(this, collider, amount, type) |
| 0x005952D0 | DoDamage_CollisionContacts | 6A FF 68 C8 AF 87 00 64 A1 00 00 00 00 50 64 89 | 7 | __thiscall(this, contactList); SEH frame |
| 0x00594020 | DoDamage | 64 A1 00 00 00 00 6A FF 68 EB AE 87 00 50 64 89 | 6 | __thiscall(this, damageDir, amount, type); SEH frame |
| 0x00593E50 | ProcessDamage | 53 8B 5C 24 08 56 8B F1 57 BF 00 00 80 3F 39 BE | 5 | __thiscall(this, damageEvent) |
| 0x006A01E0 | DestroyObject_NetworkHandler | 6A FF 68 68 DA 87 00 64 A1 00 00 00 00 50 64 89 | 7 | __cdecl(streamPtr); SEH frame; opcode 0x14 |
| 0x006A0080 | Explosion_NetworkHandler | 6A FF 68 53 DA 87 00 64 A1 00 00 00 00 50 64 89 | 7 | __cdecl(streamPtr); SEH frame; opcode 0x29 |
| 0x00592960 | DamageTickUpdate | 51 53 55 56 8B F1 57 8B 86 30 01 00 00 85 C0 75 | 7 | __thiscall(this, float64 gameTime); ret 0x8 |
| 0x00592850 | ApplyDamageToSubsystems | 83 EC 08 8B 81 28 01 00 00 56 89 4C 24 04 8B 30 | 9 | __fastcall(this, float64 gameTime); ret 0x8 |
| 0x005927E0 | DamageNotificationCallback | A0 1C 5C 8E 00 56 84 C0 74 5B 8B 44 24 0C 8B 4C | 6 | NOT in Ghidra func DB; callback ptr stored in notification obj |
| 0x005AF420 | WeaponDoDamage | 8B 44 24 04 8B 50 2C 85 D2 74 05 83 FA 01 75 1F | 7 | __thiscall(this, weaponEvent); has relative JZ at offset 9 |
| 0x00595890 | ShipInitFromStream | 64 A1 00 00 00 00 6A FF 68 01 B0 87 00 50 64 89 | 6 | __thiscall(this, stream); SEH frame; ship deserialization |

## Caution: Relative Instructions in Prologue
- FUN_00592910 (SelectMaxDamageSubsystem): bytes 7-11 contain CALL rel32 (E8 xx xx xx xx) - needs fixup if relocated
- FUN_005AF420 (WeaponDoDamage): bytes 9-10 contain JZ +5 (74 05) and bytes 14-15 contain JNZ +1F (75 1F) - short jumps need fixup
- Functions with SEH setup (64 A1 00 00 00 00) are safe to relocate at offset 6 since FS:[0] access is position-independent
