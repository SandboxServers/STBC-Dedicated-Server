# PythonEvent Generation from Collision Damage (2026-02-19)

## Complete Call Chain: Collision → PythonEvent (opcode 0x06)

### Overview
When a collision occurs, **14 PythonEvents** are generated because each damaged subsystem
triggers an automatic repair-list addition, which the MultiplayerGame's HostEventHandler
serializes and sends as opcode 0x06.

### Chain (verified from disassembly)

```
1. ProximityManager detects collision
2. Posts event ET_COLLISION_EFFECT (0x00800050) to event system
3. DamageableObject::CollisionEffectHandler catches 0x00800050
   → Also catches 0x008000fc (HostCollisionEffect variant)

4. ShipClass::CollisionEffectHandler (LAB_005af9c0) catches 0x00800050
   a. Validates sender is host (IsHost check at 0x97fa89)
   b. Calls FUN_006a17c0(event, 0x15) → sends opcode 0x15 (CollisionEffect) to "NoMe"
   c. Falls through to FUN_005afad0 → applies collision damage

5. FUN_005afad0 (collision damage application):
   a. Checks ship+0x2DC (damage interface) for auto-repair capability
   b. If auto-repair active: posts event 0x00800053 (ET_COLLISION_DAMAGE?)
   c. For each contact point (edi+0x38 = numContacts):
      - Calls FUN_005afd70 → FUN_005af4a0 (per-subsystem damage)

6. FUN_005af4a0 (per-subsystem collision damage):
   a. Reads subsystem condition (property+0x30)
   b. Reduces condition by damage amount
   c. Calls FUN_0056c470 (ShipSubsystem::SetCondition)

7. FUN_0056c470 (ShipSubsystem::SetCondition) at 0x0056c470:
   a. Stores new condition at this+0x30
   b. Updates condition ratio at this+0x34
   c. If newCondition < maxCondition AND ship is alive:
      → Posts event 0x0080006b (ET_SUBSYSTEM_HIT)

8. RepairSubsystem::HandleHitEvent (LAB_005658d0) catches 0x0080006b:
   a. Looks up damaged subsystem from event+0x28
   b. Calls FUN_00565900 (AddSubsystemToRepairList)

9. FUN_00565900 (RepairSubsystem::AddSubsystemToRepairList):
   a. Calls FUN_00565520 to add to repair queue (rejects dupes)
   b. If successful AND g_IsHost!=0 AND g_IsMultiplayer!=0:
      → Creates event with type 0x008000df (ET_ADD_TO_REPAIR_LIST)
      → Posts to event system via FUN_006da2a0

10. MultiplayerGame::HostEventHandler (LAB_006a1150) catches 0x008000df:
    a. Writes opcode byte 0x06 to buffer
    b. Serializes event via vtable[0x34] (WriteToStream)
    c. Creates TGMessage, copies buffer
    d. Sets reliable flag (msg+0x3a = 1)
    e. Sends to "NoMe" group via SendTGMessageToGroup(WSN, "NoMe", msg)
```

### Why 14 PythonEvents per collision
- Two ships collide → each ship takes damage
- Each ship has ~7 top-level subsystems that get damaged (shields, hull sections, etc.)
- 7 subsystems × 2 ships = 14 ET_ADD_TO_REPAIR_LIST events
- Each becomes one PythonEvent (opcode 0x06) message

### Three Functions That Generate Opcode 0x06

1. **HostEventHandler** (LAB_006a1150)
   - Registered for: 0x008000df (ET_ADD_TO_REPAIR_LIST), 0x00800074, 0x00800075
   - Pattern: serialize event → TGMessage → "NoMe" group

2. **ObjectExplodingHandler** (LAB_006a1240)
   - Registered for: 0x0080004e (ET_OBJECT_EXPLODING)
   - Same pattern: serialize event → TGMessage → "NoMe" group
   - Gated on IsMultiplayer (only sends in MP)

3. **GenericEventForward** (FUN_006a17c0)
   - Used by all other forwarding handlers (StartFiring, StopFiring, etc.)
   - Writes the SPECIFIC opcode (0x07, 0x08, 0x0A, 0x15, etc.), NOT 0x06
   - Sends to "NoMe" group (if MP) or self (if SP)

### Key Insight: Our Server's Missing PythonEvents
Our OpenBC dedicated server DOES apply collision damage (DoDamage works) but does NOT
generate PythonEvent messages because:
- DoDamage → ProcessDamage → subsystem damage changes condition
- BUT: ShipSubsystem::SetCondition (FUN_0056c470) posts ET_SUBSYSTEM_HIT (0x0080006b)
- RepairSubsystem::HandleHitEvent catches it and adds to repair queue
- FUN_00565900 posts ET_ADD_TO_REPAIR_LIST (0x008000df)
- HostEventHandler catches it and sends PythonEvent

The question is: are all these event handlers properly registered on our server?
All registration happens in:
- ShipClass static registration (FUN_005ab7c0) - called during class init
- RepairSubsystem per-instance registration (0x00565220) - called per ship
- MultiplayerGame constructor (FUN_0069e590) - called when MP game created

### RepairSubsystem Per-Instance Event Registrations (at 0x00565220)
- 0x0080006b → HandleHitEvent (string at 0x008e5058)
- 0x00800074 → HandleRepairComplete (string at 0x008e5030)
- 0x00800070 → HandleSubsystemDamaged (string at 0x008e5008)
- 0x00800075 → HandleRepairCancelled (string at 0x008e4fd8)

### PythonEvent Forward/Relay Logic (FUN_0069f880)
When host RECEIVES a PythonEvent from a client:
1. Looks up "Forward" group in WSN+0xf4
2. Temporarily removes sender from group
3. Forwards message to remaining "Forward" members
4. Re-adds sender
5. If sender != self: also posts event locally

This is standard relay - collision PythonEvents from host don't use this path.

### Event Registration Gate Conditions
- HostEventHandler registration: gated on `g_IsMultiplayer != 0` (only registered in MP)
- RepairSubsystem per-instance: NOT gated on MP (always registered)
- FUN_00565900 (repair list → event post): gated on `g_IsHost!=0 AND g_IsMultiplayer!=0`
