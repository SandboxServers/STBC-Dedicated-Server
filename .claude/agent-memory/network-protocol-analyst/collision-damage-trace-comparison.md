# Collision Damage Trace Comparison (2026-02-19)

## Test: Stock Dedi vs OpenBC Dedi — Collision Damage

### Opcode Distribution

| Opcode | Stock Client | OpenBC Client | Notes |
|--------|-------------|---------------|-------|
| 0x1C StateUpdate | 197 | 24 | 8x fewer in OpenBC (shorter session) |
| 0x06 PythonEvent | 14 | **0** | **CRITICAL MISSING** |
| 0x15 CollisionEffect | 2 | 2 | Same (both from server) |
| 0x29 Explosion | **0** | 2 | OpenBC sends, stock doesn't |
| 0x36 ScoreChange | 1 | 0 | Stock sends score msg |
| 0x17 DeletePlayerUI | 1 | 0 | Stock cleans up dead player |
| 0x1D ObjNotFound | 1 | 0 | Stock sends object query |
| 0x37 PlayerRoster | 0 | 1 | OpenBC sends extra roster |
| 0xC0 (keepalive?) | 0 | 13 | OpenBC sends repeating name/IP |
| 0x03 ObjCreateTeam | 1 | 1 | Same (identical payload) |

### Function Tracer (Client-Side)

| Function | Stock Client | OpenBC Client | Gap |
|----------|-------------|---------------|-----|
| DoDamage | 22 | 4 | **-18** |
| ProcessDamage | 22 | 6 | **-16** |
| DoDamage_FromPosition | 18 | 0 | **-18** |
| CollisionDamageWrapper | 18 | 0 | **-18** |
| DoDamage_CollisionContacts | 4 | 4 | Same |
| Explosion_Net | 0 | 2 | +2 |

### Root Cause: Missing PythonEvent (0x06) Forwarding

Stock server sends 14 PythonEvent messages after collision:
1. eventCode=0x00008129 (collision damage event, 1x)
2. eventCode=0x00000101 (subsystem status changed, 13x)

These trigger client-side Python handlers -> SWIG AddDamage -> CollisionDamageWrapper ->
DoDamage_FromPosition -> DoDamage -> ProcessDamage (18 calls total).

OpenBC sends ZERO PythonEvent messages. The 4 CollisionContacts DoDamage calls from
the collision physics only do minimal damage. The 18 DoDamage_FromPosition calls are
what actually destroys subsystems and kills the ship.

### Subsystem Cycling Difference (StateUpdate 0x20 flag)

Stock server: startIdx cycle = 0, 2, 6, 8, 10 (5 windows, wraps at 2)
OpenBC server: startIdx cycle = 0, 5, 7, 9 (4 windows, wraps at 0)

This means the server-side ship+0x284 linked list is in different order between
stock and OpenBC. DeferredInitObject creates subsystems in a different order than
the stock engine pipeline (LoadPropertySet -> SetupProperties -> LinkAllSubsystemsToParents).

### Shield/Hull Flickering Explanation

Because the server-side subsystem linked list order differs from the client's list order,
the round-robin StateUpdate bytes are misinterpreted by the client. For example, the server
writes PowerSubsystem battery bytes at position X, but the client reads that position as
a ShieldGenerator condition byte. The oscillating power values (FD->FC->FD) appear as
fluctuating shield/hull health to the client.

### Two Fixes Needed

1. **FIX: PythonEvent forwarding** — The stock server's C++ collision pipeline generates
   events (ET_WEAPON_HIT etc) that are forwarded as PythonEvent opcode 0x06 to clients.
   OpenBC's server-side collision detection runs (DoDamage fires) but the events are not
   forwarded. This is likely because the event handler registration on the server side
   differs — see gap-analysis-20260215.md GAP 1 (DamageEventHandler not registered).

2. **FIX: Subsystem list order** — DeferredInitObject must create subsystems in the SAME
   order as the stock engine pipeline. The stock order for Sovereign is:
   Hull, ShieldGen, Sensor, WarpCore, Impulse, Torpedoes, Repair, Bridge, Phasers,
   Tractors, WarpEngines (11 top-level, as documented in wire-format-spec.md).
   The current DeferredInitObject order produces a different linked list, causing
   all subsystem health data to be misinterpreted by the client.
