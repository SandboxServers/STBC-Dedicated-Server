# ObjCreateTeam (0x03) Packet Format

## Packet Structure
```
Offset  Size  Field                Description
------  ----  -----                -----------
  0     1     Opcode               Always 0x03
  1     1     Owner                Peer index (0=Peer#0, 1=Peer#3, etc.)
  2     1     Team                 Team ID (2=Sep's team, 3=Cady's team)
  3     4     ClassType            Object class factory ID (LE u32, always 0x00008008 for ships)
  7     4     ObjectID             Unique object instance ID (LE u32)
 11     1     SpawnIndex           Spawn point index on the map
 12    12     Position             3 x float32 LE (x, y, z)
 24    16     Orientation          Quaternion: 4 x float32 LE (w, x, y, z), |mag|=1.0
 40     4     Speed                float32 LE (always 0.0 at spawn)
 44     3     Padding              Always 0x00 0x00 0x00
 47     1     PlayerNameLen        Length of player name string (N)
 48     N     PlayerName           ASCII string, NOT null-terminated
 48+N   1     SetNameLen           Length of set/map name string (M)
 49+N   M     SetName              ASCII string, NOT null-terminated (e.g. "Poseidon2")
 49+N+M var   SubsysHealth         Subsystem health state (to end of message)
```

## Total Message Size
- Header (fixed): 47 bytes + PlayerNameLen + SetNameLen + names + SubsysHealth
- Typical sizes: 92-121 bytes total game payload

## Ship Class Identification
Ship class is NOT encoded in this packet. It must be determined from:
1. Prior ship selection UI state
2. Subsystem health data length (fingerprint):
   - 34 bytes = Bird of Prey (7 0x64-delimited groups)
   - 51 bytes = Standard cruiser (9 groups)
   - 53 bytes = Larger ship type A (9 groups)
   - 54 bytes = Larger ship type B (8 groups)
3. subsysHash from first StateUpdate after spawn
4. Weapon count from initial StateUpdate WPN flags

## Subsystem Health Encoding
Each byte represents one subsystem's health:
- 0xFF = full health / default
- 0x64 = 100% (explicit marker, acts as group boundary)
- 0x60 = 96% (appears once per ship, possibly hull integrity)
- 0x01 = 1% (appears in some configs)
- 0x00 = 0% (destroyed)

## Observed Spawns (stock-dedi trace 2026-02-09)
| # | Time     | Owner | Team | ObjID      | SpawnIdx | Pos             | SubsysLen | Ship Type |
|---|----------|-------|------|------------|----------|-----------------|-----------|-----------|
| 1 | 22:09:10 | Sep   | 2    | 0x3FFFFFFF | 5        | (-36, -61, -46) | 53        | Type A    |
| 2 | 22:09:16 | Cady  | 3    | 0x4003FFFF | 3        | (-29, -23, -22) | 54        | Type B    |
| 3 | 22:10:00 | Sep   | 2    | 0x40000025 | 6        | (-48, 10, 51)   | 34        | BoP       |
| 4 | 22:13:14 | Cady  | 3    | 0x40040080 | 1        | (-89, 10, -91)  | 51        | Cruiser   |
| 5 | 22:13:23 | Sep   | 2    | 0x40000090 | 1        | (36, 59, 1)     | 51        | Cruiser   |
| 6 | 22:18:15 | Sep   | 2    | 0x400000E2 | 4        | (-80, 89, -95)  | 51        | Cruiser   |

## Code References
- FUN_005a1f50 (0x005a1f50): Object factory, reads classType + objID from stream
- FUN_005a2060 (0x005a2060): Deserialization, reads quat/pos/names/subsys from stream
- FUN_006cf670 (0x006cf670): Stream ReadDword (4 bytes LE)
- FUN_006cf6b0 (0x006cf6b0): Stream ReadFloat (4 bytes LE)
- FUN_0069f620 (0x0069f620): ReceiveMessage dispatcher, reads owner+team header
- DAT_0097e9c8: Sorted array of set objects for binary search by name
