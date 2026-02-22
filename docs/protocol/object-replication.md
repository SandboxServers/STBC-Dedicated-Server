> [docs](../README.md) / [protocol](README.md) / object-replication.md

# Object Replication

## FUN_0069f620 - Object Create/Update Processor

When a new player joins, the server iterates all game objects and sends them. The wire format is:

```
Byte 0: type_tag
  2 = standard object (no team)
  3 = team object (has team byte)

Byte 1: owner_player_slot
  Mapped from object owner to player slot via FUN_006a19a0

[If type_tag == 3:]
  Byte 2: team_id (from playerController[0xB9])

Remaining: object serialization data
  Produced by object->vtable[0x10C](buffer + offset, maxlen - offset)
```

The receiver (`FUN_0069f620`) on the client:
1. Temporarily swaps the local player slot to the sender's slot
2. Calls `FUN_005a1f50` to deserialize and create the game object
3. Restores the original player slot
4. Replicates to all other connected players (if multiplayer host)
5. Creates a "Network" controller for the object via `FUN_0047dab0`

See also [objcreate-serialization.md](objcreate-serialization.md) for full serialization chain details.
