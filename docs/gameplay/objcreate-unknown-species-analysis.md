> [docs](../README.md) / [gameplay](README.md) / objcreate-unknown-species-analysis.md

# ObjCreate Handler: Unknown Species Behavior Analysis

Reverse-engineered from `stbc.exe` binary (Ghidra decompilation + disassembly) and verified against the shipped `Multiplayer/SpeciesToShip.py` Python source.

## Summary of Findings

| Question | Answer |
|----------|--------|
| Does the handler relay BEFORE or AFTER local creation? | **AFTER.** Ship_Deserialize runs first, then relay loop. |
| What happens when species lookup fails? | Ship C++ object is created but has NO model, NO subsystems, NO damage tracking. It is an empty hull. |
| Does the server create server-side state for unknown species? | **YES.** A network position/velocity tracker (0x58 bytes) is attached regardless of species validity. |
| Does the handler reject/drop the packet? | **NO.** The packet is relayed to all other clients verbatim, and the empty ship object persists locally. |
| Does the handler check IsHost for relay decisions? | **YES.** The relay loop only executes in multiplayer mode. IsClient gates whether self-tracking is created. |

## Detailed Execution Flow

### Handler Entry: `Handler_ObjCreate_0x02_0x03` at 0x0069f620

```
__thiscall Handler_ObjCreate(MultiplayerGame *this, TGMessage *msg, char isTeam)
```

Called from the MultiplayerGame dispatcher jump table for both opcodes 0x02 and 0x03. `isTeam` is 0 for opcode 0x02, non-zero for opcode 0x03.

### Step 1: Parse Envelope

```c
// Extract raw buffer from message
buffer = TGMessage_GetBuffer(msg, &size);   // FUN_006b8530

// Clear global "currently processing" flag
DAT_0095b07d = 0;

// Read owner player slot (always byte 1)
owner_slot = (signed char)buffer[1];
header_len = 2;

// If ObjCreateTeam, read team_id (byte 2)
if (isTeam) {
    team_id = (signed char)buffer[2];
    header_len = 3;
}
```

### Step 2: Swap Player Context

The handler temporarily sets the global "active player" context to the owner's slot, so that object ID allocation inside Ship_Deserialize uses the correct player's ID range.

```c
// Save current context
saved_slot = DAT_0097FA84;
saved_objbase = DAT_0097FA8C;

// Set context to owner's slot
DAT_0097FA84 = owner_slot;
DAT_0097FA8C = this->slots[owner_slot].objbase;  // at MultiplayerGame+0x84[slot*0x18]
```

### Step 3: Deserialize Object (LOCAL CREATION)

```c
ship = Ship_Deserialize(buffer + header_len, size - header_len);  // 0x005a1f50
```

**This is where species lookup and model loading happens.** See "Ship_Deserialize Pipeline" below for the full chain.

After deserialization, the player context is restored:
```c
DAT_0097FA84 = saved_slot;
DAT_0097FA8C = saved_objbase;
DAT_0095b07d = 1;  // re-enable "processing" flag
```

### Step 4: NULL Check (Only Abort Point)

```c
if (ship == NULL) goto exit;  // Ship_Deserialize returned NULL → done, no relay
```

**Ship_Deserialize returns NULL only for duplicate object IDs** (an object with the same network ID already exists). It does NOT return NULL for unknown species. See the analysis below.

### Step 5: Assign Team

```c
if (isTeam) {
    ship->team = team_id;  // ship+0x2E4
}
```

### Step 6: Network Check

```c
WSN = g_TGWinsockNetwork;  // 0x0097FA78
if (WSN == NULL) goto exit;
```

### Step 7: RELAY LOOP (Multiplayer Only)

```c
if (g_IsMultiplayer) {
    // Iterate all 16 peer slots
    for (int i = 0; i < 16; i++) {
        slot = &this->peers[i];  // stride 0x18, base at this+0x78

        if (!slot->isConnected) continue;

        if (slot->connectionID == msg->senderID) {
            // This is the SENDER's slot
            if (isTeam) {
                slot->objectID = ship->objectID;  // ship+0x04, update tracking
            }
        }
        else if (slot->connectionID != WSN->ownConnectionID) {
            // This is a DIFFERENT PEER (not sender, not self)
            cloned_msg = msg->Clone();              // vtable[0x18]
            SendToPeer(WSN, slot->connectionID, cloned_msg, 0);  // FUN_006b4c10
        }
    }
```

**CRITICAL**: The relay sends a **clone of the original message**, including the raw species_type byte. It does NOT re-serialize the ship object. Every receiving client gets the exact same bytes and runs the same deserialization pipeline independently.

**CRITICAL**: The relay happens AFTER Ship_Deserialize (local creation) but BEFORE the network tracker is attached. The object already exists locally when the relay executes.

### Step 8: Network Tracker Creation (Branched by Role)

After the relay loop, the handler creates a position/velocity tracking object. The branching depends on role:

```c
// --- HOST PATH (IsClient == 0) ---
if (!g_IsClient) {
    if (!isTeam) goto exit;  // Host skips tracker for ObjCreate (0x02)

    if (ship->GetClassID() == 0x8009) goto exit;  // Skip for torpedoes

    tracker = NiAlloc(0x58);
    FUN_0047dab0(tracker, ship, "Network");  // init pos/vel tracker
    ship->vtable[0x134](tracker, 1, 1);     // attach tracker
    ship->field_0xF0 = 0;                   // clear flag
}

// --- CLIENT PATH (IsClient == 1) ---
else {
    if (!isTeam) goto exit;  // Client skips for ObjCreate (0x02)

    if (ship->objectID == this->field_0x80) goto exit;  // Skip if it's client's own ship

    if (ship->GetClassID() == 0x8009) goto exit;  // Skip for torpedoes

    tracker = NiAlloc(0x58);
    FUN_0047dab0(tracker, ship, "Network");
    ship->vtable[0x134](tracker, 1, 1);
    ship->field_0xF0 = 0;
}

// --- SINGLE PLAYER PATH (not multiplayer) ---
// Same as host path but without the isTeam gate
```

**The network tracker is created regardless of whether the species was valid.** The tracker reads position from the ship via `ship->GetPosition()` (vtable[0x94]). For a ship with no model, this returns the default position (likely zeros or uninitialized memory from the factory constructor).

## Ship_Deserialize Pipeline (0x005a1f50)

```c
int* Ship_Deserialize(void* buffer, int size) {
    StreamReader stream;
    StreamReader_Init(&stream);              // FUN_006cefe0
    StreamReader_SetBuffer(&stream, buffer, size);  // FUN_006cf180

    int class_id  = StreamReader_ReadInt32(&stream);  // FUN_006cf670 — e.g. 0x8008
    int object_id = StreamReader_ReadInt32(&stream);  // FUN_006cf670

    // DUPLICATE CHECK: look up object_id in hash table
    int* existing = ObjectLookupByID(NULL, object_id);  // FUN_00430730
    if (existing != NULL) {
        return NULL;  // *** ONLY path that returns NULL ***
    }

    // FACTORY CREATE: instantiate C++ object by class_id
    int* ship = TGFactoryCreate(class_id);  // FUN_006f13e0
    // NOTE: NO NULL CHECK on factory result. If class_id is unknown, this returns 0
    //       and the vtable dereference below CRASHES.

    // READ STREAM: deserialize all fields (species, position, name, subsystems)
    ship->vtable[0x118](&stream);   // ReadStream → calls Ship_InitObject (0x005b0e80)
    // *** RETURN VALUE IS IGNORED — no check for success/failure ***

    // POST LOAD: finalize
    ship->vtable[0x11C](&stream);   // PostLoad

    return ship;  // ALWAYS returns non-NULL ship pointer (unless duplicate)
}
```

**CRITICAL FINDING**: `Ship_Deserialize` NEVER checks the return value of `vtable[0x118]` (ReadStream/InitObject). Even if the Python species lookup fails and InitObject returns 0, the ship pointer is returned to the handler.

## Ship_InitObject (0x005b0e80) — Where Species Resolution Happens

```c
int __thiscall Ship_InitObject(Ship* this, StreamReader* stream) {
    // Step 1: Read species byte from stream, store at ship+0xEC
    FUN_005a2030(this, stream);   // reads 1 byte → this->species (ship+0xEC)

    // Step 2: Get Python wrapper object for this ship
    PyObject* pySelf = this->GetPythonObject();   // vtable[0x20]

    // Step 3: Call Python: SpeciesToShip.InitObject(ship, species)
    int result = TG_CallPythonFunction(
        "Multiplayer.SpeciesToShip",    // module path
        "InitObject",                    // function name
        "i",                            // return format (integer)
        &stack_args,                    // pointer to args area
        "(Oi)",                         // arg format: Object + int
        /* variadic: pySelf, species */
    );

    // Decref the Python object
    Py_DECREF(pySelf);

    // Step 4: Check for PYTHON EXCEPTION (not logical failure)
    if (result == -1) {
        PyErr_Print();   // FUN_0074af10 → prints traceback to stderr
        return 0;        // Failed
    }

    // Step 5: Continue with remaining stream reads
    return stream->vtable[0xD8]();  // finalize/continue reading
}
```

## Python SpeciesToShip.InitObject — The Species Resolution

```python
def InitObject(self, iType):
    kStats = GetShipFromSpecies(iType)
    if kStats == None:
        return 0   # Failed. Unknown type. Bail.

    self.SetupModel(kStats['Name'])              # Load NIF model
    pPropertySet = self.GetPropertySet()
    mod = __import__("ships.Hardpoints." + kStats['HardpointFile'])
    App.g_kModelPropertyManager.ClearLocalTemplates()
    reload(mod)
    mod.LoadPropertySet(pPropertySet)
    self.SetupProperties()                        # Create subsystems
    self.UpdateNodeOnly()
    return 1

def GetShipFromSpecies(iSpecies):
    if iSpecies <= 0 or iSpecies >= MAX_SHIPS:   # MAX_SHIPS = 46
        return None
    pSpecTuple = kSpeciesTuple[iSpecies]
    pcScript = pSpecTuple[0]
    ShipScript = __import__("ships." + pcScript)  # Can raise ImportError
    ShipScript.LoadModel()
    return ShipScript.GetShipStats()
```

## Three Failure Scenarios for Unknown Species

### Scenario A: Species ID >= 46 (Out of Table Range)

Example: species_type = 100 (mod ship)

1. `GetShipFromSpecies(100)` hits the range check `iSpecies >= MAX_SHIPS` and returns `None`
2. `InitObject` checks `kStats == None`, returns `0`
3. `TG_CallPythonFunction` returns `0` (NOT -1, because no exception was raised)
4. `Ship_InitObject` does NOT call `PyErr_Print` (result != -1)
5. `Ship_InitObject` proceeds to call `stream->vtable[0xD8]()`
6. **Result**: Ship C++ object exists with species byte set, but NO model, NO subsystems, NO damage handling. Remaining stream data (position, name, set) is still read.

### Scenario B: Species ID 1-45 but Ship Script Missing

Example: species_type = 1 (Akira) but `ships/Akira.py` does not exist

1. `GetShipFromSpecies(1)` tries `__import__("ships.Akira")`
2. Python raises `ImportError`
3. `TG_CallPythonFunction` catches the exception and returns `-1`
4. `Ship_InitObject` calls `PyErr_Print()` (prints traceback)
5. `Ship_InitObject` returns `0`
6. **Result**: Same as Scenario A — empty ship hull. Traceback printed to stderr.

### Scenario C: Species ID 1-45 but Hardpoint File Missing

Example: species_type = 1, `ships/Akira.py` exists but `ships/Hardpoints/akira.py` missing

1. `GetShipFromSpecies(1)` succeeds (Akira.py loads)
2. `InitObject` calls `self.SetupModel(kStats['Name'])` — model loads OK
3. `__import__("ships.Hardpoints.akira")` raises `ImportError`
4. Exception propagates to `TG_CallPythonFunction` → returns `-1`
5. **Result**: Ship has a model (NIF loaded) but NO subsystems. Model is visible but non-functional. Partial initialization.

## Impact Summary: What an Empty Ship Hull Means

When a ship is created without successful species initialization:

| Component | State | Consequence |
|-----------|-------|-------------|
| C++ object (factory) | EXISTS (valid pointer) | Object tracked in game's object table |
| ship+0xEC (species) | SET (from stream) | Species byte is stored before Python runs |
| ship+0x18 (NiNode) | NULL | No visual model; `GetBoundingBox` returns garbage |
| ship+0x284 (subsystem list) | EMPTY | StateUpdate sends flags=0x00 (no subsystem data) |
| ship+0x128/+0x130 (damage handlers) | NULL/EMPTY | `DoDamage` skips this ship (gates on ship+0x140) |
| ship+0x140 (damage target) | NULL | No damage processing possible |
| ship+0x2E4 (team) | SET (from handler) | Team assignment happens after deserialization |
| Network tracker | CREATED (0x58 bytes) | Position tracking exists but reads default/zero position |
| ship+0xF0 (flag) | CLEARED to 0 | Handler clears this after tracker attachment |

## Relay Timing Diagram

```
TIME ──────────────────────────────────────────────────────────────►

1. Parse envelope (owner_slot, team_id)
2. Swap player context to owner's slot
3. Ship_Deserialize ◄─── LOCAL CREATION HAPPENS HERE
   ├─ Read class_id + object_id
   ├─ Duplicate check (only abort path → return NULL)
   ├─ TGFactoryCreate(class_id) → C++ object allocated
   ├─ ReadStream → Ship_InitObject
   │   ├─ Read species byte → ship+0xEC
   │   ├─ Python: SpeciesToShip.InitObject(ship, species)
   │   │   ├─ Species >= 46: returns 0 (no exception)
   │   │   ├─ Script missing: raises ImportError → TG returns -1
   │   │   └─ Success: loads model, hardpoints, subsystems
   │   └─ Return value IGNORED by Ship_Deserialize
   ├─ PostLoad
   └─ Return ship* (always non-NULL unless duplicate)
4. Restore player context
5. Assign team (if ObjCreateTeam)
6. NULL check on ship (only fails for duplicates)
7. ═══ RELAY LOOP ═══ ◄─── RELAY HAPPENS HERE (after local creation)
   │  For each connected peer != sender != self:
   │    Clone original message
   │    SendToPeer(clone)
   │  For sender's slot: update objectID tracking
8. ═══ TRACKER CREATION ═══ ◄─── server-side state created
   ├─ Check: is torpedo (0x8009)? → skip
   ├─ NiAlloc(0x58) → tracker
   ├─ Init tracker (position/velocity from ship)
   ├─ Attach tracker to ship (vtable[0x134])
   └─ Clear ship+0xF0
```

## Host vs Client Differences

| Behavior | Host (IsClient=0) | Client (IsClient=1) |
|----------|-------------------|---------------------|
| Relay to other peers | Effectively YES | Effectively NO (see below) |
| Skip ObjCreate (0x02) tracker | Yes — exits after relay | Yes — exits after check |
| Skip own ship tracker | N/A | Yes — skips if `ship->objectID == this->field_0x80` |
| Tracker creation gate | `isTeam && classID != 0x8009` | `isTeam && notOwnShip && classID != 0x8009` |

### Relay Loop Gating (Not Explicit IsHost Check)

The relay loop is gated on `IsMultiplayer` (0x0097FA8A), NOT on `IsHost`. Both host and clients execute the loop, but natural filtering prevents clients from actually sending:

```asm
0069f6fe: MOV AL,[0x0097fa8a]      ; IsMultiplayer
0069f703: TEST AL,AL
0069f705: JZ 0069f7df              ; not multiplayer → single player path

; Relay loop runs for EVERYONE in multiplayer mode.
; The loop skips self (WSN+0x20) and sender (msg->senderID).
; Clients only know about the host's connection, and for relayed messages
; the sender IS the host, so no actual sends occur on the client side.

0069f756: MOV AL,[0x0097fa88]      ; IsClient
0069f75b: TEST AL,AL
0069f75d: JZ 0069f7a4              ; IsClient=0 → HOST tracker path
;                                   ; IsClient=1 → CLIENT tracker path
```

The relay loop effectively only produces sends on the host because:
- Clients only know about the host's connection in their peer table
- For relayed messages, the sender is the host, which is filtered out
- The self-check (`WSN+0x20`) filters the client's own connection

This is a natural filtering mechanism, not an explicit `IsHost` gate.

## Potential Risks with Unknown Species

1. **Crash risk from NULL NiNode**: Functions like `GetBoundingBox` (vtable[0xE8]) and `GetModelBound` (vtable[0xE4]) may dereference ship+0x18 (NiNode). If another system queries the ship's bounds (collision, rendering), this could crash. Our `PatchNetworkUpdateNullLists` at 0x005B1D57 already guards StateUpdate, but other code paths may not.

2. **Stream desynchronization**: If Ship_InitObject fails partway through, the remaining bytes in the stream may not be consumed correctly. The position/orientation/name/subsystem reads happen in ReadStream, which InitObject is part of. If InitObject bails early, the stream cursor may be at an unexpected position, causing subsequent reads to produce garbage.

3. **Tracker with invalid position**: The network tracker reads the ship's position. If the ship has no model, the position returned by `GetPosition()` is whatever the factory constructor initialized (likely zeros). The tracker would report the ship at origin (0,0,0).

4. **No cleanup path**: There is no code to destroy or clean up a ship that failed species initialization. The empty hull persists in the game's object table for the entire session.

## Key Functions Reference

| Address | Name | Role |
|---------|------|------|
| 0x0069f620 | Handler_ObjCreate_0x02_0x03 | Dispatcher for both opcodes |
| 0x005a1f50 | Ship_Deserialize | Stream reader, factory create, ReadStream, PostLoad |
| 0x005a2030 | ReadSpeciesByte | Reads species byte into ship+0xEC |
| 0x005b0e80 | Ship_InitObject | Calls Python SpeciesToShip.InitObject |
| 0x006f8ab0 | TG_CallPythonFunction | Calls Python function by module.name |
| 0x006f13e0 | TGFactoryCreate | Class ID → C++ object via factory hash |
| 0x00430730 | ObjectLookupByID | Hash table lookup (duplicate check) |
| 0x006b4c10 | SendToPeer | Reliable message send to a connection |
| 0x0047dab0 | InitNetworkTracker | Create position/velocity tracker (0x58 bytes) |
| 0x006b8530 | TGMessage_GetBuffer | Extract raw data pointer + size |
| 0x006cf670 | StreamReader_ReadInt32 | Read 4-byte LE integer from stream |
| 0x0074af10 | PyErr_Print | Print Python exception traceback |
