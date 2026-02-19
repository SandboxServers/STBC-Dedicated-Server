# NetImmerse Engine Dev Agent Memory

## Project Scope
STBC dedicated server RE — NetImmerse 3.1 / Gamebryo 1.2 engine internals.
Decompiled source at: `reference/decompiled/11_tgnetwork.c` (7334 lines)

## TGMessage / TGHeaderMessage Vtable Layout
- Base vtable: `0x008958d0`  TGMessage (0x40 bytes)
- +0x00 (slot 0): GetType() — returns message type u8
- +0x04 (slot 1): scalar_deleting_dtor — called as `(*vtable[4])(1)`
- +0x08 (slot 2): WriteToBuffer(buf, maxSize) — returns bytes written
- +0x0c (slot 3): unknown predicate (supersedes another message?)
- +0x10 (slot 4): IsOrdered() or similar — returns non-zero if ordering enforced
- +0x14 (slot 5): GetSize() — returns serialized byte size (used to advance buffer ptr)
- +0x18 (slot 6): Clone() — FUN_006b8610, allocs+copies message
- +0x1c (slot 7): FragmentMessage(&count, maxSize) — FUN_006b8720

TGHeaderMessage vtable: `0x008959ac` (0x44 bytes, adds is_below_0x32 at +0x40)

Other vtables:
- `0x0089598c` — another message type (reliable+ordered by default, +0x3a=1, +0x3b=1)
- `0x008959cc` — yet another type (TGConnectMessage?)

## Factory Table at 0x009962d4
Type byte indexes into this table (each entry = 4-byte function ptr):
- Type 0 (TGDataMessage): `FUN_006bc6a0` — proper function
- Type 1 (TGHeaderMessage/ACK): `LAB_006bd1f0` — code label, not named function!
- Type 2: `LAB_006bdd10` — code label
- Type 3 (TGConnectAckMessage): `FUN_006be860`
- Type 4 (TGBootMessage): `FUN_006badb0`
- Type 5 (TGDisconnectMessage): `FUN_006bf410`

Types 1 and 2 use raw code labels — Ghidra didn't identify them as function entries.
The ACK deserializer is at 0x006bd1f0 but not shown in decompiled output.

## TGMessage Constructor (FUN_006b82a0)
Sets: +0x3d = 1 (field_3D = "ready to send"), retx_count at +0x2c(param[0xb]) = 1,
intervals at +0x34(0xd)=1.0, +0x30(0xc)=1.0

TGHeaderMessage constructor (FUN_006bd120):
- Calls TGMessage base ctor
- Sets param[0xc]=0, param[0xb]=0 (overrides retx interval)
- Sets param[0xd]=0x3f2aa64c (~0.667 seconds max interval)
- Sets *(u8*)(param+0x10)=1 → byte offset 0x40 = is_below_0x32 defaults to 1

## field_3D (+0x3d) Behavior
In SendOutgoingPackets (FUN_006b55b0), the first-send queue iterates messages.
`if (piVar10 + 0x3d == 0)` → message is SKIPPED (not serialized).
Normal TGMessage has field_3D=1 (from constructor), so always sent.
This field is NOT the bug — ACK messages also have field_3D=1.

## Sequence Counter Management (Receive Side)
In DispatchReceivedMessages (FUN_006b5f70), line 3626:
`*(short *)(iVar1 + 0x24) = (short)piVar2[5] + 1;`
This sets peer.expected_seq = msg.seq + 1 for EACH reliable message dispatched.
Fragmented messages share the same seq — so ALL three fragments advance the counter
by 1 from seq+0 → seq+1 → ... this is seq+1 from the last one processed.
Each fragment has the SAME seq, so expected_seq ends up at seq+1 after all 3.

## QueueForDispatch Sequence Check (FUN_006b6ad0)
Line 4125-4131: If incoming_seq - expected_seq is outside (-0x4001, +0x3fff):
→ message is DESTROYED (delete + return). No ACK is generated for out-of-window messages.

## Fragment First-Send Queue Ordering (IMPORTANT!)
In SendHelper (FUN_006b5080), lines 2737-2764:
- is_ordered == 0: fragments appended to TAIL (normal order)
- is_ordered == 1: fragments inserted at HEAD (reverse order: frag 2, 1, 0 sent first)

## Retransmit Queue: ONE MESSAGE PER TICK
In SendOutgoingPackets (FUN_006b55b0), lines 3065-3095:
The retransmit loop sends AT MOST ONE MESSAGE per peer per tick, then `break`s.
ACK-outbox loop sends ALL ACKs (no break after each).

## ACK Retransmit Count Limit
ACK-outbox entries with retransmit_count >= 3 are NOT sent in the normal pass.
Second pass at lines 3199-3228: ACKs with count > 2 only sent if data was also sent
or peer is disconnecting. After count > 8, ACK is destroyed.

## TGWinsockNetwork::Update Tick Order (FUN_006b4560)
For connected state (iVar8==3):
1. SendOutgoingPackets (FUN_006b55b0) — ACK-outbox, retransmit, first-send
2. ProcessIncomingMessages (FUN_006b5c90) — deserialize UDP packets
3. DispatchReceivedMessages (FUN_006b5f70) — type switch dispatch

This means: retransmits are sent BEFORE incoming ACKs are processed.

## Peer Object Layout (FUN_006c08d0, 0xC0 bytes)
Key fields between +0x30 and +0x64 (peer timestamp/state gap):
- +0x2C (param[0xb]): last_activity_time (DAT_0099c6bc at init)
- +0x30 (param[0xc]): last_connect_time (DAT_0099c6bc at init)
- +0x34 through +0x60: all init to 0 (no hidden state found)
- +0x64: first-send queue head (param[0x19])

## Type 0x32 Boundary Rationale
Two seq counter pairs: (peer+0x24/+0x26) for types < 0x32, (peer+0x28/+0x2A) for >= 0x32.
Purpose: separate "game data" messages from "control/setup" messages.
Types < 0x32 are game gameplay messages; >= 0x32 appear to be lobby/session setup.
See QueueForDispatch (FUN_006b6ad0) lines 4117-4123.

## Key Functions
- FUN_006b5080: SendHelper — fragments, seq assignment, first-send enqueue
- FUN_006b55b0: SendOutgoingPackets — 3-queue send loop
- FUN_006b5c90: ProcessIncomingMessages — receive + ACK creation
- FUN_006b5f70: DispatchReceivedMessages — type switch
- FUN_006b61e0: HandleReliableReceived — creates per-fragment ACKs
- FUN_006b64d0: HandleACK — searches retransmit queue
- FUN_006b6ad0: QueueForDispatch — seq check + reassembly trigger
- FUN_006b6cc0: ReassembleFragments — 256-slot array, collects by frag_idx
- FUN_006b8720: FragmentMessage — splits, sets is_fragmented/frag_idx
- FUN_006b8550: TGMessage::CopyConstructor — copies ALL fields incl +0x3b
- FUN_006c08d0: Peer object constructor (0xC0 bytes)
- FUN_006b7410: CreatePeer — allocates 0xC0 bytes, sorted insert into peer array

## Decompiled Source Files
- `reference/decompiled/11_tgnetwork.c` — TGWinsockNetwork (7334 lines)
- `reference/decompiled/12_data_serialization.c` — peer ctor, TGDataMessage serialization
