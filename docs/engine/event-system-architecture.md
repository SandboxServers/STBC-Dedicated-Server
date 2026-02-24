> [docs](../README.md) / [engine](README.md) / event-system-architecture.md

# Event System Architecture

Reverse-engineered from stbc.exe event dispatch infrastructure (Phase 8C, 2026-02-24). The event system is the backbone of all game logic — every game object registers handlers for event types and the TGEventManager dispatches events through sorted handler chains.

## Overview

```
TGEventManager (singleton)
  |
  +-- TGEventHandlerTable (global: broadcast handlers, keyed by event type)
  |     |
  |     +-- TGConditionHandler (per-event-type sorted array of handler entries)
  |           |
  |           +-- TGHandlerListEntry (linked list node: object + callback)
  |                 |
  |                 +-- TGCallback (wrapper: C++ function ptr OR Python callable)
  |
  +-- TGEventQueue (pending events: head/tail linked list)
  |
  +-- TGEvent (event object: type, source, destination, data)
```

## Dispatch Flow

1. **PostEvent** — Caller creates a TGEvent and posts it to the TGEventManager
2. **DispatchToBroadcastHandlers** — Event manager walks the global TGEventHandlerTable
3. **FindHandlerChain** — Hash table lookup by event type ID (hash = type % bucket_count)
4. **DispatchToNextHandler** — Walk the TGConditionHandler's sorted array for this event type
5. **InvokeCallback** — Each TGCallback is invoked: either a direct C++ function call, or Python module.function import + call

## Key Classes

### TGEventManager

Global singleton that owns the handler tables and event queue. Provides the API for registering handlers and posting events.

### TGEventHandlerTable

Global hash table of broadcast handlers. Keyed by event type ID. Each bucket is a chain of TGConditionHandler entries.

Key methods:
- **RegisterObject** — Create handler chain for an object in the global table
- **FindHandlerChain** — Hash lookup for event type
- **DispatchToNextHandler** — Walk chain, invoke each handler via TGConditionHandler
- **RemoveAllHandlersForObject** — Cleanup when an object is destroyed

### TGInstanceHandlerTable

Per-object handler table (lives at TGEventHandlerObject+0x10). Uses a 0x25-bucket (37-bucket) hash table. Same structure as the global table but scoped to a single object instance.

### TGConditionHandler

Manages **sorted arrays** of handler entries with binary search for insertion and lookup. Supports two arrays: broadcast (all listeners) and per-object (targeted). Key property: **reentrant** — supports deferred add/remove during dispatch to handle cases where a handler modifies the handler list.

Size: variable (two dynamically-sized sorted arrays)
Vtable: `0x00896104`

Key methods:
- **AddEntry** — Create node, insert sorted by priority key
- **InsertSorted** — Binary search for insertion point
- **FindFirstByKey** — Binary search for first matching entry
- **RemoveByName** — Find and remove by name hash
- **RemoveAllForObject** — Remove all handlers for a given object

### TGCallback

0x14-byte object wrapping either a C++ function pointer or Python callable.
Vtable: `0x008960f4`

**Layout:**
| Offset | Size | Field |
|--------|------|-------|
| +0x00 | 4 | vtable pointer |
| +0x04 | 4 | flags (bit0=isMethod, bit1=isPython, bit2=active, bit3=pendingDelete) |
| +0x08 | 4 | next (chain pointer) |
| +0x0C | 4 | sentinel value |
| +0x10 | 4 | function pointer / string pointer |

When `isPython` is set, +0x10 points to a string of the form `"module.function"` which is imported at invocation time via `__import__` + `getattr`.

### TGHandlerListEntry

0xC-byte linked list node in the handler chain:
| Offset | Size | Field |
|--------|------|-------|
| +0x00 | 4 | object pointer (TGEventHandlerObject*) |
| +0x04 | 4 | callback pointer (TGCallback*) |
| +0x08 | 4 | deleted flag |

### TGEvent

Base event object (factory ID 0x02, size 0x28). Carries event type, source object, destination object, and type-specific data.

Key methods:
- **SetSource** / **SetDestination** — Set object references
- **Duplicate** — Clone event for forwarding
- **LookupInEventTable** / **RegisterInEventTable** — Object ID resolution

### TGEventQueue

Simple linked list queue (head, tail, count). Events are enqueued for deferred processing during the game loop tick.

## Handler Registration Pattern

Every class inheriting from TGEventHandlerObject has two virtual methods:
1. **RegisterHandlerNames** — Calls `TGObject__RegisterHandlerWithName(name_string)` for each handler. These strings are debug identifiers compiled from original source.
2. **RegisterHandlers** — Calls `RegisterEventHandler(event_type_id, callback)` for each handler.

This pattern was systematically identified across 50+ classes in Pass 9C. The `discover_strings` annotation script was previously misidentifying RegisterHandlerNames functions as the handler functions themselves (because they contain the handler name strings).

## Event Type ID Encoding

Event type IDs follow a hierarchical encoding:
- `0x30001`-`0x40001` — Input events (mouse, keyboard, gamepad, control)
- `0x800XXX` — Game events (see [ui-class-hierarchy.md](ui-class-hierarchy.md) for catalog)
- `0x8000E0`-`0x8000E5` — Combat events (SetPhaserLevel, StartCloak, StopCloak)
- `0x800058`-`0x80005A` — Targeting events (TARGET_WAS_CHANGED, TARGET_SUBSYSTEM_SET)

## Serialization

The entire handler table system supports save/load:
- TGEventHandlerTable: SaveBroadcastHandlers / LoadBroadcastHandlers
- TGInstanceHandlerTable: SaveToStream / LoadFromStream
- TGConditionHandler: SaveHandlerEntries / LoadHandlerEntries
- TGEventQueue: SaveToStream / LoadFromStream

Post-load fixup resolves object IDs back to live pointers via FixupReferences → FixupComplete two-phase process.
