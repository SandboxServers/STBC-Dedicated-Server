> [docs](../README.md) / [engine](README.md) / ui-class-hierarchy.md

# UI Class Hierarchy

Reverse-engineered from stbc.exe vtable analysis, constructor chains, and SWIG wrapper tracing (Phase 8D, 2026-02-24).

## Inheritance Tree

```
TGEventHandlerObject (event dispatch base)
  -> TGUIObject (UI element base: bounds, visibility, parent link)
       -> TGPane (child container: linked list of children, rendering)
            -> TGScrollablePane (scroll offset, viewport clipping)
                 -> TGTextBlock (console/chat text: paragraph list, history)
            -> TGWindow (default child tracking, focus management)
            -> STWidget (game button base: completion/highlight events)
                 -> STButton (text, colors, states, click handling)
                      -> STToggle (4-state toggle: values at +0x124, events at +0x164)
            -> TGIcon (sprite rendering: icon group, poly, RGBA color)
            -> TGParagraph (rich text: cursor, word wrap, layout)
            -> TGRootPane (top-level: cursor stack, tooltip, focus tracking)
```

**TGTextBlock** is aliased as `TGConsole` in the SWIG Python API.

## TGUIObject Layout

| Offset | Type | Field | Notes |
|--------|------|-------|-------|
| +0x14 | TGPane* | parent | Parent container |
| +0x18 | Rect | bounds | {x, y, w, h} in parent-relative coords |
| +0x28 | uint32 | flags | See flag bits below |
| +0x2C | void* | callbacks | Event callback data |

### Flag Bits (+0x28)

| Bit | Meaning |
|-----|---------|
| 0x08 | Visible |
| 0x20 | Skip parent in rendering chain |
| 0x40 | Exclusive keyboard focus |
| 0x80 | Dirty (needs repaint) |
| 0x100 | Hidden |
| 0x200 | Disabled |
| 0x10000000 | Layout in progress (TGParagraph recalc guard) |

## MainWindow Type IDs

TopWindow (the root game window at `0x0097e238`) creates child windows identified by type ID:

| ID | Class | Description |
|----|-------|-------------|
| 0 | BridgeWindow | 3D bridge crew view |
| 1 | TacticalWindow | 3D tactical combat view |
| 2 | ConsoleWindow | Debug console (half-height overlay) |
| 5 | PlayWindow | Mission play viewport |
| 7 | SortedRegionMenuWindow | Star map / system selection |
| 8 | MultiplayerWindow | Multiplayer lobby UI |
| 9 | PlayViewWindow | Play viewport overlay |
| 10 | CinematicWindow | Cutscene overlay |

### TopWindow Child Creation Order

TopWindow constructor (`0x0050c430`) creates 5 children:
1. MainWindow (type varies by game mode)
2. ConsoleWindow (type 2)
3. MultiplayerWindow (type 8)
4. PlayWindow (type 5)
5. CinematicWindow (type 10)

`TopWindow__FindMainWindow` (`0x0050e1b0`) iterates children, checks RTTI type `0x810F`, matches +0x4C type ID.

## PlayWindow vs PlayViewWindow

Two distinct classes were both labeled "PlayWindow" in early Ghidra analysis:

| Class | Constructor | Base Class | Purpose |
|-------|------------|------------|---------|
| **PlayWindow** | `0x00405c10` | MissionBase (TGEventHandlerObject) | The "Game" object — manages game state, scoring, episodes. Stored at `g_TopWindow`. This is the SWIG `Game` API object. |
| **PlayViewWindow** | `0x004fc480` | MainWindow (TGScrollablePane) | UI rendering viewport. Type ID 9. Handles visual display. |

### PlayWindow (Game Object) Layout

| Offset | Type | Field |
|--------|------|-------|
| +0x38 | int | score |
| +0x3C | int | rating |
| +0x40 | int | kills |
| +0x54 | Ship* | playerShip |
| +0x60 | bool | godMode |
| +0x6C | int | terminateEvent |
| +0x70 | Episode* | currentEpisode |

PlayWindow inherits from MissionBase, which adds:
- +0x14: moduleName (Python module path)
- +0x1C: type ID

MultiplayerGame extends PlayWindow:
- +0x74: playerSlots[16]
- +0x1F8: readyForNewPlayers
- +0x1FC: maxPlayers

## TGDialogWindow Button System

`TGDialogWindow__AddButtons` accepts a bitfield parameter:

| Bit | Button |
|-----|--------|
| 0x001 | OK |
| 0x002 | Cancel |
| 0x004 | Yes |
| 0x008 | No |
| 0x010 | Abort |
| 0x020 | Retry |
| 0x040 | Continue |
| 0x080 | Ignore |
| 0x200000 | Read-only mode (no buttons, display only) |

## Event Type Constants

### Input Events
| ID | Name | Source |
|----|------|--------|
| 0x30001 | Mouse | Input system |
| 0x30002 | Keyboard | Input system |
| 0x30003 | Gamepad | Input system |
| 0x40001 | Control | Input system |

### UI Toggle Events
| ID | Name |
|----|------|
| 0x800494 | ToggleConsole |
| 0x800495 | ToggleOptions |
| 0x8003CC | ToggleEdit |
| 0x800496 | TabFocus |
| 0x800497 | PrintScreen |
| 0x800498 | ToggleBridgeAndTactical |
| 0x8001DD | SelfDestruct |

### Game Flow Events
| ID | Name |
|----|------|
| 0x800002 | Quit |
| 0x800005 | NewGame |
| 0x800006 | LoadGame |
| 0x800007 | SaveGame |
| 0x8000C6 | NewMultiplayerGame |
| 0x8000F0 | MissionSelected |

### Dialog Events
| ID | Name |
|----|------|
| 0x8000CE | DialogOK |
| 0x8000CF | DialogCancel |
| 0x8000D0 | ExitGame |
| 0x8000D1 | ExitProgram |

### Resolution Events
| ID | Name |
|----|------|
| 0x8000B6 | ResolutionSelect |
| 0x8000B7 | ResolutionChangeForward |
| 0x8000B8 | ResolutionChangeBack |
| 0x8000BA | ResolutionApply |

## TGL Resource Files

| File | Contents |
|------|----------|
| data/TGL/Multiplayer.tgl | MP lobby buttons, mission list, player list |
| data/TGL/Options.TGL | Quit dialog, graphics/sound settings |

## RTTI Type IDs

| ID | Class |
|----|-------|
| 0x810F | MainWindow (base for all full-screen views) |
| 0x205 | TGConsole/TGTextBlock |
| 0x80EA | STRadioGroup |
