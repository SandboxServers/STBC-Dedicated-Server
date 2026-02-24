# UI Class Hierarchy (Phase 8D, 2026-02-24)

## Inheritance Tree
```
TGEventHandlerObject (event dispatch base)
  -> TGUIObject (+0x14=parent, +0x18=bounds rect, +0x28=flags, +0x2C=callbacks)
       -> TGPane (+0x30=childCount, +0x34=head, +0x38=tail, linked list children)
            -> TGScrollablePane (scrolling)
                 -> TGTextBlock (console text, +0x4C history list)
                      - Aliased as TGConsole in SWIG
            -> TGWindow (+default child tracking)
            -> STWidget (+0x4C=completionEvent, +0x50=highlightEvent, +0x54=unhighlightEvent)
                 -> STButton (0x108 bytes: text, colors, flags, states)
                      -> STToggle (0x178 bytes: 4 state values at +0x124, events at +0x164)
            -> TGIcon (+0x30=poly, +0x34=groupName, +0x38=iconNum, +0x3C=RGBA, +0x4C=clamp)
            -> TGParagraph (text rendering, cursor, wrapping)
            -> TGRootPane (+0x5C=cursor, +0x68=cursorVisible, +0x78=focusObj, +0x84=cursorStack, +0x8C=tooltip)
```

## MainWindow Type IDs
| ID | Class | Description |
|----|-------|-------------|
| 0 | BridgeWindow | 3D bridge view (full size) |
| 1 | TacticalWindow | 3D tactical view (full size) |
| 2 | ConsoleWindow | Debug console (half height) |
| 5 | PlayWindow | Mission play view |
| 7 | SortedRegionMenuWindow | Star map navigation |
| 8 | MultiplayerWindow | Multiplayer lobby/UI |
| 9 | PlayViewWindow | Play viewport overlay |
| 10 | CinematicWindow | Cutscene overlay |

## TopWindow Child Creation (ctor at 0x0050c430)
TopWindow creates 5 children in order:
1. MainWindow (type varies)
2. ConsoleWindow (type 2)
3. MultiplayerWindow (type 8)
4. PlayWindow (type 5)
5. CinematicWindow (type 10)

TopWindow__FindMainWindow (0x0050e1b0) iterates children, checks RTTI 0x810F, matches +0x4C type.

## Event Type Constants
### Input Events (from OptionsWindow__RegisterHandlers)
- 0x30001 = Mouse
- 0x30002 = Keyboard
- 0x30003 = Gamepad
- 0x40001 = Control
- 0x800494 = ToggleConsole
- 0x800495 = ToggleOptions
- 0x8003CC = ToggleEdit
- 0x800496 = TabFocus
- 0x800497 = PrintScreen
- 0x800498 = ToggleBridgeAndTactical
- 0x8001DD = SelfDestruct

### Game Events
- 0x800002 = Quit
- 0x800005 = NewGame
- 0x800006 = LoadGame
- 0x800007 = SaveGame
- 0x8000C6 = NewMultiplayerGame
- 0x8000F0 = MissionSelected

### Dialog Events
- 0x8000CE = DialogOK
- 0x8000CF = DialogCancel
- 0x8000D0 = ExitGame
- 0x8000D1 = ExitProgram

### Resolution Events
- 0x8000B6 = ResolutionSelect
- 0x8000B7/BA = ResolutionChange
- 0x8000B8/B9 = ResolutionChangeBack

## TGDialogWindow Button Flags (bitfield param)
- 0x001 = OK
- 0x002 = Cancel
- 0x004 = Yes
- 0x008 = No
- 0x010 = Abort
- 0x020 = Retry
- 0x040 = Continue
- 0x080 = Ignore
- 0x100 = (9th button)
- 0x200000 = Read-only mode

## TGUIObject Flag Bits (+0x28)
- 0x08 = Visible
- 0x20 = Skip parent in rendering chain
- 0x40 = Exclusive keyboard focus
- 0x80 = Dirty (needs repaint)
- 0x100 = Hidden
- 0x200 = Disabled
- 0x10000000 = Layout in progress (TGParagraph__RecalcLayout)

## Key Vtable Addresses
- TGPane_vtable: referenced in TGPane__dtor and TGScrollablePane__ctor
- TGUIObject_vtable: referenced in TGUIObject__dtor
- STButton_vtable: set in STButton__ctorW
- STToggle_vtable: set in STToggle__ctor
- CinematicWindow_vtable: set in CinematicWindow__ctor
- ConsoleWindow_vtable: set in ConsoleWindow__ctor
- TGTextBlock vtable: PTR_FUN_00897270

## TGL Resource Files Used by UI
- data/TGL/Multiplayer.tgl - MP lobby buttons, mission list
- data/TGL/Options.TGL - Quit dialog, settings
- Console icon from "Console" icon group

## RTTI Type IDs
- 0x810F = MainWindow
- 0x205 = TGConsole/TGTextBlock child type check
- 0x80EA = STRadioGroup
