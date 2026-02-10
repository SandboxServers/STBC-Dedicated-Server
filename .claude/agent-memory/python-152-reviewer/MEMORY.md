# Python 1.5.2 Reviewer - Project Memory

## Project: STBC Dedicated Server
Headless dedicated server for Star Trek: Bridge Commander (2002) using DDraw proxy DLL + embedded Python 1.5.2.

## Key Files Reviewed
- `src/scripts/Custom/DedicatedServer.py` - Main server Python script (1275 lines)
- `src/scripts/Custom/ClientLogger.py` - Client-side diagnostic hooks (157 lines)
- `src/scripts/Custom/Observer.py` - Passive event/state observer (149 lines)
- `src/scripts/Custom/StateDumper.py` - Engine state dumper (409 lines)
- `src/scripts/Local.py` - Server boot hook (85 lines)
- `src/scripts/ClientLocal.py` - Client boot hook (58 lines)
- `src/scripts/DiagLocal.py` - Diagnostic boot hook (83 lines)
- `src/scripts/ObserverLocal.py` - Observer boot hook (48 lines)
- `reference/scripts/Multiplayer/` - Original game scripts for comparison
- `reference/scripts/Autoexec.py` - Boot chain entry point

## Python 1.5.2 Compatibility Findings
- See [compatibility-review.md](compatibility-review.md) for detailed issue list
- **Full review 2026-02-07: NO ISSUES FOUND across DedicatedServer.py, Local.py, ddraw_main.c**
- Uses `strop` correctly, `dict.has_key()`, `except X, e:`, `count = count + 1`

## Architecture Analysis: Python/C++ Boundary (2026-02-09)

### What C++ Engine Does (CANNOT replicate outside stbc.exe)
- Physics simulation, collision detection (NetImmerse 3.1)
- 3D model/NIF loading, scene graph
- Network packet serialization (TGWinsockNetwork UDP)
- Ship subsystem simulation (weapons, shields, hull damage)
- Object state replication (FUN_005b17f0)
- Timer system, Event system dispatch
- MultiplayerGame C++ class internals

### What Python Does (game logic glue)
- Scoring: kill/death/damage tracking dictionaries
- Game rules: time/frag limits, end-game conditions
- Network messages: MISSION_INIT, SCORE_CHANGE, END_GAME via TGBufferStream
- Ship selection: species-to-ship mapping, system creation
- Event handlers: ProcessMessageHandler, ObjectKilledHandler, DamageHandler
- UI: ALL menu/pane building (needs stubbing for headless)

### GUI Functions That Always Need Stubbing
- Mission1Menus.BuildMission1Menus, BuildEndWindow
- LoadBridge.CreateCharacterMenus
- RebuildPlayerList/InfoPane/ShipPane
- MissionShared.SetupEventHandlers warp button (line 193-194)
- DoKillSubtitle, DoEndGameDialog, DoScoreWindow

## Key Architecture Notes
- `g_bGameStarted` lives on MissionMenusShared, NOT MissionShared
- TopWindow.Initialize calls Local.TopWindowInitialized(pWindow)
- MultiplayerGame creation is separate from TopWindow creation
- `g_pStartingSet` created by CreateSystemFromSpecies (host) or ProcessMessageHandler (client)

### Common Pitfall: `continue` Inside try/except
- Python 1.5.2 SyntaxError for `continue` inside ANY `try` statement

### Common Pitfall: Import Hook Pattern
- `__import__` signature: `(name, globals, locals, fromlist)` - no **kwargs
- Inner functions MUST capture enclosing vars via default args (no closures)

### SWIG 1.x API Pattern
- `Appc.ClassName_Method(raw_ptr, args)` works with raw pointers AND shadow instances
- `App.SetClassPtr(raw_ptr)` wraps raw pointer in shadow class

## Code Reviews Log
- 2026-02-07: DedicatedServer.py, Local.py, ddraw_main.c - NO ISSUES
- 2026-02-07: System Set + g_bGameStarted + SCORE_MESSAGE changes - COMPATIBLE
- 2026-02-07: Appc-Based CreateSystem fix - COMPATIBLE
- 2026-02-08: StateDumper.py - 8 `continue` inside try/except FIXED
- 2026-02-08: DiagLocal.py - NO ISSUES
- 2026-02-08: ClientLogger.py - 2 ISSUES (call unpacking, missing closure capture) - NOW FIXED
- 2026-02-09: Architecture analysis (system-memory surfaces) - advisory only
- 2026-02-09: Python/C++ boundary analysis for brainstorm - see python-layer-analysis.md
- 2026-02-10: FULL 8-FILE REVIEW (2264 lines) - ALL PASS, 0 issues found

## Detailed Analysis Files
- [compatibility-review.md](compatibility-review.md) - Python 1.5.2 issues found
- [python-layer-analysis.md](python-layer-analysis.md) - Brainstorm Q&A analysis
