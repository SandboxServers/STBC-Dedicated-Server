# Open Source Viability Analysis (2026-02-07)

## Summary
The STBC dedicated server proxy DLL cannot be released as a standalone open-source
project without the original game executable. The proxy is architecturally a parasite
on stbc.exe, not an independent program. A clean-room reimplementation is theoretically
possible but faces significant technical and legal barriers.

## Dependencies on Copyrighted Material

### stbc.exe (CRITICAL - the exe IS the server)
60+ hardcoded addresses, 30+ binary patches, all networking/game logic runs inside exe.
Key subsystems used: TGWinsockNetwork, ChecksumManager, MultiplayerGame, TGEventManager,
Python 1.5.2 (static), SWIG bindings, GameSpy, NiAlloc/NiFree.

### Engine DLLs (NiMain.dll etc.)
Loaded by exe during startup. Eliminable in standalone server (no rendering needed).

### Game Data Files
- scripts/*.pyc - required for checksum verification with clients
- scripts/Multiplayer/ - mission logic (event handlers, scoring, ship selection)
- data/TGL/*.tgl - star system database, multiplayer config

## Clean-Room Reimplementation Estimate
- ~400 functions needed for server-only
- 6-12 months for skilled developer
- Critical path: TGWinsockNetwork reliable UDP protocol (must be byte-compatible)
- Python 1.5.2 available under PSF license (easy)
- SWIG bindings: ~40-60 functions needed server-side (medium)

## Legal Issues
1. Proxy DLL contains decompilation-derived constants (addresses, offsets, byte patterns)
2. reference/decompiled/ (19 files, 15MB) is derivative work of copyrighted exe
3. reference/scripts/ (1228 .py files) is copyrighted game content
4. Developer has seen decompiled code - cannot do clean-room implementation personally
5. DMCA anti-circumvention is a concern but reverse-engineering exemption may apply

## Recommended Path (OpenMW Model)
1. Write protocol specification from observed behavior (legally defensible)
2. Find clean-room developer who has never seen decompiled code
3. Implement standalone server from protocol spec
4. Require user's game install for data files (scripts, TGL)
5. Do NOT distribute: decompiled code, proxy DLL source, game scripts

## Current Project Status: Viable as Personal Mod
- DLL injection/proxy modding is widely tolerated
- BC EULA does not explicitly prohibit modding
- Community has active modding scene
- Distributing the proxy DLL + Python scripts (without exe/game files) is low risk
