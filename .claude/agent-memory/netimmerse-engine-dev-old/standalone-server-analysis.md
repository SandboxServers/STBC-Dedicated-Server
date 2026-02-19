# Standalone Server Feasibility Analysis

## Conclusion: Feasible, ~5K-8K lines of C, 10-16 weeks part-time

## Key Architecture Insight
STBC multiplayer is CLIENT-AUTHORITATIVE message relay, NOT server-authoritative simulation.
Server manages connections/lobby/scoring and relays messages between clients.
No physics, hit detection, damage calc, or scene graph needed server-side.

## What Can Be Eliminated
- NetImmerse entirely (scene graph, renderer, audio, animation, collision)
- Python 1.5.2 (game logic thin enough for pure C)
- All game data (NIF models, textures, sounds)
- All game scripts (1228 .py files)
- stbc.exe itself

## What Must Be Reimplemented
1. TGWinsockNetwork - reliable UDP (~2-3K lines C)
2. Checksum exchange - 4-round file hash verification
3. GameSpy LAN discovery - query/response protocol
4. Game state machine - lobby, ship select, in-game, scoring
5. Message dispatcher - opcode routing (0x00-0x0F game, 0x20-0x28 checksums)

## Clean Room Strategy
- Write protocol spec from packet captures (sendto/recvfrom hooks)
- Do NOT ship decompiled code, addresses, or struct layouts
- Implement from spec only
- Require original game for client
- Model: OpenMW approach (requires original data files)

## Recommended Order
1. FINISH proxy DLL version first (validates protocol, generates captures)
2. Write complete protocol specification from captures
3. Implement standalone server from spec
4. Proxy = research vehicle, Standalone = release vehicle

## Similar Projects for Reference
- OpenMW (Morrowind) - clean room engine reimplementation
- OpenTTD (Transport Tycoon) - decompile then replace (legally gray)
- Mangos/TrinityCore (WoW) - server from packet captures
- ScummVM - clean room, later endorsed by companies
