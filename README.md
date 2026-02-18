# Star Trek: Bridge Commander - Reverse Engineering

Reverse engineering Star Trek: Bridge Commander (2002) to produce complete behavioral specifications for [OpenBC](https://github.com/SandboxServers/OpenBC), a clean-room reimplementation of the game's multiplayer systems.

## What This Repo Contains

This is the **dirty room** side of a clean-room RE effort. Everything here touches the original binary (`stbc.exe`, 5.9MB, 32-bit x86) through Ghidra decompilation, runtime instrumentation, and packet captures. Findings are documented here, then distilled into address-free behavioral specs in the OpenBC repo.

### RE Documentation (44 docs)

Detailed analysis of game internals: function call graphs, data structures, wire formats, vtable layouts, state machines, and protocol flows -- all with binary addresses and decompiled code references.

### Ghidra Annotation Scripts (10 scripts)

Automated scripts that name ~6,000 of the game's ~18,000 functions in Ghidra, covering SWIG bindings, Python C API, NiRTTI factories, vtables, and debug strings.

### Decompiled Source (19 organized files, ~15MB)

Ghidra C output organized by subsystem: core engine, game objects, multiplayer, networking, UI, mission logic, etc.

### Decompiled Python Scripts (~1,228 files)

The game's complete Python scripting layer: mission scripts, ship hardpoints, AI behaviors, UI handlers, and multiplayer logic.

### Engine Reference Sources

- **Gamebryo 1.2** full source (the engine BC's NetImmerse 3.1 evolved into)
- **Gamebryo 2.6** source (later reference)
- **MWSE** headers (Morrowind Script Extender, ships Gamebryo 1.2 struct definitions)
- **nif.xml** (NIF file format specification from niftools, covers NI 3.1 field definitions)

### Instrumentation Proxy (historical)

A DDraw proxy DLL (`src/proxy/`) that originally served as a headless dedicated server prototype. It now primarily functions as a runtime instrumentation platform -- injecting function tracers, packet loggers, and binary patches into the running game for live analysis. The proxy intercepts COM interfaces (DirectDraw7, Direct3D7, Surface7) and hooks Winsock calls for packet capture.

## Game Architecture

- **Engine**: NetImmerse 3.1 (predecessor to Gamebryo), DirectDraw 7 / Direct3D 7
- **Networking**: Winsock UDP (`TGWinsockNetwork`), star topology, GameSpy discovery
- **Scripting**: Embedded Python 1.5.2 with SWIG 1.x bindings (`App`/`Appc` modules)
- **Class hierarchy**: 670 RTTI classes (129 NetImmerse, 124 TotallyGames, ~420 game-specific)

## Documentation Index

### Wire Protocol
| Document | Description |
|----------|-------------|
| [wire-format-spec.md](docs/wire-format-spec.md) | Complete UDP wire format: all opcodes, StateUpdate flags, compressed types |
| [stateupdate-subsystem-wire-format.md](docs/stateupdate-subsystem-wire-format.md) | Subsystem health serialization: linked list order, 3 WriteState formats, round-robin |
| [network-protocol.md](docs/network-protocol.md) | Protocol architecture, event system, handler dispatch tables |
| [multiplayer-flow.md](docs/multiplayer-flow.md) | Client/server join flow from LAN discovery through gameplay |
| [tgmessage-routing.md](docs/tgmessage-routing.md) | TGMessage relay architecture: star topology, opaque payload, no whitelist |
| [collision-effect-protocol.md](docs/collision-effect-protocol.md) | Opcode 0x15 wire format, CompressedVec4 contacts, collision event class |
| [cf16-explosion-encoding.md](docs/cf16-explosion-encoding.md) | CF16 compressed float: 8 scales, 4096 mantissa steps, precision analysis |
| [objcreate-serialization.md](docs/objcreate-serialization.md) | Object creation packet serialization |
| [message-trace-vs-packet-trace.md](docs/message-trace-vs-packet-trace.md) | Stock dedicated server opcode cross-reference (15-min session) |

### Game Systems
| Document | Description |
|----------|-------------|
| [damage-system.md](docs/damage-system.md) | Complete damage pipeline: collision, weapon, explosion paths, gate checks |
| [combat-mechanics-re.md](docs/combat-mechanics-re.md) | Shields, cloak, weapons, repair, tractor -- consolidated combat RE |
| [shield-system.md](docs/shield-system.md) | 6-facing ellipsoid shields, area/directed absorption, power-budget recharge |
| [cloaking-state-machine.md](docs/cloaking-state-machine.md) | 4-state cloak machine, shield interaction, energy failure auto-decloak |
| [weapon-firing-mechanics.md](docs/weapon-firing-mechanics.md) | Phaser charge/discharge, torpedo reload, CanFire gates, WeaponSystem loop |
| [repair-tractor-analysis.md](docs/repair-tractor-analysis.md) | Repair teams (rate formula, complexity), tractor beam (6 modes, speed drag) |
| [collision-detection-system.md](docs/collision-detection-system.md) | 3-tier collision: sweep-and-prune, bounding sphere, per-type narrow phase |
| [subsystem-trace-analysis.md](docs/subsystem-trace-analysis.md) | Ship subsystem creation pipeline (traced from stock dedicated server) |
| [disconnect-flow.md](docs/disconnect-flow.md) | Player disconnect: 3 detection paths, peer deletion, cleanup opcodes |
| [objcreate-unknown-species-analysis.md](docs/objcreate-unknown-species-analysis.md) | ObjCreate with unknown species: failure modes, crash risks |
| [cut-content-analysis.md](docs/cut-content-analysis.md) | Cut/hidden features: ghost missions, fleet AI, tractor docking, dev tools |

### Discovery & Crypto
| Document | Description |
|----------|-------------|
| [gamespy-discovery.md](docs/gamespy-discovery.md) | GameSpy LAN/internet discovery, QR1 protocol, master server |
| [gamespy-master-server.md](docs/gamespy-master-server.md) | Master server protocol (333networks replacement) |
| [gamespy-crypto-analysis.md](docs/gamespy-crypto-analysis.md) | GameSpy challenge-response cryptography |
| [alby-rules-cipher-analysis.md](docs/alby-rules-cipher-analysis.md) | AlbyRules! stream cipher: discovery, algorithm, usage |

### Engine Internals
| Document | Description |
|----------|-------------|
| [rtti-class-catalog.md](docs/rtti-class-catalog.md) | Complete RTTI catalog: 670 classes across 3 hierarchies |
| [gamebryo-cross-reference.md](docs/gamebryo-cross-reference.md) | 129 NI classes cross-referenced against Gb 1.2, MWSE, nif.xml |
| [nirtti-factory-catalog.md](docs/nirtti-factory-catalog.md) | 117 NiRTTI factory registrations with addresses |
| [netimmerse-vtables.md](docs/netimmerse-vtables.md) | Vtable maps for core NI classes (NiObject through NiTriShape) |
| [function-map.md](docs/function-map.md) | Organized map of ~18,000 game functions |
| [function-mapping-report.md](docs/function-mapping-report.md) | Annotation coverage: ~6,031 functions named (33%) |
| [decompiled-functions.md](docs/decompiled-functions.md) | Key decompiled function analysis |
| [swig-api.md](docs/swig-api.md) | SWIG Python binding reference (3,990 wrappers) |

### Proxy & Instrumentation
| Document | Description |
|----------|-------------|
| [architecture-overview.md](docs/architecture-overview.md) | DDraw proxy: COM chain, bootstrap phases, game loop |
| [dedicated-server.md](docs/dedicated-server.md) | Headless server bootstrap, binary patches, crash handling |
| [empty-stateupdate-root-cause.md](docs/empty-stateupdate-root-cause.md) | Why headless server sends empty state updates (NIF loading) |
| [black-screen-investigation.md](docs/black-screen-investigation.md) | Client disconnect investigation (historical) |
| [veh-cascade-triage.md](docs/veh-cascade-triage.md) | VEH crash recovery: why it was removed |

### Guides
| Document | Description |
|----------|-------------|
| [python-152-guide.md](docs/python-152-guide.md) | Python 1.5.2 survival guide: syntax traps, missing builtins |
| [binary-patching-primer.md](docs/binary-patching-primer.md) | Code caves, JMP patches, NOPs |
| [reading-decompiled-code.md](docs/reading-decompiled-code.md) | How to read Ghidra C output |
| [developer-workflow.md](docs/developer-workflow.md) | Build, deploy, test, debug cycle |
| [troubleshooting.md](docs/troubleshooting.md) | Symptom-to-cause reference |
| [lessons-learned.md](docs/lessons-learned.md) | Debugging pitfalls and architecture insights |

## Ghidra Annotation Scripts

Run from Ghidra's Script Manager with `stbc.exe` loaded. Execute in order:

| Script | Functions Named | What It Does |
|--------|----------------|--------------|
| `ghidra_annotate_globals.py` | 97 | Labels key globals, functions, and Python module tables |
| `ghidra_annotate_nirtti.py` | 234 | Names NiRTTI factory + registration functions |
| `ghidra_annotate_swig.py` | 3,990 | Names SWIG wrapper functions from PyMethodDef tables |
| `ghidra_annotate_python_capi.py` | 137 | Names Python C API functions, type objects, module inits |
| `ghidra_annotate_pymodules.py` | 266 | Walks 21 module method tables, names C implementations |
| `ghidra_annotate_vtables.py` | 1,270 | Auto-discovers 97 vtables: virtuals, ctors, dtors |
| `ghidra_annotate_swig_targets.py` | 4 | Traces SWIG wrappers to C++ targets |
| `ghidra_discover_strings.py` | 548 | Names functions from debug strings, adds comments |

**Total: ~6,031 functions named (33% of 18,247)**

## Repo Structure

```
docs/                   RE analysis documents (44 files)
tools/                  Ghidra annotation scripts (10 files)
reference/
  decompiled/           Ghidra C output (19 organized files, ~15MB)
  scripts/              Decompiled game Python (~1,228 files)
engine/
  gamebyro-1.2-source/  Gamebryo 1.2 full source (reference)
  gamebyro-2.6-source/  Gamebryo 2.6 source (reference)
  mwse/                 MWSE headers (Gb 1.2 struct definitions)
  nif.xml               NIF format spec (V3.1 field definitions)
src/proxy/              DDraw instrumentation proxy (C source)
src/scripts/            Python scripts for runtime analysis
config/                 Server configuration
game/                   Game installs for live testing (gitignored)
```

## Requirements

- **Star Trek: Bridge Commander** (GOG edition tested)
- **Ghidra** with [GhidraMCP](https://github.com/LaurieWired/GhidraMCP) for decompilation
- **WSL2** with `i686-w64-mingw32-gcc` (only needed for building the instrumentation proxy)

## Build (Instrumentation Proxy)

```bash
make build          # Cross-compile ddraw.dll
make deploy-server  # Deploy to game/server/
make run-server     # Deploy + launch
make logs-server    # View runtime logs
```

## Related Projects

- **[OpenBC](https://github.com/SandboxServers/OpenBC)** -- Clean-room reimplementation of BC's multiplayer, built from behavioral specs derived from this RE work
