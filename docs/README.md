# STBC Reverse Engineering Documentation

Reverse engineering Star Trek: Bridge Commander to produce behavioral specifications for [OpenBC](https://github.com/SandboxServers/OpenBC), a clean-room reimplementation.

## Sections

| Folder | Contents |
|--------|----------|
| [protocol/](protocol/README.md) | Wire formats, opcodes, serialization |
| [networking/](networking/README.md) | Transport, discovery, reliability |
| [gameplay/](gameplay/README.md) | Combat, subsystems, game mechanics |
| [engine/](engine/README.md) | Engine internals, class catalogs |
| [architecture/](architecture/README.md) | Server bootstrap, proxy DLL |
| [guides/](guides/README.md) | Developer how-tos |
| [analysis/](analysis/README.md) | Traces, investigations, archaeology |
| [openbc/](openbc/) | Clean-room specs for reimplementation |

## Quick Links

- [Troubleshooting](troubleshooting.md) - Symptom-to-cause quick reference
- [Wire Format Hub](protocol/wire-format-spec.md) - Complete opcode tables
- [Multiplayer Flow](networking/multiplayer-flow.md) - Client/server join sequence
- [Architecture Overview](architecture/architecture-overview.md) - How the proxy DLL works
