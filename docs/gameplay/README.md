> [docs](../README.md) / gameplay

# Gameplay Documentation

Combat mechanics, subsystems, and game systems.

| Document | Contents |
|----------|----------|
| [combat-mechanics-re.md](combat-mechanics-re.md) | Consolidated combat RE: shields, cloak, weapons, repair, tractor |
| [damage-system.md](damage-system.md) | Complete damage pipeline: collision, weapon, explosion paths |
| [shield-system.md](shield-system.md) | 6-facing ellipsoid shields, absorption, power-budget recharge |
| [cloaking-state-machine.md](cloaking-state-machine.md) | Cloak device: 4 states, shield disable, energy failure |
| [weapon-firing-mechanics.md](weapon-firing-mechanics.md) | Phaser charge/discharge, torpedo reload, CanFire gates |
| [power-system.md](power-system.md) | Reactor/battery/conduit model, AdjustPower, per-ship tables |
| [repair-system.md](repair-system.md) | Queue data structure, repair rate formula, priority toggle |
| [repair-tractor-analysis.md](repair-tractor-analysis.md) | Repair teams + tractor beam: 6 modes, multiplicative drag |
| [repair-event-object-ids.md](repair-event-object-ids.md) | Repair event object ID analysis |
| [collision-detection-system.md](collision-detection-system.md) | 3-tier collision: sweep-and-prune, bounding sphere, narrow phase |
| [collision-shield-interaction.md](collision-shield-interaction.md) | Collision-shield: directional absorption, two-step damage |
| [self-destruct-pipeline.md](self-destruct-pipeline.md) | Opcode 0x13: 3 execution paths, PowerSubsystem cascade |
| [objcreate-unknown-species-analysis.md](objcreate-unknown-species-analysis.md) | ObjCreate with unknown species: failure modes, crash risks |
