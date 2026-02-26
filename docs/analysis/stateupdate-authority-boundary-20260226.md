> [docs](../README.md) / [analysis](README.md) / stateupdate-authority-boundary-20260226.md

# StateUpdate Authority Boundary Audit (2026-02-26)

## Status
High-confidence, trace-backed update to authority boundaries for multiplayer replication.

## Scope

This audit focuses on:

1. What the server merely relays versus what it corrects or generates.
2. `StateUpdate` (`0x1C`) directionality and payload shaping.
3. Subsystem/power block behavior (`flag 0x20`) and cadence.

Primary evidence:

- `game/stock-dedi/packet_trace.log`
- `logs/battle-of-valentines-day/packet_trace.log`
- OpenBC comparison capture: `/mnt/c/Users/Steve/source/projects/OpenBC/build/openbc-20260225-210656.log`

## High-Confidence Findings

### 1) `0x1C` is direction-correlated, but not a byte-for-byte echo path

Observed pattern in stock and battle traces:

- `C->S`: mostly `0x8x/0x9x` (`WPN`-bearing owner updates).
- `S->C`: mostly `0x20/0x3x` (`SUB`-bearing server broadcasts).

Concrete examples:

- Stock `C->S` `flags=0xDD` (`POS+FWD+UP+SPD+CLK+WPN`):
  [packet_trace.log](../../game/stock-dedi/packet_trace.log)
- Stock `S->C` `flags=0x20` (`SUB`):
  [packet_trace.log](../../game/stock-dedi/packet_trace.log)
- Stock `S->C` `flags=0x3E` (`DELTA+FWD+UP+SPD+SUB`):
  [packet_trace.log](../../game/stock-dedi/packet_trace.log)
- Battle `C->S` `flags=0x9E` and `S->C` `flags=0x3E`:
  [packet_trace.log](../../logs/battle-of-valentines-day/packet_trace.log)

Interpretation:

- The host ingests owner-client state input, but downstream packets are server-shaped broadcasts.
- In practice this is not a raw byte-identical "echo to everyone else" model for `0x1C`.

### 2) Server relay vs server-authoritative generation (observed behavior)

| Category | Observed behavior |
|----------|-------------------|
| Relay-oriented | Weapon fire/control events (`0x07`, `0x08`, `0x19`, `0x1A`, `0x0A`) follow client-originated fanout patterns. |
| Server-generated authoritative | Explosion/death/score sync/change paths (`0x29`, `0x36`, `0x37`) are server-originated and accepted by clients. |
| Hybrid (`0x1C`) | Owner input arrives upstream, but downstream replication is packaged as server broadcasts with `SUB` content and stock-like mixed flags (`0x20/0x3x`). |

### 3) `flag 0x20` carries critical subsystem/power state and must match stock cadence/content

`0x20` payloads include subsystem health round-robin bytes and power-related bytes that other peers use to render and reconcile engineering state.

From trace histograms (`S->C`, non-`FF` bytes in `0x20` block):

- Stock top values include `0x64` very frequently (alongside `0x40`, `0x60`, `0x20`, etc.).
- Battle trace shows the same family (`0x64`, `0x60`, `0x40`, `0x43`, `0x21`, ...).
- OpenBC comparison sample is heavily skewed to a different set (`0x20`, `0x40`, `0x80`, `0xDE`, `0x87`, `0x50`, ...), which indicates format/content drift.

### 4) Timing/cadence matters as much as payload bytes

Observed cadence snapshots:

- Stock `S->C 0x20` interval: avg ~`0.101s`, p50 ~`0.100s`, p90 ~`0.110s` (about 10 Hz per ship lane).
- OpenBC sample `S->C 0x20`: roughly ~`0.142s` per object in the tested session (about 7 Hz), with overall send rate below stock-like target.

Implication:

- Even when fields exist, slower or uneven cadence can produce visible flicker/desync (shields, subsystem bars, repair UI drift).

## Authority Boundary Summary (Practical)

- Movement and weapon-state initiation: owner-client authored upstream.
- Subsystem health and power propagation to other peers: server-broadcast downstream (`0x20`/`0x3x` shaped traffic).
- Death/respawn/score lifecycle messages: server-authoritative and client-accepted.

## OpenBC Parity Targets (from this audit)

1. Treat upstream `0x1C` as owner input, not as final downstream payload.
2. Emit downstream `0x1C` in stock-like shape (`0x20`/`0x3x` patterns), not just raw relayed `0x9x` plus separate pure `0x20`.
3. Keep subsystem/power bytes and cadence aligned with stock-observed distributions/timing.

