# Protocol Timing Constraints for OpenBC (2026-02-23)

Comprehensive catalog of all timing-sensitive values in the BC multiplayer protocol.
Source: Valentine's Day trace (33.5min/3 players), stock-dedi traces, Ghidra decompilation.

## Critical Constraints (Must Honor)

| Constraint | Value | Source |
|-----------|-------|--------|
| Peer timeout | ~45s (DAT_0088bd58) | disconnect-flow.md |
| Keepalive interval | ~12s (implied by 45s timeout / ~3 missed) | disconnect-flow.md |
| Reliable retransmit initial | 1.0s (msg+0x30 init) | transport-layer.md |
| Collision cooldown | DAT_0089054c (UNKNOWN float) | collision-detection-system.md |
| Explosion lifetime | 9.5s (ObjectExplodingEvent field) | ship-death-lifecycle.md |
| 0x28+0x00+0x01 bundling | Single UDP datagram | Verified 3/3 joins |
| Packet buffer max | 512 bytes (510 usable) | ack-outbox-deadlock.md |
| Reliable ordering | Per-channel sequential (< 0x32 vs >= 0x32) | transport-layer.md |

## Observed Rates (Soft Guidelines)

| Metric | Stock Rate | Source |
|--------|-----------|--------|
| StateUpdate per ship | ~10 Hz (9.6) | Valentine's trace Section 6 |
| Keepalive per client | ~1/sec | Valentine's trace Section 15 |
| PythonEvent total | ~2/sec during combat | Valentine's trace Section 8 |
| CollisionEffect | 0.04-0.16/sec | Valentine's (317/33.5min) |
| GameSpy heartbeat | 30s, max 10 repeats | gamespy-discovery.md |
| Handshake total | ~66ms | stock-dedi trace |

## Retransmit Backoff Modes
- Mode 0 (ACK): fixed interval (~0.67s observed)
- Mode 1 (data): linear backoff (start 1.0s, ~2s observed for fragments)
- Mode 2 (exponential): clamped to msg+0x34 max (not observed in default code)

## ACK-Outbox Two-Pass System
- Pass 1: retx < 3 (fresh), always runs
- Pass 2: retx >= 3 (stale), GATED on msg_count > 0 || disconnecting
- Cleanup at retx >= 9
- Stock bug: deadlock when no traffic flows, entries stuck at retx 3-8
- Peak observed: 20-33 entries (self-limiting during active gameplay)

## Unresolved Constants (Need Ghidra Extract)
- DAT_00888860: StateUpdate force-send threshold + collision normalization
- DAT_0088bd58: Peer timeout threshold (~45s estimated)
- DAT_0089054c: Collision cooldown timer (CRITICAL for rate limiting)
- DAT_008942dc: Velocity-squared threshold (resting object exclusion)

## OpenBC CRITICAL Gap
Collision rate limiting MISSING. OpenBC saw 28,504 CollisionEffect in 11min (43/sec)
vs stock 317 in 33.5min (0.16/sec). 269x higher. Must implement cooldown at
Object+0x98 against DAT_0089054c, plus velocity threshold at DAT_008942dc.
