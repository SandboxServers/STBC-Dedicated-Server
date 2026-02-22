> [docs](../README.md) / networking

# Networking Documentation

Transport, discovery, reliability, and connection lifecycle.

| Document | Contents |
|----------|----------|
| [network-protocol.md](network-protocol.md) | Protocol architecture, event system, handler tables |
| [multiplayer-flow.md](multiplayer-flow.md) | Complete client/server join flow (connect to play) |
| [gamespy-discovery.md](gamespy-discovery.md) | GameSpy LAN/internet discovery, master server, QR1 crypto |
| [gamespy-crypto-analysis.md](gamespy-crypto-analysis.md) | GameSpy challenge-response cryptography |
| [alby-rules-cipher-analysis.md](alby-rules-cipher-analysis.md) | AlbyRules! packet encryption cipher |
| [tgmessage-routing-cleanroom.md](tgmessage-routing-cleanroom.md) | Clean-room TGMessage routing spec |
| [netimmerse-transport-deep-dive.md](netimmerse-transport-deep-dive.md) | NetImmerse transport layer internals |
| [fragmented-ack-bug.md](fragmented-ack-bug.md) | Fragmented reliable message ACK bug |
| [ack-outbox-deadlock.md](ack-outbox-deadlock.md) | ACK-outbox deadlock analysis |
| [disconnect-flow.md](disconnect-flow.md) | Player disconnect: 3 detection paths, cleanup cascade |
| [ship-death-lifecycle.md](ship-death-lifecycle.md) | Ship death in MP: explosion + respawn, no DestroyObject |
