# Packet Analysis - Session 2026-02-09 11:11:31

## Session Summary
- 77 packets total, server crashed at tick 3161
- Client connected at tick 3082 (11:13:58.270)
- Crash at tick 3161 (11:14:01.950), ~3.68 seconds after connection
- Crash: EIP=0x006CF1DC writing 0x00895C58 (.rdata section, vtable ptr)
- NewPlayerInGame was scheduled for tick 3172 but never reached

## Crash Root Cause
FUN_006cf1c0 is a message buffer destructor/reset called throughout the checksum exchange.
When the buffer's data pointer (obj+0x1C) is NULL (already cleared), it falls through to
write 0xFFFFFFFE to the address stored at obj+0x04. In this case obj+0x04 contains the
vtable pointer 0x00895C58, which is in .rdata (read-only). Access violation on write to
read-only memory.

The object is in a corrupt state where +0x04 still holds the vtable pointer but +0x1C is 0.
This suggests double-destruction or use-after-partial-cleanup of a network message buffer.
