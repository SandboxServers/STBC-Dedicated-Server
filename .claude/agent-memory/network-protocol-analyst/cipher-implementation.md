# BC AlbyRules! Cipher - C Reimplementation Specification

## Verification Status: CONFIRMED
- Round-trip encrypt/decrypt passes
- Packet #3 (8 bytes): decrypts to expected `01 01 03 06 C0 00 00 02`
- Packet #4 (33 bytes): decrypts to checksum request with ASCII "scripts/App.pyc"
- All 22 keepalive packets decode consistently with incrementing sequence numbers
- Packet #55 (72 bytes): contains float 1.0f (FF FF FF 3F) confirming correct byte order

## Critical Implementation Details

### Encryption Boundary
- Byte 0 of every UDP packet is NOT encrypted (direction flag: 0x01/0x02/0xFF)
- Encryption applies to bytes 1 through N-1 only
- Both encrypt and decrypt reset the cipher from scratch for each call

### MOVSX Sign Extension
- Input bytes are sign-extended via `MOVSX EAX, byte ptr [...]`
- Byte 0xD7 becomes int32 0xFFFFFFD7 (= -41)
- This affects the XOR computation: `byte_state ^ mask_low ^ mask_high` operates on int32
- Only the low byte of the result is stored as output

### PRNG Step (from x86 assembly at 0x006c23c0)
The key computation per round, with all values as int32:
```
mix_idx  = running_sum + round_counter
cross1   = mix_idx * 0x4E35          (20021 decimal)
cross2   = key_word[round] * 0x15A   (346 decimal)
combined = cross1 + cross2
new_rsum = state_a + combined         (state_a from PREVIOUS round entry)
new_kw   = key_word[round] * 0x4E35 + 1
prng_out = (uint32)new_rsum XOR (uint32)new_kw

Updates: running_sum=new_rsum, state_a=cross2, key_word[round]=new_kw, round_counter++
```

### Key Schedule (FUN_006c22f0)
```
key_word[0] = key[0]*256 + key[1]
PRNG_step()                             # modifies key_word[0] to new_kw
accumulator = prng_output

key_word[1] = (key[2]*256 + key[3]) XOR key_word[0]    # uses MODIFIED key_word[0]!
PRNG_step()
accumulator ^= prng_output

... repeat for key_word[2], [3], [4] ...
round_counter = 0
accumulator ^= prng_output   (final round)
```

### Decrypt (FUN_006c2520) per byte
```
1. byte_state = MOVSX(ciphertext_byte)       # sign extend to int32
2. key_schedule()                             # produces accumulator
3. mask_low  = accumulator & 0xFF
4. mask_high = accumulator >> 8
5. byte_state = byte_state XOR mask_low XOR mask_high    # int32 XOR
6. for j in 0..9: key_string[j] ^= (uint8)byte_state    # plaintext feedback
7. output = (uint8)byte_state
```

### Encrypt (FUN_006c2490) per byte
```
1. byte_state = MOVSX(plaintext_byte)
2. key_schedule()
3. mask_high = accumulator >> 8
4. mask_low  = accumulator & 0xFF
5. for j in 0..9: key_string[j] ^= (uint8)byte_state    # plaintext feedback FIRST
6. byte_state = byte_state XOR mask_high XOR mask_low
7. output = (uint8)byte_state
```

Key difference: Encrypt does feedback BEFORE XOR, decrypt does feedback AFTER XOR.
Both feed back the PLAINTEXT, ensuring the same keystream is generated.
