# TGWinsockNetwork Encryption - Complete Analysis

## Overview
BC uses a custom stream cipher at the TGNetwork transport layer. All game payloads
(checksums, state updates, chat, etc.) are encrypted before being placed in UDP datagrams.

## Cipher Object (0x58 bytes)
Located at WSN+0xF0 (param_1[0x3C] in TGNetwork constructor).
Created by allocating 0x58 bytes, setting vtable to PTR_LAB_008958c0, then calling FUN_006c2280.

### Layout:
| Offset | Size | Name | Description |
|--------|------|------|-------------|
| 0x00 | 4 | vtable | PTR_LAB_008958c0 |
| 0x04 | 4 | temp_a | Working variable |
| 0x08 | 4 | temp_b | Working variable (multiplier: 0x4E35) |
| 0x0C | 4 | temp_c | Working variable (addend: 0x15A) |
| 0x10 | 4 | temp_d | Accumulator |
| 0x14 | 4 | state_a | LCG state variable |
| 0x18 | 4 | state_b | LCG state variable |
| 0x1C | 4 | running_sum | Accumulated sum for PRNG |
| 0x20 | 4 | key_word[0] | Derived from key bytes [0],[1] |
| 0x24 | 4 | key_word[1] | Derived from key bytes [2],[3] XOR key_word[0] |
| 0x28 | 4 | key_word[2] | Derived from key bytes [4],[5] XOR key_word[1] |
| 0x2C | 4 | key_word[3] | Derived from key bytes [6],[7] XOR key_word[2] |
| 0x30 | 4 | key_word[4] | Derived from key bytes [8],[9] XOR key_word[3] |
| 0x34 | 4 | prng_output | XOR of temp_d and temp_a after each PRNG round |
| 0x38 | 4 | round_counter | Which key_word to use (0-4, incremented per round) |
| 0x3C | 4 | accumulator | Running XOR of prng_output values |
| 0x40 | 4 | mask_high | prng_output >> 8 |
| 0x44 | 4 | mask_low | prng_output & 0xFF |
| 0x48 | 10 | key_string | "AlbyRules!" (modified during encryption) |
| 0x52 | 2 | padding | Zero |
| 0x54 | 4 | byte_state | Current byte being processed |

## Key: "AlbyRules!" (at 0x0095abb4 in .rdata)
- 10 ASCII bytes: 0x41 0x6C 0x62 0x79 0x52 0x75 0x6C 0x65 0x73 0x21
- STATIC - same for all sessions, all peers, all messages
- Copied into cipher object at +0x48 during FUN_006c2280 (reset)

## Key Schedule: FUN_006c22f0
Called once before processing a message. Derives 5 key_words from the 10-byte key string:
```
key_word[0] = key[0]*256 + key[1]
key_word[1] = (key[2]*256 + key[3]) XOR key_word[0]
key_word[2] = (key[4]*256 + key[5]) XOR key_word[1]
key_word[3] = (key[6]*256 + key[7]) XOR key_word[2]
key_word[4] = (key[8]*256 + key[9]) XOR key_word[3]
```
Then runs 5 rounds of FUN_006c23c0 (PRNG step), XORing accumulator each time.

## PRNG Step: FUN_006c23c0
Linear congruential generator variant:
```
state = key_word[round_counter]
temp = running_sum + round_counter
// Series of multiplications by 0x4E35 and 0x15A
// Cross-multiplication and accumulation
new_key_word = state * 0x4E35 + 1
prng_output = temp_d XOR new_key_word
round_counter++
```
Not a standard LCG - uses 5-word rolling key with cross-products.

## Encrypt: FUN_006c2490 (per-byte stream cipher)
For each byte of plaintext:
1. Reset cipher state (FUN_006c2280 - copies "AlbyRules!" fresh)
2. Store input byte in +0x54
3. Run key schedule (FUN_006c22f0)
4. mask_high = prng_output >> 8
5. mask_low = prng_output & 0xFF
6. XOR each byte of key_string (+0x48, 10 bytes) with byte_state (MODIFIES KEY IN PLACE)
7. output = byte_state XOR mask_high XOR mask_low
8. Store output, advance to next byte

CRITICAL: The cipher resets from "AlbyRules!" on EVERY call to encrypt/decrypt.
But WITHIN a call, the key_string is modified byte-by-byte (feedback), creating position-dependent encryption.

## Decrypt: FUN_006c2520 (inverse)
Same structure but XOR order is different:
1. Reset, store input byte, run key schedule
2. byte_state = input XOR mask_low XOR mask_high  (note: reversed order from encrypt)
3. XOR key_string bytes with byte_state
4. Store output

## Implications for Reimplementation
- Encryption is fully deterministic from fixed key "AlbyRules!"
- No session keys, no nonces, no key exchange needed
- Can be reimplemented in ~100 lines of C or Python
- The "encrypted key exchange" packets (33, 24 bytes at T+0.063) are likely
  TGNetwork connection establishment, NOT actual crypto key exchange
- A standalone server could implement this cipher trivially
